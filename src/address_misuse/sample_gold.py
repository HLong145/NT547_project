"""D5 — lấy mẫu gán nhãn vàng (pilot 50 mẫu) kèm bằng chứng điền sẵn, và tính Cohen's κ.

python -X utf8 -m address_misuse.sample_gold pilot [--seed 0]
python -X utf8 -m address_misuse.sample_gold main [--seed 0] [--double 200]   → mẫu vàng chính từ dataset_v2 (sau freeze)
python -X utf8 -m address_misuse.sample_gold sheet B      → data/gold/annotator_B.xlsx (file Excel để gán)
python -X utf8 -m address_misuse.sample_gold sheet B --set main [--only-double]   → annotator_main_B.xlsx
python -X utf8 -m address_misuse.sample_gold check data/gold/annotator_B.xlsx   (kiểm tra hình thức trước khi tính κ)
python -X utf8 -m address_misuse.sample_gold kappa data/gold/annotator_A.csv data/gold/annotator_B.csv

Đầu ra trong data/gold/ (chỉ dùng nội bộ, có địa chỉ đầy đủ):
- pilot50_items.csv       danh sách đã làm mù (không có tầng/nhãn tác giả), thứ tự xáo trộn, kèm bằng chứng
- pilot50_key.csv         tầng lấy mẫu + nhãn tác giả (RQ1) — người gán KHÔNG mở file này
- annotator_template.csv  cột cần điền theo docs/CODEBOOK.md §2
Định nghĩa nhãn: docs/CODEBOOK.md.
"""

import argparse
import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from address_misuse.config import GOLD_DIR, INTERIM_DIR, NETWORKS, RAW_DIR, SEED_DIR

EXPLORERS = {
    "eth": "https://etherscan.io/address/", "bsc": "https://bscscan.com/address/",
    "arb": "https://arbiscan.io/address/", "op": "https://optimistic.etherscan.io/address/",
    "base": "https://basescan.org/address/", "polygon": "https://polygonscan.com/address/",
    "sepolia": "https://sepolia.etherscan.io/address/", "bsc_testnet": "https://testnet.bscscan.com/address/",
}
LABEL_COLS = ["is_misuse", "type", "subtype", "xc_chain", "malicious", "confidence", "evidence", "note"]
SYMEXEC_FLAGS = ["delegatecall", "transfer_all_eth", "transfer_msg_value", "transfer_input_amount"]

# (tầng, số mẫu). Tổng 50. Ưu tiên Type 1/4/5 (lõi) và có đủ âm để kiểm tra codebook.
PILOT_PLAN = [
    ("rq1_ca_pos", 3), ("rq1_ca_neg", 2), ("rq1_eoa_addr", 3),     # kiểm tra lại nhãn tác giả
    ("t1_ncd_other", 10),                                          # NCD không có contract ở chain khác
    ("t4_xc_before", 3), ("t4_xc_bsc", 3), ("t4_xc_after", 2), ("t4_xc_unknown", 2),
    ("ca_pcd", 4),
    ("eoa_key", 4), ("eoa_addr", 2), ("eoa_7702", 2), ("eoa_7702_other", 2),
    ("neg_n7_multichain", 4), ("neg_n1_random", 4),
]


def _date(ts) -> str | None:
    if ts is None or (isinstance(ts, float) and np.isnan(ts)) or pd.isna(ts):
        return None
    return datetime.fromtimestamp(int(float(ts)), tz=timezone.utc).strftime("%Y-%m-%d")


def _dedup_max(df: pd.DataFrame, keys=("chain", "address")) -> pd.DataFrame:
    return df.sort_values("cost_native", ascending=False).drop_duplicates(list(keys))


def _pick(df: pd.DataFrame, n: int, rng: np.random.Generator, loss_col: str | None = "cost_native") -> pd.DataFrame:
    """Nửa từ nhóm thiệt hại cao (top 25%), nửa ngẫu nhiên phần còn lại — để có cả ca lớn lẫn ca điển hình."""
    if len(df) <= n:
        return df
    if not loss_col or loss_col not in df:
        return df.sample(n, random_state=rng.integers(2**31))
    q = df[loss_col].quantile(0.75)
    hi, lo = df[df[loss_col] >= q], df[df[loss_col] < q]
    n_hi = min(len(hi), n // 2)
    a = hi.sample(n_hi, random_state=rng.integers(2**31))
    b = lo.sample(min(len(lo), n - n_hi), random_state=rng.integers(2**31))
    out = pd.concat([a, b])
    if len(out) < n:                                     # bù nếu một nhóm quá nhỏ
        rest = df.drop(out.index)
        out = pd.concat([out, rest.sample(n - len(out), random_state=rng.integers(2**31))])
    return out


def _n1_random(cand: pd.DataFrame, misuse_keys: set, n: int, rng: np.random.Generator) -> pd.DataFrame:
    """N1: địa chỉ ứng viên (cùng nguồn GitHub/StackExchange) có giao dịch nhưng rule tác giả không gắn cờ.
    7,5 triệu dòng → lấy dư một mẫu ngẫu nhiên rồi mới lọc."""
    pool = cand[cand.n_tx > 0].sample(n * 20, random_state=rng.integers(2**31))
    keep = [(c, a) not in misuse_keys for c, a in zip(pool.chain, pool.address)]
    return pool[np.array(keep)].head(n)


def delegations(s: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Mỗi (chain, EOA) ủy quyền 7702, kèm kết quả symexec của delegate và tên ví hợp lệ đã kiểm chứng (N6).

    `eip7702_delegate_stats.flag` của tác giả chính là kết quả symexec (1 = có đường chuyển tiền, 0 = không,
    -1 = chưa phân tích), không phải nhãn độc: delegate MetaMask hợp lệ cũng có flag 1. Vì vậy dùng symexec làm
    bằng chứng, và tách riêng delegate là ví hợp lệ đã kiểm chứng.
    """
    dl = s["eip7702_delegations"].drop_duplicates(["chain", "eoa"]).rename(columns={"eoa": "address"})
    sx = s["symexec_results"]
    sx = sx[sx.kind == "eip7702_delegate"].drop_duplicates(["chain", "address"])
    transfer = {(c, a): bool(x or y or z) for c, a, x, y, z in
                zip(sx.chain, sx.address, sx.transfer_all_eth, sx.transfer_msg_value, sx.transfer_input_amount)}
    wallets = s["n6"][s["n6"].kept].set_index("address").wallet.to_dict() if len(s["n6"]) else {}
    return dl.assign(delegate_symexec_transfer=[transfer.get((c, d)) for c, d in zip(dl.chain, dl.delegate)],
                     delegate_known_wallet=[wallets.get(d) for d in dl.delegate])


def load_sources() -> dict[str, pd.DataFrame]:
    s = {name: pd.read_parquet(SEED_DIR / f"{name}.parquet") for name in
         ("ca_misuse", "eoa_misuse", "rq1_labels", "symexec_results", "eip7702_delegations",
          "candidate_addresses")}
    s["matrix"] = pd.read_parquet(INTERIM_DIR / "crosschain_matrix.parquet")
    s["n7"] = pd.read_parquet(INTERIM_DIR / "n7_multichain_contracts.parquet")
    n6 = INTERIM_DIR / "n6_benign_7702_delegates.parquet"           # python -m address_misuse.negatives n6
    s["n6"] = pd.read_parquet(n6) if n6.exists() else pd.DataFrame(columns=["address", "wallet", "kept"])
    return s


def draw_pilot(s: dict[str, pd.DataFrame], seed: int = 0) -> pd.DataFrame:
    """Trả về DataFrame (stratum, chain, address, author_label) — 50 cặp (chain, address) không trùng."""
    rng = np.random.default_rng(seed)
    m, rq1 = s["matrix"], s["rq1_labels"]
    eoa = _dedup_max(s["eoa_misuse"])
    dl = delegations(s)
    sweep = (dl.delegate_symexec_transfer == True) & dl.delegate_known_wallet.isna()   # noqa: E712
    misuse_keys = set(zip(s["ca_misuse"].chain, s["ca_misuse"].address)) | set(zip(eoa.chain, eoa.address))
    ncd = m[m.subtype == "NCD"]

    def by_chain(df, n, **kw):
        """chia đều giữa eth và bsc."""
        parts = [_pick(df[df.chain == c], k, rng, **kw) for c, k in (("eth", n - n // 2), ("bsc", n // 2))]
        return pd.concat(parts)

    pools = {
        "rq1_ca_pos": lambda n: _pick(rq1[(rq1.misuse_type == "CA") & (rq1.label == 1)], n, rng, None),
        "rq1_ca_neg": lambda n: _pick(rq1[(rq1.misuse_type == "CA") & (rq1.label == 0)], n, rng, None),
        "rq1_eoa_addr": lambda n: _pick(rq1[rq1.misuse_type == "EOA_ADDR"], n, rng, None),
        "t1_ncd_other": lambda n: by_chain(ncd[ncd.xc_label == "NCD-Other"], n),
        "t4_xc_before": lambda n: _pick(ncd[(ncd.chain == "eth") & (ncd.xc_timing == "deployed_before")], n, rng),
        "t4_xc_bsc": lambda n: _pick(ncd[(ncd.chain == "bsc") & (ncd.xc_label == "NCD-XC")], n, rng),
        "t4_xc_after": lambda n: _pick(ncd[(ncd.chain == "eth") & (ncd.xc_timing == "deployed_after")], n, rng),
        "t4_xc_unknown": lambda n: _pick(ncd[(ncd.chain == "eth") & (ncd.xc_label == "NCD-XC")
                                             & (ncd.xc_timing == "unknown")], n, rng),
        "ca_pcd": lambda n: pd.concat([_pick(m[m.xc_label == "PCD-Other"], n // 2, rng),
                                       _pick(m[m.xc_label == "PCD-XC"], n - n // 2, rng)]),
        "eoa_key": lambda n: by_chain(eoa[eoa.subtype == "KEY"], n),
        "eoa_addr": lambda n: by_chain(eoa[eoa.subtype == "ADDR"], n),
        "eoa_7702": lambda n: _pick(dl[sweep], n, rng, None),
        # ca khó: delegate là ví hợp lệ, không có đường chuyển tiền, hoặc chưa phân tích. Dữ liệu tác giả không có
        # EOA ủy quyền lành tính thật (mọi EOA đều lộ key/ADDR) → N6 đúng nghĩa cần dữ liệu mới (BigQuery, D1).
        "eoa_7702_other": lambda n: _pick(dl[~sweep], n, rng, None),
        "neg_n7_multichain": lambda n: _pick(s["n7"][s["n7"].kept].assign(chain="eth"), n, rng, None),
        "neg_n1_random": lambda n: _n1_random(s["candidate_addresses"], misuse_keys, n, rng),
    }
    rows, seen = [], set()
    for stratum, n in PILOT_PLAN:
        got = pools[stratum](n * 3)                       # dư để còn chỗ bỏ trùng
        k = 0
        for r in got.to_dict("records"):
            key = (r["chain"], r["address"].lower())
            if key in seen:
                continue
            seen.add(key)
            rows.append({"stratum": stratum, "chain": key[0], "address": key[1],
                         "author_label": r.get("label") if stratum.startswith("rq1_") else None})
            k += 1
            if k == n:
                break
        if k < n:
            print(f"  cảnh báo: tầng {stratum} chỉ có {k}/{n} mẫu")
    return pd.DataFrame(rows)


def _state(rec: dict) -> str | None:
    if rec.get("err"):
        return None
    return "7702" if rec.get("d") else ("code" if rec.get("s") else "none")


def live_evidence(chain: str, recs: dict[str, dict]) -> dict:
    """Bằng chứng code của một địa chỉ từ getCode trên mọi mạng (`recs[net]` = `_code_record`).

    Tính cùng một cách cho mọi mẫu (dương, âm, EOA): nếu chỉ một số tầng có ô được điền, người gán đoán ra tầng.
    """
    out = {f"code_{n}": _state(recs[n]) for n in NETWORKS}
    own = recs[chain]
    out["xc_nets"] = ",".join(n for n in NETWORKS if n != chain and out[f"code_{n}"] == "code")
    out["same_code_elsewhere"] = None if own.get("err") else bool(
        own.get("h") and any(recs[n].get("h") == own["h"] for n in NETWORKS if n != chain))
    out["delegate_7702"] = own.get("d")
    return out


def _probe_live(ev: pd.DataFrame) -> dict[tuple[str, str], str]:
    """Ghi đè code_<net>, xc_nets, same_code_elsewhere, delegate_7702 bằng getCode hiện tại cho mọi mẫu.
    Mạng nào RPC lỗi thì giữ trạng thái cũ (ma trận / N7). Trả bytecode đầy đủ trên chain của mẫu (cho symexec)."""
    from address_misuse.crosschain_matrix import _code_record, rpc_batch
    addrs = ev.address.tolist()
    recs, own_code = [{} for _ in addrs], {}
    for n in NETWORKS:
        try:
            codes = rpc_batch(n, [("eth_getCode", [a, "latest"]) for a in addrs])
        except Exception:
            codes = [None] * len(addrs)
        for j, (a, c, ch) in enumerate(zip(addrs, codes, ev.chain)):
            recs[j][n] = _code_record(a, c)
            if n == ch and c:
                own_code[(ch, a)] = c
    for j, (i, ch) in enumerate(zip(ev.index, ev.chain)):
        for col, v in live_evidence(ch, recs[j]).items():
            if col.startswith("code_") and v is None:
                continue                                   # RPC lỗi: giữ trạng thái từ ma trận nếu có
            ev.at[i, col] = v
    return own_code


SYMEXEC_CACHE = RAW_DIR / "gold" / "symexec_pilot.jsonl"


def _symexec_missing(tasks: list[tuple[str, str, str]], timeout: float = 120, workers: int = 2) -> dict:
    """Chạy symexec (engine của tác giả) cho các (chain, address, bytecode) chưa có kết quả của tác giả.
    Có cache: chạy lại `pilot` không phân tích lại."""
    from address_misuse.reproduce_symexec import run_isolated
    done = {}
    if SYMEXEC_CACHE.exists():
        for line in SYMEXEC_CACHE.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done[(r["chain"], r["address"])] = r
    todo = [(c, "pilot", a, code, timeout) for c, a, code in tasks if (c, a) not in done]
    if todo:
        print(f"  symexec {len(todo)} contract chưa có kết quả của tác giả (≤ {timeout + 60:.0f}s mỗi contract)…",
              flush=True)
        SYMEXEC_CACHE.parent.mkdir(parents=True, exist_ok=True)
        with SYMEXEC_CACHE.open("a", encoding="utf-8") as f:
            for r in run_isolated(todo, workers=workers, hard_limit=timeout + 60, max_mem_mb=1500):
                done[(r["chain"], r["address"])] = r
                f.write(json.dumps(r) + "\n")
                f.flush()
    return {k: {f: r[f"ours_{f}"] for f in SYMEXEC_FLAGS} for k, r in done.items() if r.get("status") == "ok"}


def _author_symexec(s: dict[str, pd.DataFrame]) -> dict[tuple[str, str], dict]:
    sx = s["symexec_results"].drop_duplicates(["chain", "address"])
    return {(c, a): {f: bool(v) for f, v in zip(SYMEXEC_FLAGS, vals)}
            for c, a, *vals in zip(sx.chain, sx.address, *(sx[f] for f in SYMEXEC_FLAGS))}


def _transfer(flags: dict | None) -> bool | None:
    return None if flags is None else bool(flags["transfer_all_eth"] or flags["transfer_msg_value"]
                                           or flags["transfer_input_amount"])


XC_ORIGIN_COLS = ["deployer", "create_kind", "origin_net", "first_create_ts", "first_tx_ts", "xc_timing", "redeploy"]


def add_evidence(sample: pd.DataFrame, s: dict[str, pd.DataFrame], run_symexec: bool = True) -> pd.DataFrame:
    keys = ["chain", "address"]
    m = s["matrix"].copy()
    ev = sample[keys].copy()

    # Không đưa n_tx / n_misuse_tx / cost_native của tác giả vào file mẫu: chúng chỉ có cho địa chỉ trong seed,
    # nên ô trống ở mẫu âm và số "misuse tx" > 0 ở mẫu dương đều làm lộ nhãn.

    code_cols = {f"{n}_state": f"code_{n}" for n in NETWORKS}
    m = m.reindex(columns=keys + list(code_cols) + ["deployer", "kind", "origin_net", "first_create_ts",
                                                   "first_tx_ts", "xc_timing", "redeploy"])
    ev = ev.merge(m.rename(columns={**code_cols, "kind": "create_kind"}), on=keys, how="left")
    ev = ev.reindex(columns=keys + list(code_cols.values()) + ["xc_nets", "same_code_elsewhere", "delegate_7702"]
                    + XC_ORIGIN_COLS).astype(object)

    n7 = s["n7"].set_index("address")
    for i, r in ev.iterrows():                           # dự phòng khi RPC lỗi: N7 không nằm trong ma trận misuse
        if r.address in n7.index and pd.isna(r.code_eth):
            nets = n7.loc[r.address, "networks_with_code"].split(",")
            for n in NETWORKS:
                ev.at[i, f"code_{n}"] = "code" if n in nets else "none"
    own_code = _probe_live(ev)
    own_state = [ev.at[i, f"code_{c}"] for i, c in zip(ev.index, ev.chain)]

    # Nguồn gốc / thời điểm deploy ở chain khác chỉ áp dụng khi chain này KHÔNG có code mà chain khác có
    # (tình huống T4). Ngoài tình huống đó để trống cho mọi mẫu, kể cả mẫu trong ma trận.
    xc = (ev.xc_nets.fillna("") != "") & (pd.Series(own_state, index=ev.index) != "code")
    ev.loc[~xc, XC_ORIGIN_COLS] = None

    # symexec cho contract trên chain này và cho delegate 7702: ưu tiên kết quả của tác giả, thiếu thì tự chạy.
    author = _author_symexec(s)
    need = {(c, a) for c, a, st in zip(ev.chain, ev.address, own_state) if st == "code" and (c, a) not in author}
    need_d = {(c, d) for c, d in zip(ev.chain, ev.delegate_7702) if isinstance(d, str) and (c, d) not in author}
    if need_d and run_symexec:
        from address_misuse.crosschain_matrix import rpc_batch
        for c in sorted({c for c, _ in need_d}):
            ds = sorted(d for cc, d in need_d if cc == c)
            for d, code in zip(ds, rpc_batch(c, [("eth_getCode", [d, "latest"]) for d in ds])):
                if code and code != "0x":
                    own_code[(c, d)] = code
    tasks = [(c, a, own_code[(c, a)]) for c, a in sorted(need | need_d) if (c, a) in own_code]
    flags = {**(_symexec_missing(tasks) if run_symexec and tasks else {}), **author}
    for f in SYMEXEC_FLAGS:
        ev[f"symexec_{f}"] = [flags.get((c, a), {}).get(f) if st == "code" else None
                              for c, a, st in zip(ev.chain, ev.address, own_state)]
    wallets = s["n6"][s["n6"].kept].set_index("address").wallet.to_dict() if len(s["n6"]) else {}
    ev["delegate_symexec_transfer"] = [_transfer(flags.get((c, d))) if isinstance(d, str) else None
                                       for c, d in zip(ev.chain, ev.delegate_7702)]
    ev["delegate_known_wallet"] = [wallets.get(d) if isinstance(d, str) else None for d in ev.delegate_7702]

    ev["first_create_date"] = ev.first_create_ts.map(_date)
    ev["first_tx_date"] = ev.first_tx_ts.map(_date)
    ev = ev.drop(columns=["first_create_ts", "first_tx_ts"])
    ev["explorer_url"] = [EXPLORERS[c] + a for c, a in zip(ev.chain, ev.address)]
    ev["explorer_url_xc"] = [EXPLORERS[o] + a if isinstance(o, str) and o in EXPLORERS else None
                             for o, a in zip(ev.origin_net, ev.address)]
    return ev


def cmd_pilot(seed: int = 0) -> pd.DataFrame:
    s = load_sources()
    sample = draw_pilot(s, seed)
    ev = add_evidence(sample, s)
    order = np.random.default_rng(seed + 1).permutation(len(sample))   # xáo để người gán không đoán được tầng
    sample = sample.iloc[order].reset_index(drop=True)
    sample.insert(0, "item_id", [f"P{i + 1:03d}" for i in range(len(sample))])
    items = sample[["item_id", "chain", "address"]].merge(ev, on=["chain", "address"], how="left")
    items = items.astype(object).where(items.notna() & (items != ""), "-")      # "-" = không tra được, không suy ra gì từ ô này
    GOLD_DIR.mkdir(parents=True, exist_ok=True)
    items.to_csv(GOLD_DIR / "pilot50_items.csv", index=False, encoding="utf-8")
    sample[["item_id", "chain", "address", "stratum", "author_label"]].to_csv(
        GOLD_DIR / "pilot50_key.csv", index=False, encoding="utf-8")
    pd.DataFrame({"item_id": items.item_id, **{c: "" for c in LABEL_COLS}}).to_csv(
        GOLD_DIR / "annotator_template.csv", index=False, encoding="utf-8")
    print(f"Ghi {len(items)} mẫu → {GOLD_DIR / 'pilot50_items.csv'} (+ pilot50_key.csv, annotator_template.csv)")
    print(sample.stratum.value_counts().sort_index().to_string())
    return items


# ---------------------------------------------------------------- mẫu vàng chính (từ dataset_v2)

# Số mẫu mỗi tầng; None = lấy hết. Tầng "+D6" = dương mới D6 (label_source == d6_rule). Kéo từ test ∪ out_of_time của
# dataset_v2 (không lấy train/val/excluded/no_time): nhãn vàng dùng để chấm engine nên phải ở tập đánh giá. PLAN_V2 cũ ghi
# "~1.000 dương mới", nhưng dataset_v2 chỉ có 42 dương mới và ~450 dương test, nên mẫu chính là ~600 (xem FINDINGS_LOG).
MAIN_PLAN = {"+ADDR": 60, "+KEY": 60, "+NCD": 80, "+PCD": 50, "+D6": None, "-N1": 40, "-N2": 60, "-N3": 40, "-N4": 30,
             "-N5": None, "-N6": None, "-N7": None, "-N8": 80}


def draw_main(ds: pd.DataFrame, seed: int = 0, n_double: int = 200) -> pd.DataFrame:
    """Rút mẫu phân tầng từ dataset_v2. `weight` = số mẫu của tầng trong tập đánh giá / số mẫu rút (để ước lượng precision,
    recall không lệch khi tầng bị lấy mẫu con). Mỗi (chain, address) tối đa một mẫu."""
    rng = np.random.default_rng(seed)
    pool = ds[(ds.split == "test") | ds.out_of_time].copy()
    pool = pool[pool.split != "excluded"]
    pool["stratum"] = np.where(pool.label_source == "d6_rule", "+D6", pool.grp)
    pool = pool.sample(frac=1, random_state=int(rng.integers(2**31)))        # xáo trước khi bỏ trùng
    picked, taken = [], set()
    for stratum, n in MAIN_PLAN.items():
        d = pool[pool.stratum == stratum].drop_duplicates(["chain", "address"])
        d = d[np.array([k not in taken for k in zip(d.chain, d.address)], dtype=bool)]   # np: list rỗng sẽ chọn 0 cột
        if n is None or len(d) <= n:
            got = d
        else:                                              # chia đều giữa eth và bsc khi đủ mẫu
            half = {"eth": n - n // 2, "bsc": n // 2}
            got = pd.concat([d[d.chain == c].head(k) for c, k in half.items()])
            if len(got) < n:
                got = pd.concat([got, d.drop(got.index).head(n - len(got))])
        if n is not None and len(got) < n:
            print(f"  cảnh báo: tầng {stratum} chỉ có {len(got)}/{n} mẫu")
        taken |= set(zip(got.chain, got.address))
        picked.append(got.assign(weight=len(d) / max(len(got), 1)))
    out = pd.concat(picked)
    out = out.iloc[np.random.default_rng(seed + 1).permutation(len(out))].reset_index(drop=True)
    out["double"] = False
    out.loc[out.sample(min(n_double, len(out)), random_state=int(rng.integers(2**31))).index, "double"] = True
    out.insert(0, "item_id", [f"G{i + 1:03d}" for i in range(len(out))])
    return out


def event_tx(chain: str, address: str, at) -> dict | None:
    """Tx đi vào `address` tại đúng thời điểm `at` (mẫu theo địa chỉ chọn `at` từ một tx đi vào, nhưng dataset không lưu hash).
    Cần cho người gán thấy cùng loại bằng chứng ở mọi mẫu: nếu chỉ mẫu âm theo tx có tx_hash thì có hash = âm."""
    import gzip
    from address_misuse.engine.features import txlist_path
    p = txlist_path(chain, address)
    if not p.exists() or at is None or pd.isna(at):
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        txs = json.load(f)["result"]
    hit = [t for t in txs if (t.get("to") or "").lower() == address and int(t["timeStamp"]) == int(at)]
    hit.sort(key=lambda t: (int(t["gasUsed"]) <= 21_000, int(t.get("transactionIndex") or 0)))   # ưu tiên tx có calldata
    return hit[0] if hit else None


def main_evidence(sample: pd.DataFrame, s: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Bằng chứng theo địa chỉ (`add_evidence`) + bằng chứng THEO THỜI ĐIỂM `at` của mẫu: ngày xét, trạng thái code lúc đó
    (một PCD chưa có contract lúc `at` thì trạng thái là none), ngày tạo contract, tx (hash, selector, value) nếu là mẫu
    theo tx. Không đưa nhãn, tầng, điểm R hay số liệu của tác giả cho người gán."""
    from address_misuse.engine.features import FeatureStore
    ev = add_evidence(sample[["chain", "address"]].drop_duplicates(), s)
    fs = FeatureStore(load_history=False)
    rows = []
    for r in sample.itertuples():
        f = fs.features(r.address, r.chain, int(r.at))
        cts = fs.own_create.get((r.chain, r.address))
        tx_hash, selector, value = (r.tx_hash if isinstance(r.tx_hash, str) else None, r.selector,
                                    None if pd.isna(r.value_wei) else int(r.value_wei) / 1e18)
        if tx_hash is None and (t := event_tx(r.chain, r.address, r.at)):       # mẫu theo địa chỉ: khôi phục tx tại `at`
            inp = t.get("input") or "0x"
            tx_hash, selector, value = t["hash"], inp[:10] if len(inp) >= 10 else None, int(t["value"]) / 1e18
        rows.append({"item_id": r.item_id, "at_date": _date(r.at), "code_at_event": f.state() or "-",
                     "own_create_date": _date(cts) if cts else None, "tx_hash": tx_hash, "selector": selector,
                     "value_native": value})
    items = sample[["item_id", "chain", "address"]].merge(pd.DataFrame(rows), on="item_id").merge(
        ev, on=["chain", "address"], how="left")
    return items.astype(object).where(items.notna() & (items != ""), "-")


def cmd_main(seed: int = 0, n_double: int = 200) -> pd.DataFrame:
    from address_misuse.config import FINAL_DIR
    p = FINAL_DIR / "dataset_v2.parquet"
    if not p.exists():
        raise SystemExit("chưa có dataset_v2.parquet: chạy address_misuse.freeze (sau khi engine.evaluate xong)")
    sample = draw_main(pd.read_parquet(p), seed, n_double)
    items = main_evidence(sample, load_sources())
    GOLD_DIR.mkdir(parents=True, exist_ok=True)
    items.to_csv(GOLD_DIR / "main_items.csv", index=False, encoding="utf-8")
    key = sample[["item_id", "sample_id", "stratum", "grp", "chain", "address", "label", "label_source", "split",
                  "out_of_time", "needs_review", "weight", "double"]]
    key.to_csv(GOLD_DIR / "main_key.csv", index=False, encoding="utf-8")
    print(f"Ghi {len(items)} mẫu ({int(sample.double.sum())} gán đôi để tính κ) → {GOLD_DIR / 'main_items.csv'} (+ main_key.csv)")
    print(sample.groupby("stratum").agg(n=("item_id", "size"), weight=("weight", "first")).round(2).to_string())
    return items


# ---------------------------------------------------------------- file Excel cho người gán

CHOICES = {"is_misuse": ["1", "0", "?"], "type": ["T1", "T2", "T3", "T4", "T5", "T6", "NONE"],
           "subtype": ["NCD", "PCD", "KEY", "ADDR", "7702", "-"], "malicious": ["1", "0", "-"],
           "confidence": ["high", "medium", "low"]}
SHEET = "Gan_nhan"
GUIDE = [
    "HƯỚNG DẪN GÁN NHÃN (tóm tắt docs/CODEBOOK.md v0.3 §2–§6; đọc bản đầy đủ nếu phân vân)",
    "",
    "Quy tắc: gán ĐỘC LẬP. Không xem pilot50_key.csv, file của người gán kia, hay CODEBOOK §10 trước khi xong.",
    "Chỉ điền các cột màu vàng ở sheet Gan_nhan. Các cột còn lại là bằng chứng; ô '-' = không tra được, không suy ra gì.",
    "Trạng thái code là HIỆN TẠI. Khi kết luận phụ thuộc thời điểm (T4, PCD) hãy xem first_tx_date hoặc mở explorer_url.",
    "",
    "is_misuse: 1 / 0 / ?   (? chỉ khi thiếu bằng chứng, tối đa 5 mẫu)",
    "type: một type chính T1…T6, hoặc NONE khi is_misuse = 0",
    "  T1 gọi hàm tới địa chỉ không có code (NCD), không có contract cùng địa chỉ ở chain khác deploy TRƯỚC tx",
    "  T2 contract 'hố đen' hoặc contract cài sẵn chiếm tiền (PCD, không có đường rút)",
    "  T3 gửi token vào chính contract token đó",
    "  T4 NCD trên chain này + cùng địa chỉ có code ở chain khác, deploy TRƯỚC tx đầu tiên (ghi xc_chain)",
    "  T5 key lộ / sweeper / EIP-7702 delegate độc (ADDR cũng T5 nếu tiền bị sweeper rút)",
    "  T6 address poisoning (trùng 4 ký tự đầu + 4 cuối, có tx mồi giá trị 0)",
    "  Ưu tiên: T4 > T1; T5 > T6",
    "subtype: NCD / PCD / KEY / ADDR / 7702 / -",
    "xc_chain: chỉ với T4, tên chain có contract gốc (eth, bsc, arb, op, base, polygon…); còn lại '-'",
    "malicious: 1 nếu có bên thứ ba chủ động khai thác (sweeper, contract cài sẵn, delegate độc); 0; hoặc '-'",
    "confidence: high / medium / low (mức chắc chắn của chính bạn)",
    "evidence: bằng chứng đã dùng, ví dụ: code, timing, tx, symexec, label",
    "note: BẮT BUỘC khi confidence = low, is_misuse = ?, hoặc mẫu là ca khó (CODEBOOK §5)",
    "",
    "Cây quyết định (CODEBOOK §4):",
    "1. Địa chỉ có code trên chain này lúc tx?  Không → 2;  Có → 4",
    "2. Tx gọi hàm / hành vi chỉ hợp lý với contract?  Không → 5;  Có → 3",
    "3. Cùng địa chỉ có code ở chain khác deploy TRƯỚC tx đầu tiên?  Có → T4;  deploy SAU → T1 (note 'xc deployed_after');  không rõ → T1",
    "4. Code là contract người dùng định gọi và gọi đúng hàm → NONE;  là 7702 (0xef0100…) → 5;  không phải (PCD) → T2",
    "5. EOA: key lộ / delegate độc / tiền bị rút gần như ngay → T5;  giống địa chỉ quen + tx mồi → T6;  ví thường/sàn/smart wallet hợp lệ → NONE",
    "",
    "Ca khó hay gặp (CODEBOOK §5):",
    "- xc_timing = deployed_after → T1, không phải T4.  xc_timing = unknown → mở explorer chain kia; vẫn không biết → T4, confidence low.",
    "- Cùng contract trên mọi chain kể cả chain này (Multicall3, Permit2, Safe, EntryPoint…) → âm.",
    "- Gửi nhầm tới predeploy của chain KHÁC (ví dụ 0x4200…0006 trên ETH) → T4.  Precompile/system contract của chính chain → thường âm.",
    "- 7702 tới smart wallet hợp lệ (delegate_known_wallet có tên) và chủ ví vẫn rút tiền bình thường → âm.",
    "  delegate_symexec_transfer = True KHÔNG có nghĩa là độc; phải xem tiền thực tế đi đâu.",
    "- Ví sàn auto-sweep về ví tổng của sàn → âm.  Tx chỉ mất gas tới NCD vẫn là misuse.  Calldata là văn bản tới EOA → âm.",
    "",
    "Xong thì lưu file (giữ nguyên tên sheet Gan_nhan) và báo lại để tính κ.",
]


GUIDE_MAIN = [
    "MẪU CHÍNH: mỗi dòng là một địa chỉ TẠI THỜI ĐIỂM at_date (không phải trạng thái hôm nay). Hãy xét đúng tx có tx_hash.",
    "tx_hash / selector / value_native = tx đi vào địa chỉ tại at_date (selector '-' nghĩa là chuyển coin thuần, không calldata).",
    "code_at_event = trạng thái code lúc at_date (none / code / 7702); own_create_date = ngày contract được tạo trên chain này.",
    "Contract tạo SAU at_date nghĩa là lúc đó địa chỉ chưa có code: tx lúc đó là gọi tới địa chỉ trống (CODEBOOK §3).",
    "LƯU Ý: với mẫu chính, dùng code_at_event. Các cột code_eth, code_bsc… vẫn là trạng thái HIỆN TẠI (dòng 'Trạng thái code là HIỆN TẠI'",
    "bên dưới chỉ áp dụng cho các cột đó). first_tx_date / xc_timing có thể '-': mở explorer_url để xem.",
    "Dấu '?' ở mẫu chính: tối đa khoảng 10% số mẫu bạn gán (không phải 5 mẫu như pilot).",
    "",
]


def cmd_sheet(who: str, which: str = "pilot", only_double: bool = False) -> None:
    """File Excel cho người gán `who`: bằng chứng (đã làm mù) + cột nhãn có danh sách chọn + sheet hướng dẫn."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    items = pd.read_csv(GOLD_DIR / ("pilot50_items.csv" if which == "pilot" else "main_items.csv"), dtype=str).fillna("-")
    if only_double:                                      # người gán thứ hai chỉ làm tập gán đôi (để tính κ)
        key = pd.read_csv(GOLD_DIR / "main_key.csv", dtype=str)
        items = items[items.item_id.isin(key[key.double == "True"].item_id)].reset_index(drop=True)
    evidence = [c for c in items.columns if c not in ("item_id", "chain", "address")]
    cols = ["item_id", "chain", "address", *LABEL_COLS, *evidence]
    out = GOLD_DIR / (f"annotator_{who}.xlsx" if which == "pilot" else f"annotator_main_{who}.xlsx")
    if out.exists():
        raise SystemExit(f"{out} đã có, không ghi đè (có thể đã có nhãn). Xoá/đổi tên trước nếu muốn tạo lại.")
    wb = Workbook()
    ws = wb.active
    ws.title = SHEET
    ws.append(cols)
    for _, r in items.iterrows():
        ws.append([r.get(c, "") for c in cols])
    yellow, bold = PatternFill("solid", fgColor="FFF2CC"), Font(bold=True)
    last = len(items) + 1
    for j, c in enumerate(cols, 1):
        ws.cell(1, j).font = bold
        ws.column_dimensions[get_column_letter(j)].width = 44 if c in ("address", "note") else 12 if c in LABEL_COLS else 16
        for i in range(2, last + 1):
            cell = ws.cell(i, j)
            if c in LABEL_COLS:
                cell.fill = yellow
                cell.number_format = "@"                        # giữ "1"/"0" là chữ, không thành số
            elif c.startswith("explorer_url") and str(cell.value).startswith("http"):
                cell.hyperlink = cell.value
                cell.style = "Hyperlink"
        if c in LABEL_COLS:
            ws.cell(1, j).fill = yellow
    for c, opts in CHOICES.items():
        col = get_column_letter(cols.index(c) + 1)
        dv = DataValidation(type="list", formula1='"' + ",".join(opts) + '"', allow_blank=True)
        dv.add(f"{col}2:{col}{last}")
        ws.add_data_validation(dv)
    ws.freeze_panes = "D2"                                      # giữ dòng tiêu đề + mã, chain, địa chỉ
    g = wb.create_sheet("Huong_dan")
    for line in (GUIDE_MAIN if which == "main" else []) + GUIDE:
        g.append([line])
    g["A1"].font = bold
    g.column_dimensions["A"].width = 140
    for row in g.iter_rows():
        row[0].alignment = Alignment(wrap_text=True, vertical="top")
    wb.save(out)
    print(f"Ghi {len(items)} mẫu → {out}")


def read_labels(path: str) -> pd.DataFrame:
    """Nhãn của một người gán, từ .csv (annotator_template) hoặc .xlsx (`cmd_sheet`)."""
    if str(path).lower().endswith(".xlsx"):
        d = pd.read_excel(path, sheet_name=SHEET, dtype=str)
    else:
        d = pd.read_csv(path, dtype=str)
    d = d[["item_id", *[c for c in ("address", *LABEL_COLS) if c in d.columns]]].fillna("")
    return d.apply(lambda s: s.str.strip())


def check_labels(d: pd.DataFrame) -> list[str]:
    """Lỗi hình thức theo CODEBOOK §2 (không so với nhãn tác giả hay người gán kia)."""
    errs = []
    for r in d.itertuples(index=False):
        g = r._asdict()
        at = lambda c: g.get(c, "")
        for c, opts in CHOICES.items():
            v = at(c)
            if c in ("is_misuse", "type", "confidence") and not v:
                errs.append(f"{r.item_id}: thiếu {c}")
            elif v and v.lower() not in [o.lower() for o in opts]:
                errs.append(f"{r.item_id}: {c} = {v!r} không hợp lệ")
        m, t = at("is_misuse"), at("type").upper()
        if m == "0" and t and t != "NONE":
            errs.append(f"{r.item_id}: is_misuse = 0 nhưng type = {t} (phải NONE)")
        if m == "1" and t == "NONE":
            errs.append(f"{r.item_id}: is_misuse = 1 nhưng type = NONE")
        xc = at("xc_chain")
        if t == "T4" and xc in ("", "-"):
            errs.append(f"{r.item_id}: T4 nhưng chưa ghi xc_chain")
        if t != "T4" and xc not in ("", "-"):
            errs.append(f"{r.item_id}: xc_chain = {xc} chỉ dùng với T4 (ghi vào note nếu cần)")
        if (at("confidence").lower() == "low" or m == "?") and not at("note"):
            errs.append(f"{r.item_id}: confidence low hoặc is_misuse ? thì phải có note")
    n_q = int((d.is_misuse == "?").sum())
    if n_q > len(d) // 10:
        errs.append(f"có {n_q} mẫu is_misuse = ? (tối đa {len(d) // 10})")
    return errs


def cmd_check(path: str) -> None:
    d = read_labels(path)
    errs = check_labels(d)
    filled = d.is_misuse != ""
    print(f"{path}: {int(filled.sum())}/{len(d)} mẫu đã điền is_misuse")
    for col in ("is_misuse", "type", "confidence"):
        print(f"  {col}: " + ", ".join(f"{k or '(trống)'} {n}" for k, n in d[col].value_counts().items()))
    print("Không có lỗi hình thức." if not errs else f"{len(errs)} lỗi:\n  " + "\n  ".join(errs))


# ---------------------------------------------------------------- κ

def cohen_kappa(a: list, b: list) -> float:
    """Cohen's κ cho hai dãy nhãn danh định cùng độ dài."""
    if len(a) != len(b) or not a:
        raise ValueError("hai dãy nhãn phải cùng độ dài, khác rỗng")
    cats = sorted(set(a) | set(b), key=str)
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def cmd_kappa(path_a: str, path_b: str) -> dict[str, float]:
    a = read_labels(path_a)
    b = read_labels(path_b)
    j = a.merge(b, on="item_id", suffixes=("_A", "_B"))
    if "address_A" in j and "address_B" in j:                   # hai người phải gán cùng một bộ mẫu
        diff = j[j.address_A.str.lower() != j.address_B.str.lower()]
        if len(diff):
            raise SystemExit(f"{len(diff)} item_id trỏ tới địa chỉ khác nhau, ví dụ {diff.item_id.iloc[0]}: hai file không cùng bộ mẫu")
    j = j[(j.is_misuse_A != "") & (j.is_misuse_B != "")]
    out = {}
    for col in ("is_misuse", "type"):
        x = j[f"{col}_A"].str.strip().str.upper().tolist()
        y = j[f"{col}_B"].str.strip().str.upper().tolist()
        out[col] = cohen_kappa(x, y)
        print(f"κ({col}) = {out[col]:.3f} trên {len(j)} mẫu, đồng ý {sum(p == q for p, q in zip(x, y))}/{len(j)}")
    dis = j[(j.is_misuse_A.str.upper() != j.is_misuse_B.str.upper()) | (j.type_A.str.upper() != j.type_B.str.upper())]
    if len(dis):
        print("\nBất đồng cần phân xử:")
        print(dis[["item_id", "is_misuse_A", "type_A", "is_misuse_B", "type_B"]].to_string(index=False))
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pilot")
    p.add_argument("--seed", type=int, default=0)
    c = sub.add_parser("check")
    c.add_argument("path")
    sh = sub.add_parser("sheet")
    sh.add_argument("who", nargs="?", default="B")
    sh.add_argument("--set", choices=["pilot", "main"], default="pilot")
    sh.add_argument("--only-double", action="store_true")
    mn = sub.add_parser("main")
    mn.add_argument("--seed", type=int, default=0)
    mn.add_argument("--double", type=int, default=200)
    k = sub.add_parser("kappa")
    k.add_argument("a")
    k.add_argument("b")
    args = ap.parse_args()
    if args.cmd == "pilot":
        cmd_pilot(args.seed)
    elif args.cmd == "check":
        cmd_check(args.path)
    elif args.cmd == "main":
        cmd_main(args.seed, args.double)
    elif args.cmd == "sheet":
        cmd_sheet(args.who, args.set, args.only_double)
    else:
        cmd_kappa(args.a, args.b)


if __name__ == "__main__":
    main()
