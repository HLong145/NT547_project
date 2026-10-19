"""D5 — lấy mẫu gán nhãn vàng (pilot 50 mẫu) kèm bằng chứng điền sẵn, và tính Cohen's κ.

python -X utf8 -m address_misuse.sample_gold pilot [--seed 0]
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
    a = pd.read_csv(path_a, dtype=str).fillna("")
    b = pd.read_csv(path_b, dtype=str).fillna("")
    j = a.merge(b, on="item_id", suffixes=("_A", "_B"))
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
    k = sub.add_parser("kappa")
    k.add_argument("a")
    k.add_argument("b")
    args = ap.parse_args()
    if args.cmd == "pilot":
        cmd_pilot(args.seed)
    else:
        cmd_kappa(args.a, args.b)


if __name__ == "__main__":
    main()
