"""D6 bước 2: tìm dương MỚI (misuse từ 2025-09-01) trong ứng viên ETH chưa bị tác giả gắn cờ — tập test ngoài thời gian (D8, B).

python -X utf8 -m address_misuse.d6_new state      → data/interim/d6_state.parquet   (getCode hiện tại, RPC công khai)
python -X utf8 -m address_misuse.d6_new created    → data/raw/eth/creation.jsonl     (getcontractcreation, Etherscan)
python -X utf8 -m address_misuse.d6_new delegates  → data/interim/d6_delegates.parquet (symexec delegate 7702 mới)
python -X utf8 -m address_misuse.d6_new rules [--per-type 400] [--only ADDR] → data/interim/d6_new_positives.parquet
python -X utf8 -m address_misuse.d6_new recost     → tính lại số tx / loss mới từ txlist đã cache (không gọi mạng)

Đầu vào: `data/raw/eth/bq_new_activity.parquet` (`bq_fetch new-fetch`, một dòng thống kê mỗi ứng viên có tx từ 2025-09-01).
Lọc theo đúng luật của tác giả (`rules.py`), chỉ thêm bước sàng rẻ ở đầu:
- CA (NCD/PCD): có tx gọi hàm đi vào và địa chỉ chưa từng tự gửi tx (contract không gửi tx; địa chỉ contract suy từ
  deployer + nonce không có private key). Không code → NCD; có code tạo SAU tx vào đầu tiên trong cửa sổ → PCD;
  có code tạo trước 2025-09-01 → không thể có tx gọi sớm trong cửa sổ, bỏ.
- ADDR: EOA đã gửi tx type 4 và hiện uỷ quyền EIP-7702 tới delegate có đường chuyển tiền, đúng điều kiện của tác giả
  (`txs_analyzer.match_EOAMisuse_rules_for_ADDR`: symexec `transfer_all_eth` hoặc `transfer_msg_value`). Danh sách
  delegate của tác giả đã cũ nên `delegates` chạy symexec cho mọi delegate mới (mỗi bytecode một lần).
- KEY: chưa làm (địa chỉ lộ key gần như không nằm trong `candidate_addresses`, cần truy vấn riêng).
Mỗi loại lấy mẫu ngẫu nhiên `--per-type` địa chỉ (seed cố định), tải txlist Etherscan (≤ 10k tx), chạy luật; dương mới
= có ít nhất một tx bị gắn cờ từ 2025-09-01. Đây là nhãn theo luật, vẫn cần nhãn vàng (D5).
Loss mới (`cost_wei_new`) = value + phí gas các tx bị gắn cờ từ 2025-09-01, cùng định nghĩa `cost_wei` của tác giả;
`value_wei_new` = chỉ phần value.
"""

import argparse
import json

import pandas as pd

from address_misuse.config import INTERIM_DIR, OUT_OF_TIME_TS, RAW_DIR, SEED_DIR
from address_misuse.crosschain_matrix import rpc_batch

ACTIVITY = RAW_DIR / "eth" / "bq_new_activity.parquet"
STATE = INTERIM_DIR / "d6_state.parquet"
OUT = INTERIM_DIR / "d6_new_positives.parquet"
DELEGATES = INTERIM_DIR / "d6_delegates.parquet"
EIP7702_PREFIX = "0xef0100"
BATCH = 100
MAX_RECORDS = 10_000


def screened() -> pd.DataFrame:
    """Ứng viên qua bước sàng: `kind` = "ca" (nhận tx gọi hàm, không tự gửi) hoặc "7702" (đã gửi tx type 4)."""
    d = pd.read_parquet(ACTIVITY)
    ca = d[(d.n_in_call.fillna(0) > 0) & d.n_out.isna()].assign(kind="ca")
    t4 = d[d.n_out_type4.fillna(0) > 0].assign(kind="7702")
    return pd.concat([ca, t4], ignore_index=True)


def code_state(code: str | None) -> tuple[str, str | None]:
    if code is None:
        return "error", None
    if code.startswith(EIP7702_PREFIX):
        return "7702", "0x" + code[len(EIP7702_PREFIX):len(EIP7702_PREFIX) + 40]
    return ("none" if code in ("0x", "") else "code"), None


def cmd_state():
    s = screened()
    old = pd.read_parquet(STATE) if STATE.exists() else pd.DataFrame(columns=["address", "state", "delegate"])
    done = set(old[old.state != "error"].address)
    todo = sorted(set(s.address) - done)
    print(f"getCode: {len(todo):,} địa chỉ cần tra (đã có {len(done):,})", flush=True)
    rows, parts = [], [old[old.state != "error"]]
    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        try:
            codes = rpc_batch("eth", [("eth_getCode", [a, "latest"]) for a in chunk], timeout=60)
        except Exception as e:
            print(f"  lỗi lô {i}: {type(e).__name__}", flush=True)
            codes = [None] * len(chunk)
        for a, c in zip(chunk, codes):
            st, dlg = code_state(c)
            rows.append({"address": a, "state": st, "delegate": dlg})
        if (i // BATCH) % 100 == 99 or i + BATCH >= len(todo):          # ghi tạm để chạy lại tiếp tục được
            pd.concat(parts + [pd.DataFrame(rows)], ignore_index=True).to_parquet(STATE, index=False)
            print(f"  {min(i + BATCH, len(todo)):,}/{len(todo):,}", flush=True)
    out = pd.concat(parts + [pd.DataFrame(rows)], ignore_index=True)
    out.to_parquet(STATE, index=False)
    print(out.state.value_counts().to_string())


def _state_table() -> pd.DataFrame:
    return screened().merge(pd.read_parquet(STATE), on="address", how="left")


def cmd_created():
    from address_misuse.etherscan import Etherscan
    from address_misuse.reproduce_rules import fetch_creations
    d = _state_table()
    code = sorted(set(d[(d.kind == "ca") & (d.state == "code")].address))
    print(f"getcontractcreation: {len(code):,} contract (Etherscan, 5 địa chỉ/lần, có cache)", flush=True)
    fetch_creations(Etherscan("eth"), code)


def load_creations(chain: str) -> dict[str, dict]:
    """Cache của `reproduce_rules.fetch_creations` ({} = không phải contract)."""
    path = RAW_DIR / chain / "creation.jsonl"
    if not path.exists():
        return {}
    return {r["address"]: r["creation"] for r in map(json.loads, path.read_text(encoding="utf-8").splitlines())}


def malicious_delegates() -> set[str]:
    """Delegate đủ điều kiện ADDR theo tác giả. Chưa chạy `delegates` thì dùng `flag` của tác giả (danh sách cũ)."""
    if DELEGATES.exists():
        d = pd.read_parquet(DELEGATES)
        return set(d[d.author_rule == True].delegate)                       # noqa: E712
    print("  chưa có d6_delegates.parquet, dùng danh sách delegate cũ của tác giả", flush=True)
    st = pd.read_parquet(SEED_DIR / "eip7702_delegate_stats.parquet").query("chain == 'eth' and flag == 1")
    return set(st.delegate.str.lower())


def _symexec_flags() -> dict[str, dict]:
    """delegate (eth) -> cờ symexec: của tác giả trước, thiếu thì kết quả nhóm chạy lại (status ok)."""
    from address_misuse.engine.features import ENGINE_SYMEXEC
    out = {}
    sx = pd.read_parquet(SEED_DIR / "symexec_results.parquet").query("chain == 'eth'")
    for r in sx.itertuples():
        out[r.address] = {"all_eth": bool(r.transfer_all_eth), "msg_value": bool(r.transfer_msg_value),
                          "input_amount": bool(r.transfer_input_amount), "delegatecall": bool(r.delegatecall),
                          "source": "author"}
    rows = []
    for path in (INTERIM_DIR / "symexec_repro.parquet",):
        if path.exists():
            rows += pd.read_parquet(path).to_dict("records")
    if ENGINE_SYMEXEC.exists():
        rows += [json.loads(x) for x in ENGINE_SYMEXEC.read_text(encoding="utf-8").splitlines() if x.strip()]
    for r in rows:
        if r.get("chain") == "eth" and r.get("status") == "ok":
            out.setdefault(r["address"], {"all_eth": bool(r["ours_transfer_all_eth"]),
                                          "msg_value": bool(r["ours_transfer_msg_value"]),
                                          "input_amount": bool(r["ours_transfer_input_amount"]),
                                          "delegatecall": bool(r["ours_delegatecall"]), "source": "ours"})
    return out


def cmd_delegates(timeout: float, workers: int):
    """Symexec mọi delegate 7702 trong `d6_state` chưa có kết quả, nhiều EOA trước; bytecode trùng chỉ chạy một lần.
    Kết quả ghi thêm vào `engine_symexec.jsonl` (engine dùng chung), bảng tổng hợp → `d6_delegates.parquet`."""
    import hashlib
    from address_misuse.engine.features import ENGINE_SYMEXEC
    from address_misuse.reproduce_symexec import run_isolated
    n_eoa = pd.read_parquet(STATE).query("state == '7702'").delegate.value_counts()
    dels = n_eoa.index.tolist()
    codes = {}
    for i in range(0, len(dels), BATCH):
        chunk = dels[i:i + BATCH]
        codes.update(zip(chunk, rpc_batch("eth", [("eth_getCode", [a, "latest"]) for a in chunk], timeout=60)))
    h = {a: hashlib.sha256((c or "").encode()).hexdigest()[:16] for a, c in codes.items()}
    flags = _symexec_flags()
    done_hash = {h[a] for a in dels if a in flags}
    tasks, seen = [], set()
    for a in dels:                                                      # thứ tự: nhiều EOA trước
        c = codes.get(a)
        if a in flags or not c or c == "0x" or h[a] in done_hash or h[a] in seen:
            continue
        seen.add(h[a])
        tasks.append(("eth", "eip7702_delegate", a, c, timeout))
    print(f"delegate 7702: {len(dels)}, đã có symexec {sum(a in flags for a in dels)}, "
          f"bytecode khác nhau cần chạy {len(tasks)}", flush=True)
    with ENGINE_SYMEXEC.open("a", encoding="utf-8") as f:
        for i, r in enumerate(run_isolated(tasks, workers=workers, hard_limit=timeout + 60, max_mem_mb=1500), 1):
            f.write(json.dumps(r) + "\n")
            f.flush()
            if i % 10 == 0 or i == len(tasks):
                print(f"  {i}/{len(tasks)}", flush=True)
    flags = _symexec_flags()
    by_hash = {}
    for a in dels:
        if a in flags:
            by_hash.setdefault(h[a], flags[a])
    wallets = {}
    n6 = INTERIM_DIR / "n6_benign_7702_delegates.parquet"
    if n6.exists():
        w = pd.read_parquet(n6).query("kept")
        wallets = dict(zip(w.address.str.lower(), w.wallet))
    rows = []
    for a in dels:
        f = flags.get(a) or by_hash.get(h[a])
        rows.append({"delegate": a, "n_eoa": int(n_eoa[a]), "code_hash": h[a], "has_code": bool(codes.get(a) not in (None, "", "0x")),
                     "symexec": None if f is None else ("own" if a in flags else "same_code"),
                     "source": None if f is None else f["source"],
                     **{k: (None if f is None else f[k]) for k in ("all_eth", "msg_value", "input_amount", "delegatecall")},
                     "author_rule": None if f is None else bool(f["all_eth"] or f["msg_value"]),
                     "known_wallet": wallets.get(a)})
    out = pd.DataFrame(rows)
    out.to_parquet(DELEGATES, index=False)
    w = out.n_eoa
    print(f"có kết quả: {out.author_rule.notna().sum()}/{len(out)} delegate ({w[out.author_rule.notna()].sum():,}/{w.sum():,} EOA)")
    print(f"đủ điều kiện ADDR (all_eth|msg_value): {int((out.author_rule == True).sum())} delegate, "   # noqa: E712
          f"{w[out.author_rule == True].sum():,} EOA; trong đó ví hợp lệ N6: "                     # noqa: E712
          f"{int(((out.author_rule == True) & out.known_wallet.notna()).sum())}")                  # noqa: E712


def candidates() -> pd.DataFrame:
    """Ứng viên theo loại luật: NCD, PCD (có thời điểm tạo trong/ sau cửa sổ), ADDR (delegate độc)."""
    d = _state_table()
    cr = load_creations("eth")
    ca = d[d.kind == "ca"].copy()
    ca["create_ts"] = [int(cr[a]["timestamp"]) if cr.get(a) else None for a in ca.address]
    ncd = ca[ca.state == "none"].assign(rule="NCD")
    pcd = ca[(ca.state == "code") & (ca.create_ts.fillna(0) > ca.first_in_ts)].assign(rule="PCD")
    addr = d[(d.kind == "7702") & d.delegate.isin(malicious_delegates())].assign(rule="ADDR")
    return pd.concat([ncd, pcd, addr], ignore_index=True)


def cmd_rules(per_type: int, seed: int, only: str | None = None, no_wallets: bool = False):
    from address_misuse.etherscan import Etherscan
    from address_misuse.reproduce_rules import fetch_txlist
    c = candidates()
    if only:
        c = c[c.rule == only]
    if no_wallets and DELEGATES.exists():                       # bỏ EOA dùng delegate của ví hợp lệ (N6, vd MetaMask)
        d = pd.read_parquet(DELEGATES)
        c = c[~c.delegate.isin(set(d[d.known_wallet.notna()].delegate))]
    print("ứng viên theo luật: " + ", ".join(f"{k} {n:,}" for k, n in c.rule.value_counts().items()), flush=True)
    pick = pd.concat([g.sample(min(len(g), per_type), random_state=seed) for _, g in c.groupby("rule")],
                     ignore_index=True)                  # groupby.apply bỏ cột "rule" ở pandas mới
    es = Etherscan("eth")
    cr = load_creations("eth")
    bal = es.balances(pick[pick.rule == "ADDR"].address.tolist()) if (pick.rule == "ADDR").any() else {}
    rows = []
    for i, r in enumerate(pick.itertuples(), 1):
        rec = fetch_txlist(es, r.address, max_records=MAX_RECORDS)
        rows.append({"address": r.address, "rule": r.rule, "n_tx": len(rec["result"]), "truncated": rec["truncated"],
                     **apply_rule(r.rule, r.address, rec["result"], bal.get(r.address, 0), cr), "delegate": r.delegate})
        if i % 50 == 0 or i == len(pick):
            print(f"  {i}/{len(pick)}", flush=True)
    out = pd.DataFrame(rows)
    if only and OUT.exists():                                   # chạy lại một luật: giữ kết quả các luật khác
        out = pd.concat([pd.read_parquet(OUT).query("rule != @only"), out], ignore_index=True)
    out.to_parquet(OUT, index=False)
    print(out.groupby("rule").agg(n=("address", "size"), new_pos=("is_new_positive", "sum"),
                                  any_misuse=("n_misuse_tx", lambda x: int((x > 0).sum())),
                                  truncated=("truncated", "sum")).to_string())


def apply_rule(rule: str, address: str, txs: list[dict], balance_wei: int, cr: dict) -> dict:
    from address_misuse.rules import detect_ca_misuse, detect_eoa_addr
    if rule == "ADDR":
        res = detect_eoa_addr(address, txs, balance_wei=balance_wei, eip7702_delegate_malicious=True)
    else:
        res = detect_ca_misuse(address, txs, "eth", creation=cr.get(address) or None)
    new = [f for f in res.flagged if _ts(txs, f) >= OUT_OF_TIME_TS]
    return {"subtype": res.subtype, "n_misuse_tx": res.n_misuse_tx, "n_misuse_new": len(new),
            "first_misuse_new_ts": min((_ts(txs, f) for f in new), default=None),
            "cost_wei_new": str(sum(f["value_wei"] + f["gas_wei"] for f in new)),
            "value_wei_new": str(sum(f["value_wei"] for f in new)), "is_new_positive": bool(new)}


def cmd_recost():
    """Chạy lại luật trên txlist đã cache cho các dòng đã có (không gọi mạng). ADDR: dòng đã có tx bị gắn cờ thì số
    dư lúc tải đã ≤ dust (điều kiện của luật), nên dùng 0; dòng ADDR không bị gắn cờ giữ nguyên."""
    from address_misuse.reproduce_rules import load_txlist
    out = pd.read_parquet(OUT)
    cr = load_creations("eth")
    rows = []
    for r in out.to_dict("records"):
        rec = load_txlist("eth", r["address"])
        if rec is None or (r["rule"] == "ADDR" and not r["n_misuse_tx"]):
            rows.append(r)
            continue
        rows.append({**r, **apply_rule(r["rule"], r["address"], rec["result"], 0, cr)})
    new = pd.DataFrame(rows)
    changed = int((new.is_new_positive != out.is_new_positive).sum())
    new.to_parquet(OUT, index=False)
    print(f"tính lại {len(new)} dòng; đổi nhãn dương mới: {changed}; loss mới (value + gas) "
          f"{sum(int(x) for x in new.cost_wei_new[new.is_new_positive]) / 1e18:.4f} ETH, chỉ value "
          f"{sum(int(x) for x in new.value_wei_new[new.is_new_positive]) / 1e18:.4f} ETH")


def _ts(txs: list[dict], flagged: dict) -> int:
    """Thời điểm của tx bị gắn cờ (bản ghi gắn cờ chỉ có block, tra lại trong txlist)."""
    for tx in txs:
        if tx["hash"] == flagged["hash"]:
            return int(tx["timeStamp"])
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["state", "created", "delegates", "rules", "recost"])
    ap.add_argument("--per-type", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--only", choices=["NCD", "PCD", "ADDR"])
    ap.add_argument("--no-wallets", action="store_true", help="bỏ EOA dùng delegate của ví hợp lệ N6")
    ap.add_argument("--timeout", type=float, default=120, help="giây symexec mỗi delegate")
    ap.add_argument("--workers", type=int, default=2)
    a = ap.parse_args()
    if a.step == "state":
        cmd_state()
    elif a.step == "created":
        cmd_created()
    elif a.step == "delegates":
        cmd_delegates(a.timeout, a.workers)
    elif a.step == "recost":
        cmd_recost()
    else:
        cmd_rules(a.per_type, a.seed, a.only, a.no_wallets)


if __name__ == "__main__":
    main()
