"""Tái lập rule (D0 pilot / D2): kéo giao dịch thô qua Etherscan, chạy rules.py, so với CSV của tác giả.

python -m address_misuse.reproduce_rules --chain eth --n-ncd 350 --n-pcd 100 --n-key 50   # pilot 500 địa chỉ
python -m address_misuse.reproduce_rules --chain eth --n-addr 50 --n-big 30                 # + EOA ADDR, CA n_tx > 5.000
python -m address_misuse.reproduce_rules --chain eth --summary-only

Giao dịch thô lưu ở data/raw/<chain>/txlist/<addr>.json.gz (append-only, có fetched_at) → chạy lại sẽ tiếp tục.
Kết quả: data/interim/rules_repro_<chain>.parquet

Hai cách so sánh:
- snapshot: chỉ lấy n_tx giao dịch đầu tiên (n_tx = len(txs) lúc tác giả kéo dữ liệu, sắp theo block) và chỉ
  tính contract creation nếu nó nằm trong snapshot → tái hiện trạng thái tác giả đã thấy.
- current: toàn bộ giao dịch tới hiện tại → cho biết số liệu đã thay đổi bao nhiêu kể từ 08/2025.
"""

import argparse
import gzip
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pandas as pd

from address_misuse.config import INTERIM_DIR, RAW_DIR, SEED_DIR
from address_misuse.crosschain import EIP7702_PREFIX, get_code
from address_misuse.etherscan import Etherscan
from address_misuse.rules import detect_ca_misuse, detect_eoa_addr, detect_eoa_key

MAX_N_TX = 5_000          # bỏ địa chỉ quá lớn trong pilot (giữ 98,8% địa chỉ CA trên ETH)
BIG_MAX_N_TX = 50_000     # tầng "big": 5.000 < n_tx ≤ 50.000 (n_tx = 100.000 là trần lúc tác giả kéo dữ liệu)
MAX_RECORDS = 100_000


# ---------------------------------------------------------------- mẫu

def _dedup_max(df: pd.DataFrame) -> pd.DataFrame:
    """Paper lấy giá trị lớn nhất mỗi (chain, address) giữa hai nguồn github/stackexchange."""
    return df.sort_values("cost_native").groupby(["chain", "address"], as_index=False).tail(1)


def sample_targets(chain: str, n_ncd: int, n_pcd: int, n_key: int, seed: int = 0, n_addr: int = 0,
                   n_big: int = 0) -> pd.DataFrame:
    ca = _dedup_max(pd.read_parquet(SEED_DIR / "ca_misuse.parquet").query("chain == @chain"))
    eoa = pd.read_parquet(SEED_DIR / "eoa_misuse.parquet").query("chain == @chain")
    key = _dedup_max(eoa[eoa.subtype == "KEY"])          # tính đúng như pilot 500 cũ
    key = key[key.cost_native > 0]                       # "instances" như Bảng 3
    addr = _dedup_max(eoa[eoa.subtype == "ADDR"])
    small, big = ca.n_tx <= MAX_N_TX, (ca.n_tx > MAX_N_TX) & (ca.n_tx <= BIG_MAX_N_TX)
    parts = []
    # thứ tự và random_state giữ như pilot 500 cũ → cùng địa chỉ, dùng lại cache
    for stratum, pool, n in (("pilot", ca[small & (ca.subtype == "NCD")], n_ncd),
                             ("pilot", ca[small & (ca.subtype == "PCD")], n_pcd),
                             ("pilot", key[key.n_tx <= MAX_N_TX], n_key),
                             ("addr", addr[(addr.cost_native > 0) & (addr.n_tx <= MAX_N_TX)], n_addr),
                             ("big", ca[big], n_big)):
        parts.append(pool.sample(min(n, len(pool)), random_state=seed).assign(stratum=stratum))
    cols = ["chain", "address", "stratum", "subtype", "n_tx", "n_misuse_tx", "cost_wei", "cost_native"]
    return pd.concat(parts)[cols].rename(columns=lambda c: c if c in ("chain", "address", "stratum")
                                         else f"author_{c}").reset_index(drop=True)


# ---------------------------------------------------------------- dữ liệu thô (có cache)

def _raw_path(chain: str, address: str):
    return RAW_DIR / chain / "txlist" / f"{address}.json.gz"


def load_txlist(chain: str, address: str) -> dict | None:
    p = _raw_path(chain, address)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return json.load(f)


def fetch_txlist(es: Etherscan, address: str, max_records: int = MAX_RECORDS) -> dict:
    cached = load_txlist(es.chain, address)
    if cached is not None:
        return cached
    txs, truncated = es.txlist(address, max_records=max_records)
    rec = {"address": address, "chain": es.chain, "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "truncated": truncated, "result": txs}
    p = _raw_path(es.chain, address)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(rec, f)
    tmp.replace(p)
    return rec


def fetch_creations(es: Etherscan, addresses: list[str]) -> dict[str, dict]:
    """getcontractcreation, cache ở data/raw/<chain>/creation.jsonl (một dòng/địa chỉ; {} = không phải contract)."""
    path = RAW_DIR / es.chain / "creation.jsonl"
    cache = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            cache[r["address"]] = r["creation"]
    todo = [a for a in addresses if a not in cache]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for i in range(0, len(todo), 5):
            batch = todo[i:i + 5]
            got = es.contract_creation(batch)
            for a in batch:
                cache[a] = got.get(a, {})
                f.write(json.dumps({"address": a, "creation": cache[a]}) + "\n")
    return {a: cache[a] for a in addresses}


def is_eip7702_now(chain: str, address: str) -> bool | None:
    try:
        return get_code(chain, address, timeout=15).startswith(EIP7702_PREFIX)
    except Exception:
        return None


# ---------------------------------------------------------------- chạy rule

def run_rules(t, txs: list[dict], creation: dict, is7702: bool, balance_wei: int | None = None) -> dict:
    if t.author_subtype == "KEY":
        r = detect_eoa_key(t.address, txs)
    elif t.author_subtype == "ADDR":
        # Điều kiện "delegate độc" của tác giả: mọi EOA ADDR đều nằm trong eip7702_delegations của tác giả
        # (kiểm tra 3.863/3.863 trên ETH), nên coi là thoả. Số dư: snapshot dùng số dư tác giả ghi lại.
        r = detect_eoa_addr(t.address, txs, balance_wei=balance_wei or 0, eip7702_delegate_malicious=True)
    else:
        r = detect_ca_misuse(t.address, txs, t.chain, creation=creation or None, is_eip7702=bool(is7702))
    return {"subtype": r.subtype, "n_tx": r.n_tx, "n_misuse_tx": r.n_misuse_tx, "cost_wei": str(r.cost_wei),
            "cost_native": r.cost_wei / 1e18}


def author_balances(chain: str, addresses) -> dict[str, int]:
    ca = pd.read_parquet(SEED_DIR / "candidate_addresses.parquet", columns=["chain", "address", "balance_wei"],
                         filters=[("chain", "==", chain)])
    ca = ca[ca.address.isin(set(addresses))]
    return {a: int(b) for a, b in zip(ca.address, ca.balance_wei) if b is not None}


def evaluate(targets: pd.DataFrame, chain: str, current_balances: dict[str, int] | None = None) -> pd.DataFrame:
    creations = {r["address"]: r["creation"] for r in map(json.loads, (RAW_DIR / chain / "creation.jsonl")
                                                          .read_text(encoding="utf-8").splitlines())}
    snap_bal = author_balances(chain, targets.address[targets.author_subtype == "ADDR"])
    current_balances = current_balances or {}
    rows = []
    for t in targets.itertuples():
        raw = load_txlist(chain, t.address)
        if raw is None:
            continue
        txs = raw["result"]
        creation = creations.get(t.address) or {}
        row = {**t._asdict(), "fetched_n_tx": len(txs), "truncated": raw["truncated"]}
        row.pop("Index")
        snap = txs[:t.author_n_tx]
        snap_last = int(snap[-1]["blockNumber"]) if snap else 0
        snap_creation = creation if creation and int(creation["blockNumber"]) <= snap_last else {}
        for mode, tx_set, cr, bal in (("snap", snap, snap_creation, snap_bal.get(t.address)),
                                      ("cur", txs, creation, current_balances.get(t.address))):
            for k, v in run_rules(t, tx_set, cr, getattr(t, "is7702", False), bal).items():
                row[f"{mode}_{k}"] = v
        rows.append(row)
    df = pd.DataFrame(rows)
    for mode in ("snap", "cur"):
        a, m = df.author_cost_wei.map(int), df[f"{mode}_cost_wei"].map(int)
        df[f"{mode}_exact"] = (a == m) & (df.author_n_misuse_tx == df[f"{mode}_n_misuse_tx"])
        df[f"{mode}_rel_diff"] = (m - a) / a.where(a > 0, 1)
    return df


def summarize(df: pd.DataFrame):
    print(f"\n{len(df)} địa chỉ đã đánh giá; truncated: {int(df.truncated.sum())}; "
          f"n_tx lúc kéo < n_tx tác giả: {int((df.fetched_n_tx < df.author_n_tx).sum())}")
    for mode, label in (("snap", "SNAPSHOT (n_tx đầu tiên)"), ("cur", "HIỆN TẠI (toàn bộ tx)")):
        print(f"\n== {label}")
        df[f"{mode}_subtype_ok"] = df.author_subtype == df[f"{mode}_subtype"]
        g = df.groupby(["stratum", "author_subtype"]) if "stratum" in df else df.groupby("author_subtype")
        out = pd.DataFrame({
            "n": g.size(),
            "khớp chính xác": g[f"{mode}_exact"].mean().map("{:.1%}".format),
            "|lệch| ≤ 1%": g[f"{mode}_rel_diff"].apply(lambda s: (s.abs() <= 0.01).mean()).map("{:.1%}".format),
            "đúng subtype": g[f"{mode}_subtype_ok"].mean().map("{:.1%}".format),
            "loss tác giả": g.author_cost_native.sum().map("{:,.3f}".format),
            "loss mình": g[f"{mode}_cost_native"].sum().map("{:,.3f}".format),
        })
        out["lệch tổng"] = ((g[f"{mode}_cost_native"].sum() - g.author_cost_native.sum())
                            / g.author_cost_native.sum()).map("{:+.2%}".format)
        print(out.to_string())
        tot_a, tot_m = df.author_cost_native.sum(), df[f"{mode}_cost_native"].sum()
        print(f"Tổng loss: tác giả {tot_a:,.3f} · mình {tot_m:,.3f} · lệch {(tot_m - tot_a) / tot_a:+.2%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="eth")
    ap.add_argument("--n-ncd", type=int, default=350)
    ap.add_argument("--n-pcd", type=int, default=100)
    ap.add_argument("--n-key", type=int, default=50)
    ap.add_argument("--n-addr", type=int, default=0, help="EOA ADDR (cần số dư hiện tại qua balancemulti)")
    ap.add_argument("--n-big", type=int, default=0, help=f"CA có {MAX_N_TX:,} < n_tx ≤ {BIG_MAX_N_TX:,}")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--summary-only", action="store_true")
    a = ap.parse_args()
    out = INTERIM_DIR / f"rules_repro_{a.chain}.parquet"

    if a.summary_only:
        summarize(pd.read_parquet(out))
        return

    targets = sample_targets(a.chain, a.n_ncd, a.n_pcd, a.n_key, a.seed, a.n_addr, a.n_big)
    print(f"{len(targets)} địa chỉ: {targets.author_subtype.value_counts().to_dict()}", flush=True)
    es = Etherscan(a.chain)

    t0, done, errors = time.time(), 0, []

    def job(addr):
        try:
            fetch_txlist(es, addr)
            return None
        except Exception as e:
            return addr, repr(e)[:200]

    with ThreadPoolExecutor(a.workers) as ex:
        for res in ex.map(job, targets.address):
            done += 1
            if res:
                errors.append(res)
            if done % 50 == 0:
                print(f"  txlist {done}/{len(targets)} ({time.time() - t0:.0f}s, lỗi {len(errors)})", flush=True)
    for addr, err in errors[:10]:
        print("  LỖI", addr, err)

    print("getcontractcreation ...", flush=True)
    fetch_creations(es, list(targets.address))
    print("eth_getCode (cờ EIP-7702) ...", flush=True)
    with ThreadPoolExecutor(a.workers) as ex:
        targets["is7702"] = list(ex.map(lambda x: is_eip7702_now(a.chain, x), targets.address))

    addr = list(targets.address[targets.author_subtype == "ADDR"])
    print(f"số dư hiện tại {len(addr)} EOA ADDR ...", flush=True)
    df = evaluate(targets, a.chain, current_balances=es.balances(addr) if addr else {})
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"Ghi {out} ({time.time() - t0:.0f}s)")
    summarize(df)
    if errors:
        print(f"\n{len(errors)} địa chỉ lỗi khi kéo — chạy lại lệnh để tiếp tục (dùng cache).")


if __name__ == "__main__":
    main()
