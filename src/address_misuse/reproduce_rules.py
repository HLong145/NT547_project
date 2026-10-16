"""Tái lập rule (D0 pilot / D2): kéo giao dịch thô qua Etherscan, chạy rules.py, so với CSV của tác giả.

python -m address_misuse.reproduce_rules --chain eth --n-ncd 350 --n-pcd 100 --n-key 50   # pilot 500 địa chỉ
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
from address_misuse.rules import detect_ca_misuse, detect_eoa_key

MAX_N_TX = 5_000          # bỏ địa chỉ quá lớn trong pilot (giữ 98,8% địa chỉ CA trên ETH)


# ---------------------------------------------------------------- mẫu

def _dedup_max(df: pd.DataFrame) -> pd.DataFrame:
    """Paper lấy giá trị lớn nhất mỗi (chain, address) giữa hai nguồn github/stackexchange."""
    return df.sort_values("cost_native").groupby(["chain", "address"], as_index=False).tail(1)


def sample_targets(chain: str, n_ncd: int, n_pcd: int, n_key: int, seed: int = 0) -> pd.DataFrame:
    ca = _dedup_max(pd.read_parquet(SEED_DIR / "ca_misuse.parquet").query("chain == @chain"))
    key = _dedup_max(pd.read_parquet(SEED_DIR / "eoa_misuse.parquet").query("chain == @chain and subtype == 'KEY'"))
    key = key[key.cost_native > 0]                       # "instances" như Bảng 3
    parts = []
    for df, sub, n in ((ca, "NCD", n_ncd), (ca, "PCD", n_pcd), (key, "KEY", n_key)):
        pool = df[(df.subtype == sub) & (df.n_tx <= MAX_N_TX)]
        parts.append(pool.sample(min(n, len(pool)), random_state=seed))
    cols = ["chain", "address", "subtype", "n_tx", "n_misuse_tx", "cost_wei", "cost_native"]
    return pd.concat(parts)[cols].rename(columns=lambda c: c if c in ("chain", "address") else f"author_{c}") \
        .reset_index(drop=True)


# ---------------------------------------------------------------- dữ liệu thô (có cache)

def _raw_path(chain: str, address: str):
    return RAW_DIR / chain / "txlist" / f"{address}.json.gz"


def load_txlist(chain: str, address: str) -> dict | None:
    p = _raw_path(chain, address)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return json.load(f)


def fetch_txlist(es: Etherscan, address: str, max_records: int = 50_000) -> dict:
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

def run_rules(t, txs: list[dict], creation: dict, is7702: bool) -> dict:
    if t.author_subtype == "KEY":
        r = detect_eoa_key(t.address, txs)
    else:
        r = detect_ca_misuse(t.address, txs, t.chain, creation=creation or None, is_eip7702=bool(is7702))
    return {"subtype": r.subtype, "n_tx": r.n_tx, "n_misuse_tx": r.n_misuse_tx, "cost_wei": str(r.cost_wei),
            "cost_native": r.cost_wei / 1e18}


def evaluate(targets: pd.DataFrame, chain: str) -> pd.DataFrame:
    creations = {r["address"]: r["creation"] for r in map(json.loads, (RAW_DIR / chain / "creation.jsonl")
                                                          .read_text(encoding="utf-8").splitlines())}
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
        for mode, tx_set, cr in (("snap", snap, snap_creation), ("cur", txs, creation)):
            for k, v in run_rules(t, tx_set, cr, getattr(t, "is7702", False)).items():
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
        g = df.groupby("author_subtype")
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
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--summary-only", action="store_true")
    a = ap.parse_args()
    out = INTERIM_DIR / f"rules_repro_{a.chain}.parquet"

    if a.summary_only:
        summarize(pd.read_parquet(out))
        return

    targets = sample_targets(a.chain, a.n_ncd, a.n_pcd, a.n_key, a.seed)
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

    df = evaluate(targets, a.chain)
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"Ghi {out} ({time.time() - t0:.0f}s)")
    summarize(df)
    if errors:
        print(f"\n{len(errors)} địa chỉ lỗi khi kéo — chạy lại lệnh để tiếp tục (dùng cache).")


if __name__ == "__main__":
    main()
