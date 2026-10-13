"""Pilot cross-chain: các địa chỉ NCD (CA Misuse) thiệt hại lớn nhất có phải contract ở chain khác không?

python -m address_misuse.crosschain_pilot [--top 100]
Kết quả: data/interim/crosschain_pilot.parquet

Lưu ý: kiểm tra theo trạng thái HIỆN TẠI (block mới nhất). Contract trên chain khác có thể được deploy
sau thời điểm misuse → đây là ước lượng ban đầu; gán nhãn chính thức cần block deploy (Etherscan).
"""

import argparse
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

from address_misuse.config import INTERIM_DIR, NETWORKS, SEED_DIR
from address_misuse.crosschain import probe


def _probe_with_retry(address: str) -> dict:
    res = probe(address, timeout=10)
    retry = [n for n, p in res.items() if p.error]
    if retry:
        res.update(probe(address, retry, timeout=15))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=100, help="số địa chỉ NCD lấy theo thiệt hại, mỗi chain")
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()

    ca = pd.read_parquet(SEED_DIR / "ca_misuse.parquet")
    ncd = (ca[ca.subtype == "NCD"].groupby(["chain", "address"], as_index=False)
           .agg(cost_native=("cost_native", "max"), n_misuse_tx=("n_misuse_tx", "max")))
    targets = ncd.sort_values("cost_native", ascending=False).groupby("chain").head(a.top).reset_index(drop=True)
    print(f"Probing {len(targets)} NCD addresses on {len(NETWORKS)} networks ...", flush=True)

    with ThreadPoolExecutor(a.workers) as ex:
        results = list(ex.map(_probe_with_retry, targets.address))

    rows = []
    for t, res in zip(targets.itertuples(), results):
        row = {"chain": t.chain, "address": t.address, "cost_native": t.cost_native, "n_misuse_tx": t.n_misuse_tx}
        for n, p in res.items():
            row[f"{n}_state"] = "error" if p.error else ("7702" if p.is_eip7702 else ("code" if p.has_code else "none"))
            row[f"{n}_size"] = p.code_size
        others = [n for n, p in res.items() if n != t.chain and p.has_code]
        row["other_chains_with_code"] = ",".join(others)
        row["same_chain_now"] = row[f"{t.chain}_state"]
        rows.append(row)
    df = pd.DataFrame(rows)
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(INTERIM_DIR / "crosschain_pilot.parquet", index=False)

    df["xc"] = df.other_chains_with_code != ""
    print("\nErrors per network:", {n: int((df[f'{n}_state'] == 'error').sum()) for n in NETWORKS})
    for chain, g in df.groupby("chain"):
        print(f"\n== {chain}: {len(g)} NCD addresses (top theo thiệt hại), tổng {g.cost_native.sum():,.1f} native")
        print(f"  là contract ở >=1 chain khác : {g.xc.sum():3d} ({g.xc.mean():.0%}), "
              f"chiếm {g[g.xc].cost_native.sum() / g.cost_native.sum():.0%} thiệt hại")
        print(f"  trạng thái trên chính chain đó hiện nay: {g.same_chain_now.value_counts().to_dict()}")
        counts = pd.Series([n for s in g.other_chains_with_code for n in s.split(",") if n]).value_counts()
        print(f"  chain có contract: {counts.to_dict()}")
        print(g[g.xc].head(5)[["address", "cost_native", "n_misuse_tx", "other_chains_with_code"]].to_string(index=False))


if __name__ == "__main__":
    main()
