"""Loss KEY của tác giả có tính cả phân bổ genesis không? (FINDINGS_LOG 2026-10-23)

python -X utf8 -m address_misuse.key_genesis → data/interim/key_genesis.parquet

Luật KEY của tác giả (`txs_analyzer.analyze_EOAMisuse_for_KEY_txs`) cộng mọi tx vào có `isError == 0`, mà Etherscan
`txlist` trả phân bổ genesis như một tx từ `GENESIS` ở block 0. Phần này không phải tiền nạp vào ví lộ key.
Số dư tại block 0 (RPC archive NodeReal) = đúng phần genesis; không cần Etherscan.
"""

import pandas as pd

from address_misuse.config import INTERIM_DIR, SEED_DIR
from address_misuse.negatives import _nodereal_blocks

OUT = INTERIM_DIR / "key_genesis.parquet"


def main():
    e = pd.read_parquet(SEED_DIR / "eoa_misuse.parquet").query("chain == 'eth' and subtype == 'KEY'")
    e = e.assign(address=e.address.str.lower()).sort_values("cost_wei", ascending=False).drop_duplicates("address")
    done = pd.read_parquet(OUT) if OUT.exists() else pd.DataFrame(columns=["address", "genesis_wei"])
    have = set(done.address)
    todo = [a for a in e.address if a not in have]
    print(f"KEY ETH: {len(e):,} ví, cần tra {len(todo):,}", flush=True)
    rows = done.to_dict("records")
    for i, a in enumerate(todo, 1):
        bal = _nodereal_blocks("eth", [("eth_getBalance", [a, "0x0"])])[0]
        rows.append({"address": a, "genesis_wei": str(int(bal, 16))})
        if i % 500 == 0 or i == len(todo):
            pd.DataFrame(rows).to_parquet(OUT, index=False)
            print(f"  {i:,}/{len(todo):,}", flush=True)
    g = pd.DataFrame(rows).merge(e[["address", "value_wei", "cost_wei"]], on="address")
    gen = g.genesis_wei.map(int)
    val = g.value_wei.map(lambda x: int(x) if pd.notna(x) else 0)
    cost = g.cost_wei.map(lambda x: int(x) if pd.notna(x) else 0)
    hit = gen > 0
    print(f"ví KEY có phân bổ genesis: {int(hit.sum())}/{len(g)}")
    print(f"genesis trong loss tác giả: {sum(min(a, b) for a, b in zip(gen[hit], val[hit])) / 1e18:,.4f} ETH "
          f"/ tổng value KEY ETH {sum(val) / 1e18:,.4f} ETH, tổng cost {sum(cost) / 1e18:,.4f} ETH")
    print(g[hit].assign(genesis_eth=gen[hit] / 1e18, value_eth=val[hit] / 1e18)
          [["address", "genesis_eth", "value_eth"]].sort_values("genesis_eth", ascending=False).head(15).to_string(index=False))


if __name__ == "__main__":
    main()
