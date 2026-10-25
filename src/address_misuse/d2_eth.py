"""D2 (ETH): chạy lại rule của tác giả trên giao dịch thô BigQuery rồi so với CSV của họ.

python -m address_misuse.d2_eth

Dữ liệu `bq_txs.parquet` không có `input`, nên:
- KEY: tính chính xác (không cần input).
- ADDR: tính chính xác, vì tx chuyển tiền thuần có gasUsed đúng 21.000 (input rỗng), còn tx có input thì > 21.000.
- NCD: chỉ ra **cận trên** (success, to = addr, gasUsed trong (21.000, 30.000]); bỏ các bộ lọc functionName, văn bản đọc được,
  transfer-to-self, selector rác.
- PCD: chỉ kiểm tra số tx (cần creation block và input).
Chế độ snapshot: chỉ giữ n_tx giao dịch đầu của mỗi địa chỉ (như lúc tác giả thu thập).
`value` của BigQuery là wei dạng NUMERIC; đọc sang float64 nên sai số tương đối ~1e-16.
"""

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from address_misuse.config import INTERIM_DIR, RAW_DIR, SEED_DIR
from address_misuse.rules import find_sweep_pairs

SRC = RAW_DIR / "eth" / "bq_txs.parquet"
OUT = INTERIM_DIR / "d2_eth_compare.parquet"
WEI = 10 ** 18
VALUES = None          # cột `value` gốc (decimal) để lấy wei chính xác khi cần


def exact_wei(rows) -> list[int]:
    """Wei nguyên chính xác (float64 làm tròn sai tx rút đúng bằng tx nạp, nên rule ADDR cần số nguyên)."""
    return [int(d) for d in VALUES.take(pa.array(np.asarray(rows))).to_pylist()]


def load() -> pd.DataFrame:
    t = pq.read_table(SRC)
    global VALUES
    VALUES = t.column("value")
    v = t.column("value").cast(pa.float64()).to_numpy()   # wei (cột NUMERIC của BigQuery tính bằng wei), độ chính xác float ~1e-16
    t = t.drop_columns(["value", "receipt_contract_address", "transaction_type", "nonce", "gas"])
    df = t.to_pandas()
    df["value_wei"] = v
    df["to_address"] = df.to_address.fillna("")
    df["row"] = np.arange(len(df))
    df["fee_wei"] = df.receipt_gas_used.astype("float64") * df.gas_price.astype("float64")   # int64 tràn khi gas_price rác
    return df


def per_address(df: pd.DataFrame, addrs: pd.Series, n_tx: pd.Series) -> pd.DataFrame:
    """Các tx của từng địa chỉ (đi hoặc đến), sắp theo (block, index), chỉ giữ n_tx đầu. Cột `addr` là địa chỉ đang xét."""
    s = set(addrs)
    sel = df[df.to_address.isin(s) | df.from_address.isin(s)]
    a = sel[sel.to_address.isin(s)].assign(addr=lambda x: x.to_address)
    b = sel[sel.from_address.isin(s)].assign(addr=lambda x: x.from_address)
    ev = pd.concat([a, b]).drop_duplicates(["addr", "block_number", "transaction_index"])
    ev = ev.sort_values(["addr", "block_number", "transaction_index"], kind="stable")
    ev["rank"] = ev.groupby("addr").cumcount()
    ev["n_seed"] = ev.addr.map(n_tx)
    return ev, ev[ev["rank"] < ev["n_seed"]]


def summarize(name, seed: pd.DataFrame, calc: pd.DataFrame, bq_n: pd.Series) -> dict:
    m = seed.merge(calc, on="address", how="left").fillna({"calc_n": 0, "calc_cost": 0.0})
    m["bq_n_tx"] = m.address.map(bq_n).fillna(0).astype(int)
    tot_s, tot_c = m.cost_native.sum(), m.calc_cost.sum()
    exact = (np.abs(m.calc_cost - m.cost_native) <= 1e-6 + 1e-6 * m.cost_native).sum()
    return {"set": name, "addresses": len(m), "seed_misuse_tx": int(m.n_misuse_tx.sum()), "calc_misuse_tx": int(m.calc_n.sum()),
            "seed_cost": round(tot_s, 3), "calc_cost": round(tot_c, 3), "gap_pct": round(100 * (tot_c - tot_s) / tot_s, 3) if tot_s else 0,
            "addr_cost_match": int(exact), "addr_n_tx_match": int((m.bq_n_tx.clip(upper=m.n_tx) == m.n_tx).sum()),
            "n_tx_seed": int(m.n_tx.sum()), "n_tx_bq": int(m.bq_n_tx.sum())}, m


def main():
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df = load()
    print(f"{len(df):,} tx; block_ts đến {pd.to_datetime(df.block_ts.max(), unit='s')}", flush=True)
    ca = pd.read_parquet(SEED_DIR / "ca_misuse.parquet")
    eoa = pd.read_parquet(SEED_DIR / "eoa_misuse.parquet")
    ca, eoa = [x[x.chain == "eth"].copy() for x in (ca, eoa)]
    for x in (ca, eoa):
        x["address"] = x.address.str.lower()
    out, rows = [], []

    def run(name, seed, mask_fn, snap=True):
        seed = seed.drop_duplicates("address")
        full, ev = per_address(df, seed.address, seed.set_index("address").n_tx)
        bq_n = full.groupby("addr").size()
        hit = ev[mask_fn(ev)]
        g = hit.groupby("addr").agg(calc_n=("addr", "size"), v=("value_wei", "sum"), f=("fee_wei", "sum"))
        g["calc_cost"] = (g.v + g.f.astype(float)) / WEI
        s, m = summarize(name, seed, g[["calc_n", "calc_cost"]].rename_axis("address").reset_index(), bq_n)
        m["set"] = name
        rows.append(s), out.append(m)
        print(s, flush=True)
        return ev

    run("KEY", eoa[eoa.subtype == "KEY"],
        lambda e: (e.receipt_status == 1) & (e.to_address == e.addr) & (e.from_address != e.addr))
    run("NCD_upper", ca[ca.subtype == "NCD"],
        lambda e: (e.receipt_status == 1) & (e.to_address == e.addr) & (e.from_address != e.addr)
        & (e.receipt_gas_used > 21_000) & (e.receipt_gas_used <= 30_000))
    run("PCD_ntx_only", ca[ca.subtype == "PCD"], lambda e: e.receipt_status < 0)

    # ADDR: dùng find_sweep_pairs của rules.py
    adr = eoa[eoa.subtype == "ADDR"].drop_duplicates("address")
    _, ev = per_address(df, adr.address, adr.set_index("address").n_tx)
    full, _ = per_address(df, adr.address, adr.set_index("address").n_tx)
    bq_n = full.groupby("addr").size()
    res = []
    for addr, g in ev.groupby("addr", sort=False):
        txs = [{"blockNumber": str(b), "hash": "", "from": f, "to": t, "value": str(v), "gasPrice": str(gp),
                "gasUsed": str(gu), "isError": "0" if st == 1 else "1", "input": "0x" if gu == 21_000 else "0x01"}
               for b, f, t, v, gp, gu, st in zip(g.block_number, g.from_address, g.to_address, exact_wei(g.row),
                                                 g.gas_price, g.receipt_gas_used, g.receipt_status)]
        pairs = find_sweep_pairs(addr, txs)
        res.append((addr, len(pairs), sum(int(a["value"]) + int(a["gasUsed"]) * int(a["gasPrice"]) for a, _ in pairs) / WEI))
    g = pd.DataFrame(res, columns=["address", "calc_n", "calc_cost"])
    s, m = summarize("ADDR", adr, g, bq_n)
    m["set"] = "ADDR"
    rows.append(s), out.append(m)
    print(s)

    pd.concat(out).to_parquet(OUT, index=False)
    pd.DataFrame(rows).to_csv(INTERIM_DIR / "d2_eth_summary.csv", index=False)
    print(f"→ {OUT}")


if __name__ == "__main__":
    main()
