"""Đo tốc độ bị rút của các ví nằm trong danh sách khoá lộ (KEY) trên ETH, từ giao dịch BigQuery đã tải sẵn.

python -m address_misuse.key_sweep

Câu hỏi: với mỗi lần nạp coin vào một ví lộ khoá, bao lâu sau thì có tx rút gần hết khoản đó đi?
Luật KEY của tác giả (`rules.detect_eoa_key`) chỉ cần "ví thuộc danh sách và có tx nạp thành công", không kiểm tra việc tiền bị rút,
nên phép đo này kiểm chứng giả định "mọi khoản nạp đều mất" và không vòng lặp với luật đó.

Giới hạn (ghi vào paper): chỉ ETH coin gốc; BigQuery thiếu internal tx và token; danh sách chỉ gồm ví đã có tx, không có ngày lộ,
nên tiền chủ ví tự nạp trước khi lộ bị tính vào (xem cờ `pre_mark`); số liệu là có điều kiện trên "khoá lộ, có hoạt động, có nạp value".
"""

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from address_misuse.config import INTERIM_DIR, RAW_DIR, SEED_DIR

SRC = RAW_DIR / "eth" / "bq_txs.parquet"
OUT = INTERIM_DIR / "key_sweep_eth.parquet"
SUMMARY = INTERIM_DIR / "key_sweep_eth_summary.csv"
DRAIN_RATIO = 0.95
SCAN_SECONDS = 24 * 3600                       # chỉ tìm tx rút trong 24 giờ sau khoản nạp
BINS = [("<=2 block", None, 2), ("<=10 phút", 600, None), ("<=1 giờ", 3600, None), ("<=24 giờ", SCAN_SECONDS, None)]
COLLECTOR_MIN = 3                              # ví nhận là "collector" nếu nhận khoản rút từ >= 3 ví lộ khác nhau
# Địa chỉ mặc định công khai của Hardhat (account #0-#9); chỉ để tách nhóm khoá test, không dùng gì khác.
HARDHAT = {a.lower() for a in (
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    "0x976EA74026E726554dB657fA54763abd0C3a0aa9", "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
    "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f", "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")}


def key_addresses() -> set[str]:
    pk = pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet", columns=["chain", "address"])
    return set(pk[pk.chain == "eth"].address.str.lower())


def load_txs(keys: set[str]) -> pd.DataFrame:
    cols = ["block_number", "transaction_index", "block_ts", "from_address", "to_address", "value",
            "receipt_gas_used", "gas_price", "receipt_status"]
    t = pq.read_table(SRC, columns=cols)
    df = t.drop_columns(["value"]).to_pandas()
    df["value_wei"] = t.column("value").cast("float64").to_numpy()
    df["to_address"] = df.to_address.fillna("")
    df = df[df.to_address.isin(keys) | df.from_address.isin(keys)].copy()
    df["fee_wei"] = df.receipt_gas_used.astype("float64") * df.gas_price.astype("float64")
    df["order"] = df.block_number.astype("int64") * 100_000 + df.transaction_index.astype("int64")
    return df


def analyze(df: pd.DataFrame, keys: set[str]) -> pd.DataFrame:
    """Một dòng mỗi khoản nạp (tx thành công, value > 0, từ ví khác): thời gian tới tx rút đầu tiên mang >= 95% khoản đó."""
    rows = []
    for addr in sorted(keys):
        a_in = df[(df.to_address == addr) & (df.from_address != addr) & (df.receipt_status == 1) & (df.value_wei > 0)]
        if a_in.empty:
            continue
        a_out = df[(df.from_address == addr) & (df.to_address != addr) & (df.receipt_status == 1)].sort_values("order")
        o_order, o_ts, o_blk = a_out.order.to_numpy(), a_out.block_ts.to_numpy(), a_out.block_number.to_numpy()
        o_tot = (a_out.value_wei + a_out.fee_wei).to_numpy()
        o_to, o_val = a_out.to_address.to_numpy(), a_out.value_wei.to_numpy()
        for r in a_in.itertuples():
            j = np.searchsorted(o_order, r.order, side="right")
            hit = None
            for k in range(j, len(o_order)):
                if o_ts[k] - r.block_ts > SCAN_SECONDS:
                    break
                if o_val[k] > 0 and o_tot[k] >= DRAIN_RATIO * r.value_wei:
                    hit = k
                    break
            rows.append({"addr": addr, "in_block": int(r.block_number), "in_ts": int(r.block_ts), "in_wei": r.value_wei,
                         "sender": r.from_address,
                         "dt_sec": None if hit is None else int(o_ts[hit] - r.block_ts),
                         "dt_block": None if hit is None else int(o_blk[hit] - r.block_number),
                         "recipient": None if hit is None else o_to[hit]})
    d = pd.DataFrame(rows)
    d["drained"] = d.dt_sec.notna()
    return d


def classify(d: pd.DataFrame, keys: set[str]) -> pd.DataFrame:
    """Gắn loại người nhận, cờ `pre_mark` (khoản nạp trước lần bị rút nhanh đầu tiên của ví) và nhóm khoá test."""
    d = d.copy()
    fast = d[d.drained & (d.dt_sec <= 3600)]
    coll = fast[~fast.recipient.isin(keys)].groupby("recipient").addr.nunique()
    collectors = set(coll[coll >= COLLECTOR_MIN].index)

    def kind(r):
        if not r.drained:
            return "không thấy rút"
        if r.recipient == r.sender:
            return "trả về người gửi"
        if r.recipient in keys:
            return "sang ví lộ khác (nội danh sách)"
        return "collector" if r.recipient in collectors else "ví khác"
    d["recipient_kind"] = [kind(r) for r in d.itertuples()]
    first = fast.groupby("addr").in_ts.min()
    d["pre_mark"] = [(a in first.index) and (t < first[a]) for a, t in zip(d.addr, d.in_ts)]
    d["hardhat"] = d.addr.isin(HARDHAT)
    return d


def bucket(dt_sec, dt_block) -> str:
    if pd.isna(dt_sec):
        return "không thấy rút trong 24 giờ"
    if dt_block <= 2:
        return "<=2 block"
    for name, secs, _ in BINS[1:]:
        if dt_sec <= secs:
            return name
    return "không thấy rút trong 24 giờ"


def summarize(d: pd.DataFrame) -> pd.DataFrame:
    d = d.copy()
    d["bucket"] = [bucket(s, b) for s, b in zip(d.dt_sec, d.dt_block)]
    d["eth"] = d.in_wei / 1e18
    order = ["<=2 block", "<=10 phút", "<=1 giờ", "<=24 giờ", "không thấy rút trong 24 giờ"]
    out = []
    for name, g in (("tất cả", d), ("bỏ khoá test mặc định", d[~d.hardhat]), ("bỏ nạp trước mốc", d[~d.pre_mark]),
                    ("người nhận ngoài danh sách", d[d.recipient_kind.isin(["collector", "ví khác", "không thấy rút"])])):
        cnt = g.bucket.value_counts().reindex(order, fill_value=0)
        val = g.groupby("bucket").eth.sum().reindex(order, fill_value=0.0)
        row = {"tập": name, "số khoản nạp": len(g), "số ví": g.addr.nunique(), "tổng ETH nạp": round(g.eth.sum(), 3)}
        cum = 0
        for b in order:
            cum += cnt[b]
            row[f"tx {b}"] = int(cnt[b])
            row[f"ETH {b}"] = round(float(val[b]), 3)
        row["% tx rút <=2 block"] = round(100 * cnt["<=2 block"] / max(len(g), 1), 2)
        row["% tx rút <=10 phút"] = round(100 * cnt[["<=2 block", "<=10 phút"]].sum() / max(len(g), 1), 2)
        row["% ETH rút <=10 phút"] = round(100 * val[["<=2 block", "<=10 phút"]].sum() / max(g.eth.sum(), 1e-12), 2)
        out.append(row)
    return pd.DataFrame(out)


def per_address(d: pd.DataFrame) -> dict:
    d = d.assign(fast=d.drained & (d.dt_sec <= 600))
    g = d.groupby("addr").agg(n=("fast", "size"), fast=("fast", "mean"), eth=("in_wei", "sum"))
    top10 = g.eth.sort_values(ascending=False).head(10).sum() / g.eth.sum()
    return {"ví có khoản nạp": len(g), "ví có >=1 khoản bị rút <=10 phút": int((g.fast > 0).sum()),
            "ví có >=50% khoản bị rút <=10 phút": int((g.fast >= 0.5).sum()),
            "trung vị % khoản bị rút <=10 phút theo ví": round(100 * float(g.fast.median()), 2),
            "tỉ trọng ETH nạp của top-10 ví": round(100 * float(top10), 2)}


def main():
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    keys = key_addresses()
    df = load_txs(keys)
    print(f"{len(keys):,} ví KEY eth; {len(df):,} tx liên quan; block_ts đến {pd.to_datetime(df.block_ts.max(), unit='s')}", flush=True)
    d = classify(analyze(df, keys), keys)
    d.to_parquet(OUT, index=False)
    s = summarize(d)
    s.to_csv(SUMMARY, index=False)
    print(s.T.to_string())
    print(per_address(d))
    print(d.groupby("recipient_kind").agg(tx=("addr", "size"), eth=("in_wei", lambda x: round(x.sum() / 1e18, 3))).to_string())
    print(f"pre_mark: {int(d.pre_mark.sum())} khoản; hardhat: {int(d.hardhat.sum())} khoản ({d[d.hardhat].addr.nunique()} ví)")
    print(f"→ {OUT}, {SUMMARY}")


if __name__ == "__main__":
    main()
