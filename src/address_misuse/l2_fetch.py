"""D3b: đo misuse trên L2 (Arbitrum One, Optimism, Polygon PoS) qua BigQuery công khai `goog_blockchain_<chain>_us`.

python -X utf8 -m address_misuse.l2_fetch dry-run                          # chỉ ước lượng GB, không tốn quota
python -X utf8 -m address_misuse.l2_fetch fetch --chain arb --max-gb 200   # chạy thật (cần duyệt), mặc định `inbound`

Tập địa chỉ giống pipeline tác giả: ứng viên GitHub/StackExchange (`seed/candidate_addresses`, cả ETH lẫn BSC) +
địa chỉ suy ra từ key lộ (`seed/candidate_pk_addresses`). Bước 1 chỉ lấy một dòng thống kê mỗi địa chỉ trên mỗi L2
(trả từng tx thì quá lớn); địa chỉ đáng chú ý lấy txlist chi tiết sau rồi chạy `rules.py` (PLAN_V2 §D3b).

Biến thể truy vấn (giá khác nhau vì BigQuery tính theo cột được đọc):
- `lite`:    số tx đến / đi, tổng value, thời điểm đầu/cuối, số người gửi;
- `call`:    + số tx đến có calldata (đọc cột `input`, đắt) — cần cho NCD/PCD;
- `receipt`: + số tx đến thành công (JOIN `receipts`);
- `inbound`: chỉ tx đến, đọc bảng `receipts` (to, status, gas_used, thời điểm) — rẻ nhất mà vẫn bỏ được tx lỗi;
  gas_used > 21.000 là dấu hiệu gọi hàm trên OP/Polygon (Arbitrum cộng phí L1 vào gas_used nên không dùng được).
  Đủ cho bước 1: địa chỉ nào có tx đến trên L2; chi tiết (value, input, tx đi của ví key lộ) lấy sau theo địa chỉ.
Kết quả: data/raw/<chain>/bq_l2_activity_<variant>.parquet; nhật ký job: data/raw/eth/bq_jobs.jsonl.
"""

import argparse

import pandas as pd

from address_misuse.bq_fetch import GB, _client, _log, _upload
from address_misuse.config import RAW_DIR, SEED_DIR

L2 = {"arb": "goog_blockchain_arbitrum_one_us", "op": "goog_blockchain_optimism_mainnet_us",
      "polygon": "goog_blockchain_polygon_mainnet_us"}
VARIANTS = ("inbound", "lite", "call", "receipt")


def l2_targets() -> list[str]:
    cand = pd.read_parquet(SEED_DIR / "candidate_addresses.parquet", columns=["address"]).address
    pk = pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet", columns=["address"]).address
    return sorted(set(cand.str.lower()) | set(pk.str.lower()))


def build_sql(chain: str, ref: str, variant: str) -> str:
    ds = f"bigquery-public-data.{L2[chain]}"
    if variant == "inbound":
        return f"""
SELECT LOWER(to_address) AS address, COUNT(*) AS n_in, COUNTIF(status = 1) AS n_in_ok,
       COUNTIF(status = 1 AND gas_used > 21000) AS n_in_ok_gas_gt_21000,
       UNIX_SECONDS(MIN(block_timestamp)) AS first_in_ts, UNIX_SECONDS(MAX(block_timestamp)) AS last_in_ts
FROM `{ds}.receipts`
WHERE LOWER(to_address) IN (SELECT address FROM `{ref}`)
GROUP BY 1
"""
    call = ", COUNTIF(t.input IS NOT NULL AND t.input != '0x') AS n_in_call" if variant == "call" else ""
    ok, join = "", ""
    if variant == "receipt":
        ok = ", COUNTIF(r.status = 1) AS n_in_ok, SUM(r.gas_used) AS gas_in"
        join = (f"JOIN `{ds}.receipts` AS r ON r.transaction_hash = t.transaction_hash "
                f"AND r.block_hash = t.block_hash")
    return f"""
WITH c AS (SELECT address FROM `{ref}`),
inc AS (
  SELECT LOWER(t.to_address) AS address, COUNT(*) AS n_in, COUNT(DISTINCT t.from_address) AS n_senders,
         CAST(SUM(t.value.bignumeric_value) AS STRING) AS value_in_wei,
         UNIX_SECONDS(MIN(t.block_timestamp)) AS first_in_ts, UNIX_SECONDS(MAX(t.block_timestamp)) AS last_in_ts
         {call}{ok}
  FROM `{ds}.transactions` AS t {join}
  WHERE LOWER(t.to_address) IN (SELECT address FROM c)
  GROUP BY 1
),
out_ AS (
  SELECT LOWER(from_address) AS address, COUNT(*) AS n_out, UNIX_SECONDS(MIN(block_timestamp)) AS first_out_ts,
         COUNTIF(transaction_type = 4) AS n_out_type4
  FROM `{ds}.transactions`
  WHERE LOWER(from_address) IN (SELECT address FROM c)
  GROUP BY 1
)
SELECT * FROM inc FULL OUTER JOIN out_ USING (address)
"""


def _estimate(bq, client, sql: str) -> float:
    job = client.query(sql, job_config=bq.QueryJobConfig(dry_run=True, use_query_cache=False))
    return job.total_bytes_processed / GB


def cmd_dry_run():
    bq, client = _client()
    a = l2_targets()
    ref = _upload(bq, client, "l2_targets", a)
    print(f"{len(a):,} địa chỉ (ứng viên + key lộ) → {ref}; ước lượng GB quét (dry-run, không tính phí):")
    rows = []
    for chain in L2:
        rows.append({"chain": chain, **{v: round(_estimate(bq, client, build_sql(chain, ref, v)), 1) for v in VARIANTS}})
    df = pd.DataFrame(rows).set_index("chain")
    df.loc["tổng"] = df.sum()
    print(df.to_string())


def cmd_fetch(chain: str, variant: str, max_gb: float):
    bq, client = _client()
    ref = _upload(bq, client, "l2_targets", l2_targets())
    sql = build_sql(chain, ref, variant)
    est = _estimate(bq, client, sql)
    print(f"{chain}/{variant}: ước lượng quét {est:,.1f} GB (giới hạn --max-gb {max_gb:,.0f})", flush=True)
    if est > max_gb:
        raise SystemExit("Vượt --max-gb, dừng.")
    job = client.query(sql, job_config=bq.QueryJobConfig(maximum_bytes_billed=int(max_gb * GB * 1.05)))
    df = job.result().to_dataframe(create_bqstorage_client=True)
    out = RAW_DIR / chain / f"bq_l2_activity_{variant}.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    _log({"job": job.job_id, "billed_gb": (job.total_bytes_billed or 0) / GB, "rows": len(df), "out": f"{chain}/{out.name}"})
    print(f"{len(df):,} địa chỉ có tx trên {chain} → {out} (tính phí {(job.total_bytes_billed or 0) / GB:,.0f} GB)")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("dry-run")
    p = sub.add_parser("fetch")
    p.add_argument("--chain", choices=list(L2), required=True)
    p.add_argument("--variant", choices=VARIANTS, default="inbound")
    p.add_argument("--max-gb", type=float, required=True)
    a = ap.parse_args()
    if a.cmd == "dry-run":
        cmd_dry_run()
    else:
        cmd_fetch(a.chain, a.variant, a.max_gb)


if __name__ == "__main__":
    main()
