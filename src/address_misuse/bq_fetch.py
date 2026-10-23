"""D1 (ETH): kéo giao dịch thô của mọi địa chỉ misuse từ BigQuery `crypto_ethereum` về Parquet.

python -m address_misuse.bq_fetch dry-run              # chỉ ước lượng số GB sẽ quét, không tốn quota
python -m address_misuse.bq_fetch fetch [--max-gb 700]  # chạy thật (~680 GB quota)
python -m address_misuse.bq_fetch new-dry-run          # D6: thống kê tx của ứng viên chưa gắn cờ từ 2025-09-01
python -m address_misuse.bq_fetch new-fetch [--max-gb 220]

Xác thực: `gcloud auth application-default login` (xem SETUP_GUIDE §2). Cần GCP_PROJECT_ID trong .env.
Sandbox: 1 TB truy vấn/tháng, nên luôn dry-run trước. Truy vấn đã chạy được ghi ở data/raw/eth/bq_jobs.jsonl.

Kết quả: data/raw/eth/bq_txs.parquet — giao dịch đến/đi của từng địa chỉ mục tiêu, KHÔNG có input và hash
(2,4 TB và ~240 GB, vượt hạn mức). Khoá: (block_number, transaction_index). Đủ cho đặc trưng định lượng
(value, gas, thời điểm, đối tác, nonce); những rule cần input (NCD/PCD, ADDR input=="0x") dùng Etherscan cho tập con.
"""

import argparse
import json
import os
import time

import pandas as pd

from address_misuse.config import RAW_DIR, SEED_DIR

ETH_DIR = RAW_DIR / "eth"
TABLE = "bigquery-public-data.crypto_ethereum.transactions"
GB = 1024 ** 3


def targets() -> pd.DataFrame:
    """Mọi địa chỉ ETH trong dữ liệu tác giả (CA + EOA), chữ thường, bỏ trùng."""
    ca = pd.read_parquet(SEED_DIR / "ca_misuse.parquet", columns=["chain", "address", "subtype", "n_tx"])
    eoa = pd.read_parquet(SEED_DIR / "eoa_misuse.parquet", columns=["chain", "address", "subtype", "n_tx"])
    df = pd.concat([ca, eoa]).query("chain == 'eth'")
    df["address"] = df.address.str.lower()
    return df.sort_values("n_tx").drop_duplicates(["address", "subtype"]).reset_index(drop=True)


def _client():
    from google.cloud import bigquery
    project = os.environ.get("GCP_PROJECT_ID")
    if not project:
        raise SystemExit("Thiếu GCP_PROJECT_ID trong .env (xem docs/SETUP_GUIDE.md §2).")
    return bigquery, bigquery.Client(project=project, location="US")


def _upload_targets(bq, client) -> str:
    """Đưa danh sách địa chỉ lên bảng tạm trong project của bạn (tự hết hạn sau 7 ngày)."""
    ds = f"{client.project}.work"
    client.create_dataset(bq.Dataset(ds), exists_ok=True)
    ref = f"{ds}.targets"
    df = pd.DataFrame({"address": sorted(targets().address.unique())})
    client.load_table_from_dataframe(df, ref, job_config=bq.LoadJobConfig(write_disposition="WRITE_TRUNCATE")).result()
    t = client.get_table(ref)
    t.expires = pd.Timestamp.now(tz="UTC") + pd.Timedelta(days=7)
    client.update_table(t, ["expires"])
    return ref


def build_sql(targets_ref: str) -> str:
    """Không lấy `input` (2,4 TB) và `hash` (~240 GB): vượt hạn mức 1 TB/tháng của sandbox. Khoá giao dịch là
    (block_number, transaction_index); hash của các tx cần dẫn chứng lấy sau qua Etherscan/RPC."""
    return f"""
SELECT
  t.block_number, t.transaction_index, UNIX_SECONDS(t.block_timestamp) AS block_ts,
  t.from_address, t.to_address, t.value, t.gas, t.gas_price, t.receipt_gas_used,
  t.receipt_status, t.receipt_contract_address, t.transaction_type, t.nonce
FROM `{TABLE}` AS t
WHERE t.to_address IN (SELECT address FROM `{targets_ref}`)
   OR t.from_address IN (SELECT address FROM `{targets_ref}`)
   OR t.receipt_contract_address IN (SELECT address FROM `{targets_ref}`)
"""


NEW_SINCE = "2025-09-01"          # = config.OUT_OF_TIME_TS: tập test thứ hai (D8, cách B)


def new_targets() -> list[str]:
    """Ứng viên ETH của tác giả (GitHub/StackExchange) chưa bị gắn cờ misuse — nguồn dương mới cho D6."""
    cand = pd.read_parquet(SEED_DIR / "candidate_addresses.parquet", columns=["chain", "address"]).query("chain == 'eth'")
    known = set(targets().address)
    return sorted(set(cand.address.str.lower()) - known)


def _upload(bq, client, name: str, addresses: list[str]) -> str:
    ds = f"{client.project}.work"
    client.create_dataset(bq.Dataset(ds), exists_ok=True)
    ref = f"{ds}.{name}"
    client.load_table_from_dataframe(pd.DataFrame({"address": addresses}), ref,
                                     job_config=bq.LoadJobConfig(write_disposition="WRITE_TRUNCATE")).result()
    t = client.get_table(ref)
    t.expires = pd.Timestamp.now(tz="UTC") + pd.Timedelta(days=7)
    client.update_table(t, ["expires"])
    return ref


def build_new_sql(ref: str) -> str:
    """Gom theo ứng viên mọi tx từ NEW_SINCE mà ứng viên là người nhận hoặc người gửi (lọc theo phân vùng
    block_timestamp nên rẻ). Trả từng tx thì quá lớn (> 10 GB, BigQuery từ chối), nên chỉ lấy một dòng thống kê
    mỗi địa chỉ; ứng viên đáng chú ý sẽ lấy đủ txlist sau qua Etherscan/NodeReal rồi chạy `rules.py`."""
    return f"""
WITH c AS (SELECT address FROM `{ref}`),
t AS (
  SELECT block_timestamp, from_address, to_address, value, receipt_gas_used, receipt_status, transaction_type
  FROM `{TABLE}`
  WHERE block_timestamp >= TIMESTAMP('{NEW_SINCE}')
    AND (to_address IN (SELECT address FROM c) OR from_address IN (SELECT address FROM c))
),
inc AS (
  SELECT to_address AS address, COUNT(*) AS n_in, COUNTIF(receipt_gas_used > 21000) AS n_in_call,
         COUNTIF(receipt_status = 1) AS n_in_ok, COUNT(DISTINCT from_address) AS n_senders,
         CAST(SUM(value) AS STRING) AS value_in_wei, UNIX_SECONDS(MIN(block_timestamp)) AS first_in_ts,
         UNIX_SECONDS(MAX(block_timestamp)) AS last_in_ts
  FROM t WHERE to_address IN (SELECT address FROM c) GROUP BY 1
),
out_ AS (
  SELECT from_address AS address, COUNT(*) AS n_out, COUNTIF(transaction_type = 4) AS n_out_type4,
         UNIX_SECONDS(MIN(block_timestamp)) AS first_out_ts
  FROM t WHERE from_address IN (SELECT address FROM c) GROUP BY 1
)
SELECT * FROM inc FULL OUTER JOIN out_ USING (address)
"""


def cmd_new(max_gb: float, dry_run: bool):
    bq, client = _client()
    a = new_targets()
    ref = _upload(bq, client, "candidates_new", a)
    sql = build_new_sql(ref)
    est = client.query(sql, job_config=bq.QueryJobConfig(dry_run=True, use_query_cache=False)).total_bytes_processed / GB
    print(f"{len(a):,} ứng viên chưa gắn cờ → {ref}; ước lượng quét {est:,.1f} GB (giới hạn --max-gb {max_gb:,.0f})")
    if dry_run:
        return
    if est > max_gb:
        raise SystemExit("Vượt --max-gb, dừng.")
    job = client.query(sql, job_config=bq.QueryJobConfig(maximum_bytes_billed=int(max_gb * GB * 1.05)))
    df = job.result().to_dataframe(create_bqstorage_client=True)
    out = ETH_DIR / "bq_new_activity.parquet"
    df.to_parquet(out, index=False)
    _log({"job": job.job_id, "billed_gb": (job.total_bytes_billed or 0) / GB, "rows": len(df), "out": out.name})
    print(f"{len(df):,} ứng viên có tx từ {NEW_SINCE} → {out} (tính phí {(job.total_bytes_billed or 0) / GB:,.0f} GB)")


def _log(entry: dict):
    ETH_DIR.mkdir(parents=True, exist_ok=True)
    with (ETH_DIR / "bq_jobs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), **entry}) + "\n")


def cmd_dry_run():
    bq, client = _client()
    ref = _upload_targets(bq, client)
    job = client.query(build_sql(ref), job_config=bq.QueryJobConfig(dry_run=True, use_query_cache=False))
    print(f"{len(targets()):,} dòng mục tiêu → {ref}")
    print(f"quét {job.total_bytes_processed / GB:,.0f} GB ({job.total_bytes_processed / 1024 ** 4:.2f} TB của hạn mức 1 TB/tháng)")


def cmd_fetch(max_gb: float):
    bq, client = _client()
    ref = _upload_targets(bq, client)
    sql = build_sql(ref)
    est = client.query(sql, job_config=bq.QueryJobConfig(dry_run=True)).total_bytes_processed / GB
    print(f"ước lượng quét {est:,.0f} GB (giới hạn --max-gb {max_gb:,.0f})", flush=True)
    if est > max_gb:
        raise SystemExit("Vượt --max-gb, dừng.")
    job = client.query(sql, job_config=bq.QueryJobConfig(maximum_bytes_billed=int(max_gb * GB * 1.05)))
    df = job.result().to_dataframe(create_bqstorage_client=True)
    ETH_DIR.mkdir(parents=True, exist_ok=True)
    out = ETH_DIR / "bq_txs.parquet"
    df.to_parquet(out, index=False)
    _log({"job": job.job_id, "billed_gb": (job.total_bytes_billed or 0) / GB, "rows": len(df), "out": out.name})
    print(f"{len(df):,} giao dịch → {out} (tính phí {(job.total_bytes_billed or 0) / GB:,.0f} GB)")


def main():
    from address_misuse import config  # noqa: F401  (nạp .env)
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["dry-run", "fetch", "new-dry-run", "new-fetch"])
    ap.add_argument("--max-gb", type=float, default=700)
    a = ap.parse_args()
    if a.step.startswith("new-"):
        cmd_new(a.max_gb if a.max_gb != 700 else 220, dry_run=a.step == "new-dry-run")
    else:
        cmd_dry_run() if a.step == "dry-run" else cmd_fetch(a.max_gb)


if __name__ == "__main__":
    main()
