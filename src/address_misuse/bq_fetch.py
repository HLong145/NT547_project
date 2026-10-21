"""D1 (ETH): kéo giao dịch thô của mọi địa chỉ misuse từ BigQuery `crypto_ethereum` về Parquet.

python -m address_misuse.bq_fetch dry-run              # chỉ ước lượng số GB sẽ quét, không tốn quota
python -m address_misuse.bq_fetch fetch [--max-gb 700]  # chạy thật (~680 GB quota)

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
    ap.add_argument("step", choices=["dry-run", "fetch"])
    ap.add_argument("--max-gb", type=float, default=700)
    a = ap.parse_args()
    cmd_dry_run() if a.step == "dry-run" else cmd_fetch(a.max_gb)


if __name__ == "__main__":
    main()
