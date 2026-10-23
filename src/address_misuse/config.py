"""Đường dẫn và hằng số dùng chung cho toàn dự án."""

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

DATA_DIR = PROJECT_ROOT / "data"
AUTHOR_DIR = DATA_DIR / "Address-Misuse"           # dữ liệu gốc Zenodo 17984167, chỉ đọc
AUTHOR_EXP_DIR = AUTHOR_DIR / "experiment"
SEED_DIR = DATA_DIR / "seed"
RAW_DIR = DATA_DIR / "raw"
INTERIM_DIR = DATA_DIR / "interim"
GOLD_DIR = DATA_DIR / "gold"
FINAL_DIR = DATA_DIR / "final"

CHAINS = ("eth", "bsc")                           # chain có trong dữ liệu tác giả
SOURCES = ("github", "stackexchange")

# Block kích hoạt EIP-7702 mà code tác giả dùng (txs_analyzer.py)
EIP7702_ACTIVATION_BLOCK = {"eth": 22431111, "bsc": 47618307}
# timestamp của hai block trên: trước đó không EOA nào có thể ủy quyền EIP-7702
EIP7702_ACTIVATION_TS = {"eth": 1746612683, "bsc": 1742436600}

# D8 (chốt 2026-10-23): chia theo thời điểm xét `at`, mốc = phân vị 70/85% thời điểm tx đầu tiên của dương CA
# trong dữ liệu tác giả. Tập "ngoài thời gian" (≥ 2025-09-01) là tập test thứ hai cho dương mới của D6.
SPLIT_VAL_TS = 1675987200          # 2023-02-10 UTC: train < mốc này ≤ val
SPLIT_TEST_TS = 1696464000         # 2023-10-05 UTC: val < mốc này ≤ test
OUT_OF_TIME_TS = 1756684800        # 2025-09-01 UTC

# chainId và RPC công khai mặc định (ghi đè bằng biến môi trường RPC_<NAME>)
NETWORKS = {
    "eth": (1, "https://ethereum-rpc.publicnode.com"),
    "bsc": (56, "https://bsc-rpc.publicnode.com"),
    "arb": (42161, "https://arbitrum-one-rpc.publicnode.com"),
    "op": (10, "https://optimism-rpc.publicnode.com"),       # mainnet.optimism.io: batch tối đa 10
    "base": (8453, "https://base-rpc.publicnode.com"),       # mainnet.base.org: giới hạn batch/tốc độ
    "polygon": (137, "https://polygon-bor-rpc.publicnode.com"),
    "sepolia": (11155111, "https://ethereum-sepolia-rpc.publicnode.com"),
    "bsc_testnet": (97, "https://bsc-testnet-rpc.publicnode.com"),
}


def rpc_url(network: str) -> str:
    return os.environ.get(f"RPC_{network.upper()}") or NETWORKS[network][1]


def etherscan_api_key() -> str | None:
    return os.environ.get("ETHERSCAN_API_KEY") or None
