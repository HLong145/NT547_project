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

# chainId và RPC công khai mặc định (ghi đè bằng biến môi trường RPC_<NAME>)
NETWORKS = {
    "eth": (1, "https://ethereum-rpc.publicnode.com"),
    "bsc": (56, "https://bsc-rpc.publicnode.com"),
    "arb": (42161, "https://arb1.arbitrum.io/rpc"),
    "op": (10, "https://mainnet.optimism.io"),
    "base": (8453, "https://mainnet.base.org"),
    "polygon": (137, "https://polygon-bor-rpc.publicnode.com"),
    "sepolia": (11155111, "https://ethereum-sepolia-rpc.publicnode.com"),
    "bsc_testnet": (97, "https://bsc-testnet-rpc.publicnode.com"),
}


def rpc_url(network: str) -> str:
    return os.environ.get(f"RPC_{network.upper()}") or NETWORKS[network][1]


def etherscan_api_key() -> str | None:
    return os.environ.get("ETHERSCAN_API_KEY") or None
