"""Client Etherscan API V2 (một key, nhiều chain qua `chainid`).

Thay cho onchain_fetcher/ của tác giả, sửa các lỗi:
- Dùng API V2 (`https://api.etherscan.io/v2/api?chainid=...`); V1 và các domain bscscan riêng đã ngừng.
- `CodeFetcher(etherscan_api)` của tác giả truyền key vào tham số `chain` → luôn lỗi "chain not exist".
- Key đọc từ .env thay vì file api_config.py không được công bố.
Bản ghi trả về giữ nguyên định dạng Etherscan (chuỗi), nên các rule trong rules.py dùng trực tiếp được.
"""

import os
import threading
import time
from typing import Callable

import requests

from address_misuse.config import NETWORKS, etherscan_api_key

BASE_URL = "https://api.etherscan.io/v2/api"
# Gói miễn phí: tối đa 1.000 bản ghi/lần gọi (từ 07/2026); gói trả phí: 10.000. Đặt ETHERSCAN_PAGE_SIZE trong .env.
PAGE_SIZE = int(os.environ.get("ETHERSCAN_PAGE_SIZE", 1000))

# Khoá để bỏ trùng khi ghép nhiều trang
_RECORD_KEY: dict[str, Callable[[dict], tuple]] = {
    "txlist": lambda r: (r["hash"],),
    "txlistinternal": lambda r: (r["hash"], r.get("traceId", ""), r.get("from"), r.get("to"), r.get("value")),
    "tokentx": lambda r: (r["hash"], r.get("logIndex", "")),
}


class EtherscanError(RuntimeError):
    pass


class Etherscan:
    def __init__(self, chain: str, api_key: str | None = None, rps: float | None = None, session=None):
        self.chain = chain
        self.chain_id = NETWORKS[chain][0]
        self.api_key = api_key or etherscan_api_key()
        if not self.api_key:
            raise EtherscanError("Thiếu ETHERSCAN_API_KEY trong .env")
        # Gói miễn phí: 3 lệnh/giây (vượt → "Max calls per sec rate limit reached"); để dư một chút
        self.min_interval = 1.0 / (rps or float(os.environ.get("ETHERSCAN_RPS", 2.8)))
        self.session = session or requests.Session()
        self._lock = threading.Lock()
        self._last_call = 0.0

    # ------------------------------------------------------------ low level

    def _throttle(self):
        with self._lock:
            wait = self._last_call + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def call(self, module: str, action: str, retries: int = 4, **params) -> dict:
        query = {"chainid": self.chain_id, "module": module, "action": action, "apikey": self.api_key, **params}
        last_err = None
        attempt = rate_waits = 0
        while attempt < retries:
            self._throttle()
            try:
                r = self.session.get(BASE_URL, params=query, timeout=(10, 60))
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                last_err = e
            else:
                if module == "proxy":                        # JSON-RPC style
                    res = data.get("result")
                    if "error" not in data and (not isinstance(res, str) or res.startswith("0x")):
                        return data
                    last_err = data.get("error") or res or data   # vd. "Free API access is not supported for this chain"
                    if isinstance(last_err, str) and "not supported" in last_err.lower():
                        raise EtherscanError(f"{self.chain}: {last_err}")
                elif data.get("status") == "1" or data.get("message", "").startswith("No "):
                    return data                              # "No transactions found" / "No records found"
                else:
                    last_err = data.get("result") or data.get("message")
                    if isinstance(last_err, str) and ("Invalid API Key" in last_err or "not supported" in last_err.lower()):
                        raise EtherscanError(f"{self.chain}: {last_err}")
                    if isinstance(last_err, str) and "rate limit" in last_err.lower() and rate_waits < 30:
                        rate_waits += 1                      # chỉ vượt hạn mức/giây: chờ ngắn, không tính là lần thử
                        time.sleep(1.0)
                        continue
            attempt += 1
            time.sleep(1.5 * attempt)
        raise EtherscanError(f"{self.chain} {module}.{action} {params.get('address', '')}: {last_err}")

    # ------------------------------------------------------------ account

    def fetch_all(self, action: str, address: str, max_records: int = 50_000) -> tuple[list[dict], bool]:
        """Lấy toàn bộ bản ghi (txlist / txlistinternal / tokentx) theo thứ tự block tăng dần.

        Trả về (records, truncated). Phân trang bằng startblock như tác giả, rồi bỏ trùng.
        """
        key = _RECORD_KEY[action]
        records, seen, start_block = [], set(), 0
        while True:
            data = self.call("account", action, address=address, startblock=start_block, endblock=9_999_999_999,
                             page=1, offset=PAGE_SIZE, sort="asc")
            batch = data.get("result") or []
            for r in batch:
                k = key(r)
                if k not in seen:
                    seen.add(k)
                    records.append(r)
            if len(batch) < PAGE_SIZE:
                return records, False
            if len(records) >= max_records:
                return records[:max_records], True
            next_start = int(batch[-1]["blockNumber"])
            if next_start == start_block:                    # > PAGE_SIZE bản ghi trong một block: không thể phân trang tiếp
                return records, True
            start_block = next_start

    def txlist(self, address: str, max_records: int = 50_000):
        return self.fetch_all("txlist", address, max_records)

    def internal_txs(self, address: str, max_records: int = 50_000):
        return self.fetch_all("txlistinternal", address, max_records)

    def token_transfers(self, address: str, max_records: int = 50_000):
        return self.fetch_all("tokentx", address, max_records)

    def balances(self, addresses: list[str]) -> dict[str, int]:
        out = {}
        for i in range(0, len(addresses), 20):            # balancemulti: tối đa 20 địa chỉ
            data = self.call("account", "balancemulti", address=",".join(addresses[i:i + 20]), tag="latest")
            out.update({r["account"].lower(): int(r["balance"]) for r in data["result"]})
        return out

    # ------------------------------------------------------------ contract / state

    def contract_creation(self, addresses: list[str]) -> dict[str, dict]:
        """Giao dịch tạo contract (tối đa 5 địa chỉ mỗi lần). Địa chỉ không phải contract sẽ không có trong kết quả."""
        out = {}
        for i in range(0, len(addresses), 5):
            data = self.call("contract", "getcontractcreation", contractaddresses=",".join(addresses[i:i + 5]))
            for r in data.get("result") or []:
                out[r["contractAddress"].lower()] = r
        return out

    def get_code(self, address: str, tag: str = "latest") -> str:
        return self.call("proxy", "eth_getCode", address=address, tag=tag)["result"]

    def get_storage_at(self, address: str, slot: str, tag: str = "latest") -> str:
        return self.call("proxy", "eth_getStorageAt", address=address, position=slot, tag=tag)["result"]


def check_key(networks=("eth", "bsc", "arb", "op", "base", "polygon", "sepolia")) -> dict[str, str]:
    """Thử key trên từng chain bằng một lệnh rẻ (eth_blockNumber). Trả về {chain: 'OK block N' | lỗi}."""
    out = {}
    for n in networks:
        try:
            es = Etherscan(n, rps=2)
            out[n] = f"OK (block {int(es.call('proxy', 'eth_blockNumber', retries=1)['result'], 16):,})"
        except Exception as e:
            out[n] = f"LỖI: {str(e)[:150]}"
    return out


if __name__ == "__main__":
    # python -X utf8 -m address_misuse.etherscan   → kiểm tra key hỗ trợ chain nào
    for chain, status in check_key().items():
        print(f"{chain:10s} {status}")
