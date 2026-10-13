"""Symbolic execution nhẹ của Shao et al. để nhận diện contract rút tiền (fund-sweeping).

Cách tác giả diễn giải kết quả (run_sym.py, txs_analyzer.py, RQ3/attack_pattern):
- Contract tại địa chỉ PCD (CA Misuse) là độc nếu rút toàn bộ số dư, rút theo số lượng do input chỉ định,
  hoặc có SELFDESTRUCT (xét cả logic contract nếu là proxy).
- Delegate EIP-7702 là độc nếu rút toàn bộ số dư hoặc chuyển tiếp msg.value.
"""

import time

from .disassembly import Disassembly
from .symbolic_executor import DEFAULT_TIMEOUT_SEC, SymbolicExecutor

__all__ = ["Disassembly", "SymbolicExecutor", "analyze", "is_pcd_sweeper", "is_eip7702_sweeper"]


def analyze(address: str, bytecode: str, timeout_sec: float = DEFAULT_TIMEOUT_SEC) -> dict:
    """Chạy symbolic execution, trả về detection_res của tác giả + time + timed_out."""
    ex = SymbolicExecutor(address, bytecode)
    start = time.perf_counter()
    ex.process(timeout_sec=timeout_sec)
    res = ex.detection_res
    res["time"] = time.perf_counter() - start
    res["timed_out"] = ex.timed_out
    return res


def _valid(res: dict, key: str) -> bool:
    return bool((res.get(key) or {}).get("valid"))


def is_pcd_sweeper(res: dict) -> bool:
    return _valid(res, "transfer_all_eth") or _valid(res, "transfer_input_amount") or _valid(res, "self_destruct")


def is_eip7702_sweeper(res: dict) -> bool:
    return _valid(res, "transfer_all_eth") or _valid(res, "transfer_msg_value")
