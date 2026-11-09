"""Engine v2 (tiền đăng ký GOLD_PROTOCOL §10, trước khi có nhãn lô 2). v1 (994bb2b) giữ nguyên làm kết quả chính.

Quyết định v2 cho một dòng (địa chỉ, chain, `at`) = quyết định v1 (luật cứng v1 hoặc risk(w học) ≥ τ_warn) HOẶC:

- `ncd_call`: trên chính chain không có code tại `at` (`state = none`), tx có gọi hàm và không phải tin nhắn văn bản
  (`bytecode = 1`, tức tín hiệu T1 đầy đủ). Ở v1 tín hiệu này một mình chỉ cho R = 62,39 < τ_warn = 63,01 (trọng số bytecode
  0,522), nên T1 thuần bị bỏ sót.
- `sweeper_full`: địa chỉ không có code tại `at` và có ≥ `MIN_FAST` lần rút nhanh (`fullhist.fast_withdrawals`: coin, token,
  NFT; ≤ 600 s; 90–102%; tới ví khác ví gửi; tx rút không nhận lại tài sản) trong lịch sử. Ngưỡng lấy nguyên từ CODEBOOK §3.4
  (đặt trước khi có nhãn lô 1), không chỉnh theo nhãn vàng. Hai mốc cắt, báo cả hai:
  - `at` (nhân quả, CHÍNH cho v2): chỉ các lần rút có `out_ts < at`.
  - `now`: toàn bộ lịch sử đến lúc tải (đúng câu hỏi của ví: gửi tới địa chỉ này HÔM NAY có rủi ro không; trùng định nghĩa nhãn
    KEY dùng toàn bộ lịch sử, nên dễ được lợi hơn khi so nhãn vàng).
"""
from __future__ import annotations

import pandas as pd

from address_misuse.engine import fullhist

MIN_FAST = 2


def fast_counts(pairs: pd.DataFrame) -> dict[tuple[str, str], list[int]]:
    """(chain, address) → danh sách `out_ts` các lần rút nhanh (chỉ địa chỉ đã có cache fullhist)."""
    out = {}
    for c, a in pairs[["chain", "address"]].drop_duplicates().itertuples(index=False):
        j = fullhist.load(c, a)
        if j is not None:
            out[(c, a)] = sorted(w["out_ts"] for w in fullhist.fast_withdrawals(j["events"], a))
    return out


def flags_rows(e: pd.DataFrame, fast: dict, cut: str = "at") -> pd.DataFrame:
    """Thêm cột `ncd_call`, `sweeper_full`, `n_fast`, `hard_v2`, `f_v2` cho các dòng của `gold_final._pool()`."""
    e = e.copy()
    e["ncd_call"] = (e.state == "none") & e.has_call.fillna(False).astype(bool) & (e.bytecode >= 1.0)
    n = []
    for c, a, at in zip(e.chain, e.address, e["at"]):
        ts = fast.get((c, a))
        n.append(None if ts is None else (sum(t < int(at) for t in ts) if cut == "at" else len(ts)))
    e["n_fast"] = n
    e["sweeper_full"] = (e.state != "code") & (pd.to_numeric(e.n_fast).fillna(0) >= MIN_FAST)
    e["hard_v2"] = e.hard.where(e.hard.notna(), None)
    e.loc[e.hard_v2.isna() & e.ncd_call, "hard_v2"] = "ncd_call"
    e.loc[e.hard_v2.isna() & e.sweeper_full, "hard_v2"] = "sweeper_full"
    e["f_v2"] = e.f_frozen | e.ncd_call | e.sweeper_full
    return e
