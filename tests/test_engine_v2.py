import pandas as pd

from address_misuse.engine import fullhist, v2

A = "0x" + "a" * 40


def ev(ts, frm, to, amt, asset="NATIVE", h=None, fee=0.0):
    return {"ts": ts, "block": ts, "frm": frm, "to": to, "amt": amt, "asset": asset, "hash": h or f"h{ts}{frm[2]}{to[2]}",
            "fee": fee}


def test_fast_withdrawals_counts_tokens_and_skips_swaps_and_refunds():
    b, c, d = "0x" + "b" * 40, "0x" + "c" * 40, "0x" + "d" * 40
    usdt = "0x" + "e" * 40
    events = [
        ev(100, b, A, 1.0), ev(160, A, c, 0.995, fee=0.004),          # rút nhanh coin (tính phí gas)
        ev(1000, b, A, 50.0, usdt), ev(1100, A, d, 50.0, usdt),        # rút nhanh token
        ev(2000, b, A, 1.0), ev(3000, A, c, 1.0),                      # quá 600 s: không tính
        ev(4000, b, A, 1.0), ev(4010, A, b, 1.0),                      # trả lại ví gửi: không tính
        ev(5000, b, A, 1.0), ev(5010, A, c, 1.0, h="swap"), ev(5010, c, A, 7.0, usdt, h="swap"),   # swap nhận lại token
        ev(6000, b, A, 1.0), ev(6010, A, c, 0.5),                      # chỉ 50%: không tính
    ]
    fw = fullhist.fast_withdrawals(events, A)
    assert [(w["in_ts"], w["asset"]) for w in fw] == [(100, "NATIVE"), (1000, usdt)]


def test_v2_flags_ncd_call_and_sweeper_cut_at():
    e = pd.DataFrame({
        "chain": ["eth"] * 4, "address": [A, A, "0x" + "1" * 40, "0x" + "2" * 40], "at": [150, 10_000, 5, 5],
        "state": ["none", "none", "none", "code"], "has_call": [False, False, True, True], "bytecode": [0.0, 0.0, 1.0, 1.0],
        "hard": [None, None, None, None], "f_frozen": [False, False, False, False]})
    fast = {("eth", A): [100, 200, 300]}
    at = v2.flags_rows(e, fast, cut="at")
    assert at.n_fast.tolist()[:2] == [1, 3]
    assert at.f_v2.tolist() == [False, True, True, False]
    assert at.hard_v2.tolist() == [None, "sweeper_full", "ncd_call", None]
    now = v2.flags_rows(e, fast, cut="now")
    assert now.f_v2.tolist() == [True, True, True, False]
