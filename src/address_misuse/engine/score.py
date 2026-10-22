"""Risk score R(A, C) = 100 · Σ w_i · S_i (docs/RISK_SCORE.md §2–§3).

Mỗi S_i là hàm thuần trên `Features` (+ ngữ cảnh giao dịch nếu có), trả (điểm ∈ [0,1], các Type nghi ngờ, lý do).
Hằng số ghi (*) trong đặc tả là tham số mặc định, sẽ chọn lại trên tập val.

    python -m address_misuse.engine 0x... --chain bsc [--data 0x...] [--at UNIX_TS]
"""

import argparse
import math
from dataclasses import dataclass, field

from address_misuse.engine.features import NETS, Features, FeatureStore
from address_misuse.rules import is_hex_readable

DEFAULT_WEIGHTS = {"bytecode": 0.25, "cross": 0.25, "osint": 0.25, "history": 0.25}

# (*) tham số mặc định
NONE_NO_CTX = 0.5            # địa chỉ không có code, không biết tx có calldata không, không có lịch sử
UNKNOWN_CODE = 0.3           # contract chưa có symexec
DELEGATE_TRANSFER = 0.5      # delegate 7702 lạ, symexec thấy đường chuyển tiền
DELEGATE_NO_TRANSFER = 0.2
DELEGATE_UNKNOWN = 0.3
XC_UNKNOWN_TIME = 0.7        # có code ở mạng khác nhưng không biết deploy trước hay sau `at`
XC_DIFFERENT_CODE = 0.6      # PCD-XC: có code ở cả hai nơi nhưng bytecode khác
SAME_CONTRACT_JACCARD = 0.8  # tỉ lệ selector trùng để coi là cùng contract trên hai chain
REDEPLOY_BONUS = 0.1
OSINT_K = 3.0
REVERT_MIN_TX = 5
MISUSE_MIN_SENDERS = 2
TRANSFER_SELECTOR = "0xa9059cbb"


@dataclass
class TxContext:
    value_wei: int = 0
    calldata: str = "0x"

    @property
    def has_call(self) -> bool:
        return self.calldata not in ("", "0x", None)


@dataclass
class RiskResult:
    score: float                                         # 0–100
    components: dict = field(default_factory=dict)       # {"bytecode": .., "cross": .., "osint": .., "history": ..}
    types: list = field(default_factory=list)            # ví dụ ["T4"], ["T1", "T4"]
    reasons: list = field(default_factory=list)
    hard_rule: str | None = None                         # "leaked_key" | "malicious_delegate" | None


def s_bytecode(f: Features, ctx: TxContext | None = None) -> tuple[float, list, list]:
    st = f.state()
    if st is None:
        return 0.0, [], [f"không tra được code trên {f.chain}"]
    if st == "none":
        if ctx is not None:
            if ctx.has_call and is_hex_readable(ctx.calldata):            # bộ lọc IDM của Shao et al.
                return 0.0, [], ["input là tin nhắn văn bản, không phải gọi hàm"]
            if ctx.has_call:
                return 1.0, ["T1"], [f"gọi hàm tới địa chỉ không có code trên {f.chain}"]
            return 0.0, [], []
        h = f.history
        if h and h["n_in"]:
            share = h["n_in_call"] / h["n_in"]
            return share, ["T1"] if share else [], [f"{share:.0%} tx tới địa chỉ không code có calldata"] if share else []
        return NONE_NO_CTX, [], [f"địa chỉ không có code trên {f.chain}"]
    if st == "code":
        if ctx is not None and ctx.calldata.lower().startswith(TRANSFER_SELECTOR) and len(ctx.calldata) >= 74:
            if "0x" + ctx.calldata[34:74].lower() == f.address:
                return 1.0, ["T3"], ["chuyển token tới chính contract token"]
        sx = f.symexec
        if sx is None:
            return UNKNOWN_CODE, [], ["contract chưa phân tích symexec"]
        if not sx["transfer"] and not sx["delegatecall"] and not sx["selfdestruct"]:
            return 1.0, ["T2"], ["contract không có đường rút coin (hố đen)"]
        return 0.0, [], []
    # 7702
    if f.delegate_malicious:
        return 1.0, ["T5"], ["EOA ủy quyền EIP-7702 cho delegate trong danh sách đen"]
    if f.delegate_benign:
        return 0.0, [], []
    sx = f.delegate_symexec
    if sx is None:
        return DELEGATE_UNKNOWN, [], ["delegate EIP-7702 lạ, chưa phân tích"]
    if sx["transfer"]:
        return DELEGATE_TRANSFER, ["T5"], ["delegate EIP-7702 lạ có đường chuyển tiền"]
    return DELEGATE_NO_TRANSFER, [], []


def same_contract(f: Features, net: str) -> bool:
    """Cùng một contract (hạ tầng đa chain) trên `f.chain` và `net`: trùng hash, hoặc trùng phần lớn selector.
    So hash thôi là quá chặt: immutable khác nhau giữa các chain (vd. địa chỉ WETH) làm hash khác."""
    own_h, h = f.code_hash.get(f.chain), f.code_hash.get(net)
    if own_h and own_h == h:
        return True
    a, b = f.selectors.get(f.chain), f.selectors.get(net)
    return bool(a and b and len(a & b) / len(a | b) >= SAME_CONTRACT_JACCARD)


def s_cross(f: Features, ctx: TxContext | None = None) -> tuple[float, list, list]:
    others = [n for n in NETS if n != f.chain and f.code.get(n) == "code"]
    st = f.state()
    if not others or st in (None, "7702"):
        return 0.0, [], []
    if st == "code":
        if any(same_contract(f, n) for n in others):
            return 0.0, [], []
        return XC_DIFFERENT_CODE, ["PCD-XC"], [f"bytecode trên {f.chain} khác bản ở {', '.join(others)}"]
    nets = ", ".join(others)
    if f.at is None:
        s, why = 1.0, f"địa chỉ không có code trên {f.chain} nhưng là contract trên {nets}"
    elif f.first_create_ts is None:
        s, why = XC_UNKNOWN_TIME, f"là contract trên {nets} (không rõ deploy lúc nào)"
    elif f.first_create_ts <= f.at:
        s, why = 1.0, f"địa chỉ không có code trên {f.chain} nhưng đã là contract trên {nets}"
    else:
        return 0.0, [], [f"contract trên {nets} được deploy sau thời điểm xét"]
    reasons = [why]
    if f.redeploy == "claimable":
        s = min(1.0, s + REDEPLOY_BONUS)
        reasons.append(f"người deploy vẫn có thể chiếm địa chỉ này trên {f.chain}")
    return s, ["T4"], reasons


def s_osint(f: Features) -> tuple[float, list, list]:
    if f.leaked_key:
        return 1.0, ["KEY"], ["private key của địa chỉ đã bị lộ công khai"]
    if f.osint:
        return 1 - math.exp(-1 / OSINT_K), [], ["địa chỉ xuất hiện trong mã nguồn công khai"]
    return 0.0, [], []


def s_history(f: Features) -> tuple[float, list, list]:
    h = f.history
    if not h or not h["n_tx"]:
        return 0.0, [], []
    s_sweep = min(1.0, h["n_sweep"] / h["n_plain_in"]) if h["n_plain_in"] else 0.0
    s_revert = h["n_in_fail"] / h["n_in"] if h["n_in"] >= REVERT_MIN_TX else 0.0
    s_misuse = 1.0 if f.state() == "none" and h["call_senders"] >= MISUSE_MIN_SENDERS else 0.0
    s = 1 - (1 - s_sweep) * (1 - s_revert) * (1 - s_misuse)
    reasons, types = [], []
    if s_sweep:
        reasons.append(f"{h['n_sweep']} lần tiền nạp bị rút sạch ngay (sweeper)")
        types.append("SWEEP")
    if s_revert:
        reasons.append(f"{s_revert:.0%} tx tới địa chỉ bị revert")
    if s_misuse:
        reasons.append(f"{h['call_senders']} người khác đã gọi hàm tới địa chỉ không có code này")
    return s, types, reasons


COMPONENTS = {"bytecode": s_bytecode, "cross": s_cross, "osint": lambda f, ctx: s_osint(f),
              "history": lambda f, ctx: s_history(f)}


def score_features(f: Features, ctx: TxContext | None = None, weights: dict = DEFAULT_WEIGHTS) -> RiskResult:
    parts = {k: fn(f, ctx) for k, fn in COMPONENTS.items()}
    comps = {k: round(v[0], 4) for k, v in parts.items()}
    total = 100 * sum(weights[k] * comps[k] for k in comps) / sum(weights.values())
    types = list(dict.fromkeys(t for _, ts, _ in parts.values() for t in ts))
    order = sorted(parts, key=lambda k: -weights[k] * comps[k])
    reasons = [r for k in order for r in parts[k][2]]
    hard = "leaked_key" if f.leaked_key else "malicious_delegate" if f.state() == "7702" and f.delegate_malicious \
        else None
    return RiskResult(round(total, 2), comps, types, reasons, hard)


_store: FeatureStore | None = None


def score(address: str, chain: str, at: int | None = None, ctx: TxContext | None = None,
          weights: dict = DEFAULT_WEIGHTS, store: FeatureStore | None = None, probe: bool = True) -> RiskResult:
    global _store
    if store is None:
        _store = _store or FeatureStore()
        store = _store
    store.prepare([(chain, address)])
    if probe and store.missing_code([address]):
        store.probe([address])
    return score_features(store.features(address, chain, at), ctx, weights)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("address")
    ap.add_argument("--chain", default="eth")
    ap.add_argument("--data", default=None, help="calldata của tx sắp gửi (bỏ trống = chấm theo địa chỉ)")
    ap.add_argument("--value", type=int, default=0)
    ap.add_argument("--at", type=int, default=None)
    a = ap.parse_args()
    ctx = TxContext(a.value, a.data) if a.data is not None else None
    r = score(a.address, a.chain, a.at, ctx)
    print(f"R = {r.score:.1f}/100  {r.components}  types={r.types}  hard_rule={r.hard_rule}")
    for why in r.reasons:
        print("  -", why)


if __name__ == "__main__":
    main()
