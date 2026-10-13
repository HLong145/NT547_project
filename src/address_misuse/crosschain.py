"""Kiểm tra nhất quán địa chỉ xuyên chuỗi (cross-chain) bằng JSON-RPC.

Ý tưởng: một giao dịch GỌI HÀM tới địa chỉ không có code trên chain hiện tại sẽ "thành công" và
tiền bị kẹt (CA Misuse). Nếu chính địa chỉ đó là contract trên một chain khác — nhất là khi
selector được gọi có trong bảng dispatcher của contract đó — gần như chắc chắn người dùng nhầm mạng.

    python -m address_misuse.crosschain 0x7a250d5630b4cf539739df2c5dacb4c659f2488d --chain bsc --data 0x7ff36ab5
"""

import argparse
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

import requests

from address_misuse.config import NETWORKS, rpc_url
from address_misuse.rules import is_hex_readable

EIP7702_PREFIX = "0xef0100"
_session = requests.Session()
_session.headers.update({"Content-Type": "application/json", "User-Agent": "address-misuse-research/0.1"})
_cache: dict[tuple[str, str], tuple[float, str]] = {}
CACHE_TTL_SEC = 300


class RpcError(RuntimeError):
    pass


def rpc(network: str, method: str, params: list, timeout: float = 8.0):
    r = _session.post(rpc_url(network), data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
                      timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RpcError(f"{network} {method}: {data['error']}")
    return data["result"]


def get_code(network: str, address: str, block: str = "latest", use_cache: bool = True, timeout: float = 8.0) -> str:
    key = (network, address.lower())
    now = time.monotonic()
    if use_cache and block == "latest" and key in _cache and now - _cache[key][0] < CACHE_TTL_SEC:
        return _cache[key][1]
    code = rpc(network, "eth_getCode", [address, block], timeout=timeout)
    if block == "latest":
        _cache[key] = (now, code)
    return code


def dispatcher_selectors(code: str) -> set[str]:
    """Selector trong bảng dispatcher: PUSH4 <sel> theo sau (trong 2 opcode) bởi EQ. Bỏ qua dữ liệu của PUSH."""
    b = bytes.fromhex(code[2:] if code.startswith("0x") else code)
    ops, pc = [], 0
    while pc < len(b):
        op = b[pc]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            ops.append((op, b[pc + 1:pc + 1 + n]))
            pc += 1 + n
        else:
            ops.append((op, b""))
            pc += 1
    sels = set()
    for i, (op, arg) in enumerate(ops):
        if op == 0x63 and len(arg) == 4 and any(o == 0x14 for o, _ in ops[i + 1:i + 3]):
            sels.add("0x" + arg.hex())
    return sels


@dataclass
class CodeInfo:
    network: str
    chain_id: int
    has_code: bool = False
    is_eip7702: bool = False
    delegate: str | None = None
    code_size: int = 0
    code_hash: str | None = None
    selectors: list[str] = field(default_factory=list)
    error: str | None = None
    latency_ms: float = 0.0


def probe_network(network: str, address: str, timeout: float = 8.0) -> CodeInfo:
    info = CodeInfo(network, NETWORKS[network][0])
    t = time.perf_counter()
    try:
        code = get_code(network, address, timeout=timeout)
    except Exception as e:
        info.error = repr(e)[:200]
        info.latency_ms = (time.perf_counter() - t) * 1000
        return info
    info.latency_ms = (time.perf_counter() - t) * 1000
    if code and code != "0x":
        info.code_size = (len(code) - 2) // 2
        info.code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        if code.startswith(EIP7702_PREFIX):
            info.is_eip7702, info.delegate = True, "0x" + code[8:48]
        else:
            info.has_code = True
            info.selectors = sorted(dispatcher_selectors(code))
    return info


def probe(address: str, networks: list[str] | None = None, timeout: float = 8.0) -> dict[str, CodeInfo]:
    """getCode song song trên nhiều chain. timeout áp dụng cho từng chain (lỗi/timeout → CodeInfo.error)."""
    networks = networks or list(NETWORKS)
    with ThreadPoolExecutor(max_workers=len(networks)) as ex:
        return dict(zip(networks, ex.map(lambda n: probe_network(n, address, timeout), networks)))


@dataclass
class Assessment:
    chain: str
    address: str
    selector: str | None
    verdict: str            # CONTRACT | EIP7702_DELEGATED | PLAIN_TRANSFER | INPUT_MESSAGE | NCD_CROSS_CHAIN | NCD_NO_CODE_ANYWHERE | UNKNOWN
    risk: str               # low | medium | high | critical
    reason: str
    other_chains_with_code: list[dict] = field(default_factory=list)
    probes: dict = field(default_factory=dict)
    latency_ms: float = 0.0


def assess_call(chain: str, to: str, data: str = "0x", networks: list[str] | None = None,
                timeout: float = 8.0) -> Assessment:
    """Đánh giá một giao dịch (chain, to, data) trước khi ký — phần CA Misuse / cross-chain."""
    t = time.perf_counter()
    data = (data or "0x").lower()
    selector = data[:10] if len(data) >= 10 else None
    probes = probe(to, networks, timeout)
    here = probes[chain]

    def done(verdict, risk, reason, others=()):
        return Assessment(chain, to.lower(), selector, verdict, risk, reason, list(others),
                          {k: asdict(v) for k, v in probes.items()}, (time.perf_counter() - t) * 1000)

    if here.error:
        return done("UNKNOWN", "medium", f"Không đọc được code trên {chain}: {here.error}")
    if here.has_code:
        return done("CONTRACT", "low", f"Địa chỉ là contract trên {chain}.")
    if here.is_eip7702:
        return done("EIP7702_DELEGATED", "medium", f"EOA đã ủy quyền EIP-7702 cho {here.delegate} — cần kiểm tra delegate.")
    if selector is None:
        return done("PLAIN_TRANSFER", "low", "Chuyển tiền thường tới địa chỉ không có code.")
    if is_hex_readable(data):
        return done("INPUT_MESSAGE", "low", "Input là văn bản (tin nhắn/memo), không phải lời gọi hàm.")

    others = []
    for n, p in probes.items():
        if n != chain and p.has_code:
            match = selector in p.selectors if p.selectors else None     # None: không đọc được dispatcher (vd. proxy)
            others.append({"network": n, "code_size": p.code_size, "selector_match": match})
    if others:
        names = ", ".join(o["network"] for o in others)
        matched = [o["network"] for o in others if o["selector_match"]]
        risk = "critical" if matched else "high"
        why = f"; hàm {selector} có trong contract ở {', '.join(matched)}" if matched else ""
        return done("NCD_CROSS_CHAIN", risk,
                    f"Địa chỉ KHÔNG có code trên {chain} nhưng là contract trên {names}{why}. "
                    f"Gọi hàm sẽ 'thành công' và tiền bị kẹt — có thể bạn đang nhầm mạng.", others)
    return done("NCD_NO_CODE_ANYWHERE", "high",
                f"Gọi hàm {selector} tới địa chỉ không có code trên mọi chain đã kiểm tra — tiền gửi kèm sẽ bị kẹt.")


def main():
    ap = argparse.ArgumentParser(description="Kiểm tra cross-chain cho một giao dịch")
    ap.add_argument("address")
    ap.add_argument("--chain", default="eth", choices=list(NETWORKS))
    ap.add_argument("--data", default="0x", help="calldata (hoặc chỉ 4-byte selector)")
    ap.add_argument("--timeout", type=float, default=8.0, help="timeout mỗi chain (giây)")
    a = ap.parse_args()
    r = assess_call(a.chain, a.address, a.data, timeout=a.timeout)
    print(f"[{r.risk.upper()}] {r.verdict} ({r.latency_ms:.0f} ms)\n{r.reason}")
    for n, p in r.probes.items():
        state = "7702→" + p["delegate"] if p["is_eip7702"] else (f"code {p['code_size']} B" if p["has_code"] else "—")
        print(f"  {n:12s} {state:50s} {p['latency_ms']:6.0f} ms {p['error'] or ''}")


if __name__ == "__main__":
    main()
