"""RPC proxy đứng giữa ví và RPC thật (PLAN_V2 §5): chặn giao dịch rủi ro trước khi gửi lên mạng.

python -X utf8 -m address_misuse.wallet.proxy [--chain eth] [--port 8545] [--upstream URL]
    Trỏ ví (MetaMask "Add network", hoặc Anvil fork khi demo) tới http://127.0.0.1:8545.

- `eth_sendTransaction` / `eth_sendRawTransaction`: giải mã to / value / data (tx thô: legacy, type 1/2/3/4; type 4
  thêm danh sách delegate trong authorizationList), gọi `OnlineStore.check`.
  `block` → trả lỗi JSON-RPC (code 4001) kèm lý do, không chuyển tiếp; `warn` → ghi log rồi chuyển tiếp;
  `ok` → chuyển tiếp. Mọi lệnh khác chuyển tiếp nguyên vẹn.
- `POST /check` {"to", "chain", "value", "data"} → kết quả JSON (dùng cho Snap/extension hoặc đo độ trễ).

Ghi chú: MetaMask ký trong ví rồi mới gửi `eth_sendRawTransaction`, nên proxy chặn được việc *phát* giao dịch
nhưng người dùng chỉ thấy lỗi sau khi bấm xác nhận. Cảnh báo trước khi ký cần Snap (GOALS: chưa chốt);
proxy dùng để đo độ trễ và demo.
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from address_misuse.config import rpc_url
from address_misuse.wallet.online import OnlineStore


# ---------------------------------------------------------------- giải mã tx thô

def rlp_decode(b: bytes):
    """RLP → bytes hoặc list lồng nhau."""
    def item(i):
        p = b[i]
        if p < 0x80:
            return b[i:i + 1], i + 1
        if p < 0xb8:
            n = p - 0x80
            return b[i + 1:i + 1 + n], i + 1 + n
        if p < 0xc0:
            ln = p - 0xb7
            n = int.from_bytes(b[i + 1:i + 1 + ln], "big")
            s = i + 1 + ln
            return b[s:s + n], s + n
        if p < 0xf8:
            n, s = p - 0xc0, i + 1
        else:
            ln = p - 0xf7
            n, s = int.from_bytes(b[i + 1:i + 1 + ln], "big"), i + 1 + ln
        out, j = [], s
        while j < s + n:
            x, j = item(j)
            out.append(x)
        return out, s + n
    return item(0)[0]


TO_INDEX = {None: 3, 1: 4, 2: 5, 3: 5, 4: 5}              # vị trí `to` trong danh sách RLP theo loại tx


def decode_raw_tx(raw: str) -> dict:
    """{"type", "to", "value", "data", "authorizations"} từ tx thô đã ký (hex)."""
    b = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    typ = None
    if b[0] < 0x7f:                                         # EIP-2718: byte đầu là loại tx
        typ, b = b[0], b[1:]
    f = rlp_decode(b)
    i = TO_INDEX.get(typ)
    if i is None:
        raise ValueError(f"loại tx {typ} chưa hỗ trợ")
    to, value, data = f[i], f[i + 1], f[i + 2]
    auth = [("0x" + a[1].hex()) for a in f[9]] if typ == 4 and len(f) > 9 else []
    return {"type": typ or 0, "to": ("0x" + to.hex()) if to else None, "value": int.from_bytes(value, "big"),
            "data": "0x" + data.hex(), "authorizations": auth}


def tx_from_request(method: str, params: list) -> dict | None:
    if method == "eth_sendRawTransaction":
        return decode_raw_tx(params[0])
    if method == "eth_sendTransaction":
        p = params[0]
        return {"type": None, "to": p.get("to"), "value": int(p.get("value") or "0x0", 16),
                "data": p.get("data") or p.get("input") or "0x",
                "authorizations": [a.get("address") for a in p.get("authorizationList") or []]}
    return None


# ---------------------------------------------------------------- server

class Proxy(BaseHTTPRequestHandler):
    store: OnlineStore
    chain: str
    upstream: str
    session = requests.Session()

    def log_message(self, *a):
        pass

    def _send(self, obj, code: int = 200):
        body = json.dumps(obj, ensure_ascii=False, default=list).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path.rstrip("/") == "/check":
            r = self.store.check(req["to"], req.get("chain", self.chain), int(req.get("value", 0)),
                                 req.get("data", "0x"), authorizations=req.get("authorizations"))
            return self._send(r)
        batch = req if isinstance(req, list) else [req]
        out = [self._handle(r) for r in batch]
        self._send(out if isinstance(req, list) else out[0])

    def _handle(self, r: dict) -> dict:
        tx = None
        try:
            tx = tx_from_request(r.get("method", ""), r.get("params") or [])
        except Exception as e:                              # không giải mã được thì không chặn
            print(f"[proxy] không giải mã được tx: {e!r:.100}", flush=True)
        res = None
        if tx and tx["to"]:
            try:
                res = self.store.check(tx["to"], self.chain, tx["value"], tx["data"], authorizations=tx["authorizations"])
            except Exception as e:                          # kiểm tra lỗi thì không chặn (fail-open), tránh làm ví mất kết nối
                print(f"[proxy] kiểm tra lỗi, chuyển tiếp: {e!r:.100}", flush=True)
        if res:
            print(f"[proxy] {r['method']} → {tx['to']} R={res['score']:.1f} {res['decision']} "
                  f"({res['ms_total']:.0f} ms) {res['reasons'][:2]}", flush=True)
            if res["decision"] == "block":
                return {"jsonrpc": "2.0", "id": r.get("id"),
                        "error": {"code": 4001, "message": "Address Misuse: chặn giao dịch rủi ro — "
                                  + "; ".join(res["reasons"][:3]), "data": res}}
        return self.session.post(self.upstream, json=r, timeout=30).json()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="eth")
    ap.add_argument("--port", type=int, default=8545)
    ap.add_argument("--upstream", default=None, help="RPC thật (mặc định RPC công khai của chain)")
    ap.add_argument("--timeout", type=float, default=0.3, help="giây ví chịu chờ getCode các mạng")
    a = ap.parse_args()
    Proxy.store = OnlineStore(timeout=a.timeout)
    Proxy.store.warm()
    Proxy.chain, Proxy.upstream = a.chain, a.upstream or rpc_url(a.chain)
    print(f"proxy {a.chain} tại http://127.0.0.1:{a.port} → RPC thật của {a.chain}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), Proxy).serve_forever()


if __name__ == "__main__":
    main()
