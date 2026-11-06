"""Risk Engine cục bộ cho MetaMask Snap (`snap/`): chỉ phục vụ `POST /check`, không chuyển tiếp JSON-RPC.

python -X utf8 -m address_misuse.wallet.api [--port 8711] [--timeout 0.3]

- `POST /check` {"to", "chain", "value", "data", "authorizations"} → kết quả `OnlineStore.check` (JSON).
  `value` nhận số nguyên hoặc chuỗi hex ("0x…") như MetaMask gửi; `to` rỗng (tạo contract) → `ok`.
- `GET /health` → {"ok": true, "chains": [...]}: Snap dùng để báo người dùng khi engine chưa chạy.
- Chỉ nghe 127.0.0.1. Snap là phía hiển thị; mọi bảng tra và getCode nằm ở đây (Python) để dùng lại đúng engine của
  Module 2–3, không viết lại logic chấm bằng TypeScript.
"""

import argparse
import json

from address_misuse.config import NETWORKS
from address_misuse.wallet.online import OnlineStore
from address_misuse.wallet.proxy import Proxy


def parse_value(v) -> int:
    if v in (None, ""):
        return 0
    if isinstance(v, str):
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    return int(v)


def check_request(store: OnlineStore, req: dict, default_chain: str = "eth") -> dict:
    to = req.get("to")
    chain = req.get("chain") or default_chain
    if chain not in NETWORKS:
        return {"decision": "unsupported", "reasons": [f"chain {chain} chưa hỗ trợ"], "score": None}
    if not to:
        return {"decision": "ok", "score": 0.0, "reasons": ["tạo contract mới, không có địa chỉ đích để kiểm tra"],
                "types": [], "hard_rule": None, "missed_nets": [], "cached": False, "ms_total": 0.0}
    return store.check(to, chain, parse_value(req.get("value")), req.get("data") or "0x",
                       authorizations=req.get("authorizations"))


class Api(Proxy):
    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            return self._send({"ok": True, "chains": list(NETWORKS)})
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        if self.path.rstrip("/") != "/check":
            return self._send({"error": "chỉ có POST /check"}, 404)
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            self._send(check_request(self.store, req, self.chain))
        except Exception as e:                                  # lỗi đầu vào: báo lỗi, Snap tự fail-open
            self._send({"error": f"{type(e).__name__}: {e}"[:200]}, 400)


def main():
    from http.server import ThreadingHTTPServer
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8711)
    ap.add_argument("--chain", default="eth", help="chain mặc định khi yêu cầu không ghi chain")
    ap.add_argument("--timeout", type=float, default=0.3, help="giây ví chịu chờ getCode các mạng")
    a = ap.parse_args()
    Api.store = OnlineStore(timeout=a.timeout)
    Api.store.warm()
    Api.chain = a.chain
    print(f"Risk Engine tại http://127.0.0.1:{a.port}/check", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), Api).serve_forever()


if __name__ == "__main__":
    main()
