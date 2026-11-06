"""Demo Module 4 trên Anvil fork (PLAN_V2 §5 "Demo"): phát lại giao dịch misuse thật, có và không có proxy.

python -X utf8 -m address_misuse.wallet.demo --anvil C:/path/anvil.exe [--fork-rpc URL] [--case all|aave|pancake|truffle]
    → data/interim/wallet_demo.json + bảng tóm tắt

Mỗi ca:
1. `anvil --fork-url <RPC lưu trữ> --fork-block-number <block ngay trước tx gốc> --chain-id 1`.
2. Engine đọc code của chain ETH **từ chính bản fork** (đặt `RPC_ETH` = Anvil), nên thấy trạng thái lúc tx gốc chứ không
   phải hôm nay (ví dụ địa chỉ Aave Kovan hôm nay đã có contract do deployer deploy lại). Các mạng khác vẫn đọc trạng
   thái hiện tại (giới hạn của demo, ghi trong kết quả).
3. Mạo danh người gửi gốc (`anvil_impersonateAccount`), gửi lại đúng to / value / data qua proxy → ghi quyết định,
   điểm R, lý do, độ trễ. Sau đó gửi thẳng vào Anvil (không qua proxy) → ghi số dư đích trước/sau để thấy thiệt hại.

Ca:
- `aave`: 2.580 ETH gửi vào địa chỉ LendingPool của Aave trên Kovan, trên mainnet chưa có code (2020-09-07).
- `pancake`: gọi Router của PancakeSwap trên BSC nhưng ở ETH mainnet (T4 cross-chain, 2021-05-01).
- `truffle`: gửi 1 ETH tới tài khoản mặc định Truffle `0x6273…ef57` (private key công khai, đang ủy quyền 7702 cho
  sweeper) ở block gần nhất; người gửi là tài khoản dev của Anvil.

Không dùng private key nào: Anvil cho mạo danh địa chỉ trên fork cục bộ, không có gì được phát lên mạng thật.
"""

import argparse
import json
import os
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer

import requests

from address_misuse.config import INTERIM_DIR

OUT = INTERIM_DIR / "wallet_demo.json"
TRUFFLE = "0x627306090abab3a6e1400e9345bc60c78a8bef57"
CASES = {
    "aave": {"tx": "0xf58e880e7bc660df9624b55b9e6584934e97fc8c03a308e1b8a4acdd474b37de",
             "desc": "Aave LendingPool (Kovan) dùng trên ETH mainnet, 2.580 ETH"},
    "pancake": {"tx": "0x2084b381b6a1cda77ad58a60ae8084810e34872f884365ce2f116b7f2d961ea0",
                "desc": "PancakeSwap Router (BSC) gọi trên ETH mainnet, 1,2 ETH"},
    "truffle": {"tx": None, "desc": "Gửi 1 ETH tới tài khoản Truffle lộ key (EIP-7702 sweeper)"},
}
ANVIL_PORT, PROXY_PORT = 8546, 8545
ANVIL_DEV0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"      # tài khoản dev #0 của Anvil (đã có số dư trên fork)


class Rpc:
    def __init__(self, url: str):
        self.url, self.s = url, requests.Session()

    def __call__(self, method: str, *params, raw: bool = False, timeout: float = 120):
        r = self.s.post(self.url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)},
                        timeout=timeout).json()
        if raw:
            return r
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]


def start_anvil(anvil: str, fork_rpc: str, block: int | None) -> subprocess.Popen:
    cmd = [anvil, "--fork-url", fork_rpc, "--chain-id", "1", "--port", str(ANVIL_PORT), "--quiet",
           "--no-rate-limit"]
    if block is not None:
        cmd += ["--fork-block-number", str(block)]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rpc = Rpc(f"http://127.0.0.1:{ANVIL_PORT}")
    for _ in range(120):
        if p.poll() is not None:
            raise RuntimeError(f"anvil thoát: {p.stderr.read().decode(errors='replace')[:400]}")
        try:
            rpc("eth_blockNumber", timeout=2)
            return p
        except Exception:
            time.sleep(0.5)
    p.kill()
    raise RuntimeError("anvil không lên sau 60 s")


def start_proxy() -> ThreadingHTTPServer:
    from address_misuse.wallet.online import OnlineStore
    from address_misuse.wallet.proxy import Proxy
    Proxy.store = OnlineStore(timeout=0.3)
    Proxy.store.warm()
    check = Proxy.store.check

    def recorded(*args, **kw):                               # giữ kết quả lần kiểm cuối (cả khi ok/warn, proxy không trả về)
        Proxy.store.last = check(*args, **kw)
        return Proxy.store.last
    Proxy.store.check = recorded
    Proxy.chain, Proxy.upstream = "eth", f"http://127.0.0.1:{ANVIL_PORT}"
    srv = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def value_flows(rpc: Rpc, h: str) -> list[dict]:
    """Các lời gọi có chuyển ETH trong tx (callTracer), để thấy tiền thật sự đi đâu (vd. sweeper chuyển tiếp)."""
    out = []

    def walk(c):
        if int(c.get("value", "0x0"), 16):
            out.append({"from": c["from"], "to": c["to"], "eth": int(c["value"], 16) / 1e18, "type": c["type"]})
        for x in c.get("calls", []):
            walk(x)
    try:
        walk(rpc("debug_traceTransaction", h, {"tracer": "callTracer"}))
    except Exception as e:
        out.append({"error": str(e)[:200]})
    return out


def run_case(name: str, anvil_path: str, fork_rpc: str, proxy: ThreadingHTTPServer) -> dict:
    src = Rpc(fork_rpc)
    c = CASES[name]
    if c["tx"]:
        tx = src("eth_getTransactionByHash", c["tx"])
        block = int(tx["blockNumber"], 16) - 1
        sender, to, value, data = tx["from"], tx["to"], tx["value"], tx["input"]
        fee = {"gasPrice": tx["gasPrice"]}                   # fork trước London: tx legacy với đúng giá gas gốc
    else:
        block = int(src("eth_blockNumber"), 16) - 5
        sender, to, value, data = ANVIL_DEV0, TRUFFLE, hex(10**18), "0x"
        fee = {}
    anvil = start_anvil(anvil_path, fork_rpc, block)
    a = Rpc(f"http://127.0.0.1:{ANVIL_PORT}")
    p = Rpc(f"http://127.0.0.1:{PROXY_PORT}")
    proxy.RequestHandlerClass.store.cache.clear()
    proxy.RequestHandlerClass.store.last = {}           # mỗi ca là một fork mới, không dùng cache ca trước
    try:
        a("anvil_impersonateAccount", sender)
        code_at_fork = a("eth_getCode", to, "latest")
        req = {"from": sender, "to": to, "value": value, "data": data, "gas": hex(3_000_000), **fee}
        before = int(a("eth_getBalance", to, "latest"), 16)
        t = time.perf_counter()
        via = p("eth_sendTransaction", req, raw=True)
        ms = (time.perf_counter() - t) * 1000
        blocked = "error" in via and via["error"].get("code") == 4001
        res = proxy.RequestHandlerClass.store.last
        if blocked:                                          # bị chặn: gửi thẳng vào Anvil để thấy điều sẽ xảy ra
            h = a("eth_sendTransaction", req)
        elif "error" in via:
            raise RuntimeError(f"proxy chuyển tiếp lỗi: {via['error']}")
        else:                                                # proxy cho qua: chính tx này đã vào fork
            h = via["result"]
        rc = None
        for _ in range(20):
            rc = a("eth_getTransactionReceipt", h)
            if rc:
                break
            a("evm_mine")
        after = int(a("eth_getBalance", to, "latest"), 16)
        return {"case": name, "desc": c["desc"], "orig_tx": c["tx"], "fork_block": block,
                "target": to, "value_eth": int(value, 16) / 1e18,
                "target_code_at_fork": "7702" if code_at_fork.startswith("0xef0100") else
                ("code" if code_at_fork not in ("0x", "0x0") else "none"),
                "proxy_blocked": blocked, "proxy_ms": round(ms, 1),
                "decision": res.get("decision"), "score": round(res["score"], 2) if res.get("score") is not None else None,
                "engine_ms": res.get("ms_total"),
                "hard_rule": res.get("hard_rule"), "types": res.get("types"), "reasons": res.get("reasons", [])[:4],
                "missed_nets": res.get("missed_nets"),
                "direct_status": int(rc["status"], 16), "value_flows": value_flows(a, h), "target_balance_delta_eth": (after - before) / 1e18}
    finally:
        anvil.kill()
        anvil.wait()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--anvil", default=os.environ.get("ANVIL", "anvil"))
    ap.add_argument("--fork-rpc", default="https://eth.drpc.org", help="RPC ETH có dữ liệu lưu trữ (archive)")
    ap.add_argument("--case", default="all", choices=["all", *CASES])
    a = ap.parse_args()
    os.environ["RPC_ETH"] = f"http://127.0.0.1:{ANVIL_PORT}"     # engine đọc code ETH từ fork (trạng thái lúc tx gốc)
    proxy = start_proxy()
    out = []
    for name in (CASES if a.case == "all" else [a.case]):
        r = run_case(name, a.anvil, a.fork_rpc, proxy)
        out.append(r)
        print(f"[{name}] {r['desc']}\n  fork block {r['fork_block']}, đích lúc đó: {r['target_code_at_fork']}\n"
              f"  qua proxy: {'CHẶN' if r['proxy_blocked'] else 'cho qua'} ({r['decision']}, R={r['score']}, "
              f"{r['hard_rule'] or '-'}, {r['proxy_ms']} ms) {r['reasons'][:2]}\n"
              f"  {'gửi thẳng' if r['proxy_blocked'] else 'đã gửi'}: status {r['direct_status']}, số dư đích thay đổi "
              f"{r['target_balance_delta_eth']:+.4f} ETH, dòng ETH {r['value_flows']}",
              flush=True)
    proxy.shutdown()
    OUT.write_text(json.dumps({"note": "code ETH đọc từ fork; các mạng khác, 7702 và bảng tra là trạng thái hiện tại",
                               "cases": out}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"ghi {OUT}")


if __name__ == "__main__":
    main()
