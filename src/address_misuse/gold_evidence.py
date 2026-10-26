"""D5 — bằng chứng theo thời điểm cho mẫu vàng chính, tính CÙNG MỘT CÁCH cho mọi mẫu (CODEBOOK v0.6, GOLD_PROTOCOL §3).

Bản v0.5 lấy ngày tạo contract từ `engine_creation.parquet`, file chỉ phủ +PCD và -N5: cột `own_create_date` chỉ có ở hai tầng đó,
và `code_at_event` của các mẫu có code khác thật ra là trạng thái HÔM NAY. Bản này tra lại cho mọi mẫu bằng cùng một nguồn:

- tx tại `at` (theo `tx_hash`): block, vị trí trong block, calldata, trạng thái.
  ETH: RPC công khai (`eth_getTransactionByHash`) + Etherscan `transaction.getstatus`; BSC: NodeReal (tx + receipt).
- contract trên chain của mẫu: ETH Etherscan V2 `getcontractcreation`, BSC NodeReal `nr_getContractCreationTransaction`,
  cho MỌI mẫu (kể cả EOA và địa chỉ hôm nay không có code: có thể là contract đã tự huỷ).
- contract cùng địa chỉ ở mạng khác (`xc_*`): creation trên MỌI mạng đang có code, cho mọi mẫu mà chain này không có code lúc tx.
  Mạng không có nguồn creation miễn phí (op, base, bsc_testnet) → 'unknown' cho mọi mẫu như nhau.

Lỗi tra cứu không bao giờ được thay bằng nguồn khác chỉ có ở một số tầng: lỗi → 'unknown'.
Cache (data/raw/gold/, gitignore): chạy lại không gọi API lần nữa; lỗi không được cache nên lần sau tra lại.
"""

import json
import os
import time
from datetime import datetime, timezone

import requests

from address_misuse.config import EIP7702_ACTIVATION_TS, RAW_DIR
from address_misuse.rules import is_hex_readable

CACHE_DIR = RAW_DIR / "gold"
TX_CACHE = CACHE_DIR / "v06_event_tx.jsonl"
CREATION_CACHE = CACHE_DIR / "v06_creation.jsonl"
ETHERSCAN_CREATION_NETS = ("eth", "arb", "polygon", "sepolia")     # gói miễn phí hỗ trợ getcontractcreation
NODEREAL_URL = {"bsc": "https://bsc-mainnet.nodereal.io/v1/{}"}
SLEEP = 0.25                                                        # ~4 lệnh/giây cho NodeReal / RPC công khai
_session = requests.Session()


# ---------------------------------------------------------------- hàm thuần (có test)

def utc(ts) -> str | None:
    """Giờ UTC dạng 'YYYY-MM-DD HH:MM:SS' (đủ giây, để so tx với lúc tạo contract mà không bị trùng ngày)."""
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def calldata_len(inp: str | None) -> int | None:
    """Số byte calldata (0 khi chuyển coin thuần). None = không tra được tx. Lời gọi hàm chuẩn ABI có 4 + 32k byte;
    đúng 32 byte là một từ dữ liệu (ví dụ event topic), không phải dạng selector + tham số."""
    if inp is None:
        return None
    h = inp[2:] if inp.startswith("0x") else inp
    return len(h) // 2


def calldata_kind(inp: str | None) -> str | None:
    """'-' khi không có calldata (chuyển coin thuần); 'text' khi calldata đọc được thành văn bản (cùng hàm
    `is_hex_readable` mà luật NCD/PCD của tác giả dùng để loại tx); 'call' khi có ≥ 4 byte và không phải văn bản;
    'short' khi 1–3 byte. None = không tra được tx."""
    if inp is None:
        return None
    if inp in ("0x", ""):
        return "-"
    if is_hex_readable(inp):
        return "text"
    return "call" if len(inp) >= 10 else "short"


def token_recipient(inp: str | None) -> str | None:
    """Người nhận trong transfer(to, amount) / transferFrom(from, to, amount) chuẩn ERC-20; None nếu không phải hai hàm này."""
    if not inp:
        return None
    if inp.startswith("0xa9059cbb") and len(inp) >= 10 + 64:
        return "0x" + inp[10 + 24:10 + 64].lower()
    if inp.startswith("0x23b872dd") and len(inp) >= 10 + 128:
        return "0x" + inp[10 + 64 + 24:10 + 128].lower()
    return None


def _before(c: dict, ev: dict) -> bool | None:
    """Contract được tạo TRƯỚC tx tại `at`? So (block, vị trí trong block); cùng block mà thiếu vị trí → None."""
    if c.get("block") is None or ev.get("block") is None:
        return None
    if c["block"] != ev["block"]:
        return c["block"] < ev["block"]
    if c.get("index") is None or ev.get("index") is None:
        return None
    return c["index"] < ev["index"]


def _same_tx(c: dict, ev: dict) -> bool:
    """Contract được tạo NGAY TRONG tx tại `at` (cùng hash, hoặc cùng block và cùng vị trí)."""
    if c.get("tx_hash") and ev.get("hash") and str(c["tx_hash"]).lower() == str(ev["hash"]).lower():
        return True
    return (c.get("block") is not None and c.get("block") == ev.get("block")
            and c.get("index") is not None and c.get("index") == ev.get("index"))


def state_at_event(chain: str, own_now: str | None, at_ts: int, ev: dict | None, creation: dict | None) -> str:
    """Trạng thái code của địa chỉ trên chain của mẫu, ngay trước tx tại `at` — một quy tắc cho mọi mẫu:

    - getCode hôm nay lỗi → 'unknown'.
    - Hôm nay là ủy quyền 7702: 'none' nếu tx trước khi EIP-7702 kích hoạt trên chain, ngược lại '7702'
      (ủy quyền có thể được đặt SAU tx: không tra được lúc đặt, ghi trong hạn chế).
    - Có bản ghi tạo contract: tạo trước tx → 'code' (hôm nay còn code) hoặc 'destroyed' (hôm nay hết code: đã tự huỷ,
      không rõ lúc nào); tạo sau tx → 'none'; cùng block mà không rõ thứ tự → 'unknown'.
      Tạo NGAY TRONG tx tại `at` → 'unknown' (không phải 'none'/PCD): khi `to` của tx là chính địa chỉ thì điều này không thể
      xảy ra, nên đây là dấu hiệu dữ liệu sai; người gán tự xem explorer.
    - Không có bản ghi tạo contract (tra được, kết quả rỗng): hôm nay không code → 'none'; hôm nay có code → 'unknown'.
    - Tra creation lỗi / không có nguồn → 'unknown'.
    """
    if own_now not in ("none", "code", "7702"):
        return "unknown"
    if own_now == "7702":
        return "none" if at_ts < EIP7702_ACTIVATION_TS.get(chain, 0) else "7702"
    st = (creation or {}).get("status")
    if st == "found":
        if _same_tx(creation, ev or {}):
            return "unknown"
        before = _before(creation, ev or {})
        if before is None:
            return "unknown"
        if not before:
            return "none"
        return "code" if own_now == "code" else "destroyed"
    if st == "not_found":
        return "none" if own_now == "none" else "unknown"
    return "unknown"


def xc_fields(at_ts: int, xc_nets: list[str], creations: dict) -> dict:
    """Contract cùng địa chỉ ở mạng khác, so với tx tại `at` (KHÔNG so với tx đầu tiên):

    - 'before' nếu có ít nhất một mạng tạo contract trước `at` (so giây UTC, trùng giây không tính là trước);
    - 'unknown' nếu không có mạng nào 'before' và có mạng không tra được ngày tạo;
    - 'after' nếu mọi mạng đều tạo sau (hoặc đúng giây của) `at`.
    `origin_net`, `deployer`, `xc_create_time` lấy từ mạng tạo sớm nhất đã biết. Genesis/predeploy tính là ts 0.
    `creations`: {mạng: bản ghi creation của địa chỉ này trên mạng đó}."""
    known, unknown = [], []
    for n in xc_nets:
        c = creations.get(n) or {}
        if c.get("status") == "found" and c.get("ts") is not None:
            known.append((int(c["ts"]), n, c.get("creator")))
        else:
            unknown.append(n)
    known.sort()
    timing = ("before" if known and known[0][0] < int(at_ts) else "unknown" if unknown else "after")
    first = known[0] if known else None
    return {"xc_timing": timing, "origin_net": first[1] if first else None, "deployer": first[2] if first else None,
            "xc_create_time": utc(first[0]) if first else None,
            "xc_net_link": first[1] if first else (xc_nets[0] if xc_nets else None)}


# ---------------------------------------------------------------- tra cứu (mạng)

def _read(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _nodereal(chain: str, calls: list[tuple[str, list]], retries: int = 4) -> tuple[list, list[bool]]:
    """JSON-RPC batch tới NodeReal. Trả (kết quả, ok): `ok[i]` False khi phần tử i vẫn lỗi sau `retries` lần (kết quả None);
    `ok[i]` True với kết quả None nghĩa là NodeReal trả rỗng (ví dụ không có tx tạo contract)."""
    key = os.environ.get("NODEREAL_API_KEY")
    if not key:
        raise SystemExit("thiếu NODEREAL_API_KEY trong .env (cần cho BSC)")
    url = NODEREAL_URL[chain].format(key)
    out = [None] * len(calls)
    todo = list(range(len(calls)))
    for attempt in range(retries):
        body = [{"jsonrpc": "2.0", "id": i, "method": calls[i][0], "params": calls[i][1]} for i in todo]
        try:
            r = _session.post(url, json=body, timeout=60)
            if r.status_code == 429:
                raise RuntimeError("429")
            data = r.json()
            for x in data if isinstance(data, list) else []:
                if "result" in x and isinstance(x.get("id"), int):
                    out[x["id"]] = {"ok": True, "result": x["result"]}
            todo = [i for i in todo if out[i] is None]
            if not todo:
                break
        except Exception:
            pass
        time.sleep(2 * 2 ** attempt)
    return [x["result"] if x else None for x in out], [x is not None for x in out]


def fetch_event_txs(pairs: list[tuple[str, str]]) -> dict:
    """{(chain, hash): {block, index, input, from, to, value, status}}; status 1 = thành công, 0 = lỗi.
    Tx không tra được thì không có trong kết quả (→ các cột theo tx ghi 'unknown' / '-')."""
    from address_misuse.crosschain_matrix import rpc_batch
    from address_misuse.etherscan import Etherscan
    have = {(r["chain"], r["hash"]): r for r in _read(TX_CACHE) if "value" in r}
    todo = sorted({p for p in pairs if p not in have})
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with TX_CACHE.open("a", encoding="utf-8") as f:
        for chain in sorted({c for c, _ in todo}):
            hs = [h for c, h in todo if c == chain]
            for i in range(0, len(hs), 20):
                part = hs[i:i + 20]
                if chain in NODEREAL_URL:
                    txs, _ = _nodereal(chain, [("eth_getTransactionByHash", [h]) for h in part])
                    rcs, _ = _nodereal(chain, [("eth_getTransactionReceipt", [h]) for h in part])
                    status = [None if not rc or rc.get("status") is None else int(rc["status"], 16) for rc in rcs]
                else:
                    try:
                        txs = rpc_batch(chain, [("eth_getTransactionByHash", [h]) for h in part])
                    except Exception:
                        txs = [None] * len(part)
                    es = Etherscan(chain)
                    status = []
                    for h in part:                       # getstatus đúng cả trước Byzantium (receipt chưa có status)
                        try:
                            status.append(1 - int(es.call("transaction", "getstatus", txhash=h)["result"]["isError"]))
                        except Exception:
                            status.append(None)
                for h, t, s in zip(part, txs, status):
                    if not t or s is None:
                        continue                         # lỗi: không cache, lần sau tra lại
                    rec = {"chain": chain, "hash": h, "block": int(t["blockNumber"], 16),
                           "index": int(t["transactionIndex"], 16), "input": t.get("input") or "0x", "status": s,
                           "from": (t.get("from") or "").lower(), "to": (t.get("to") or "").lower(),
                           "value": str(int(t.get("value") or "0x0", 16))}
                    have[(chain, h)] = rec
                    f.write(json.dumps(rec) + "\n")
                f.flush()
                time.sleep(SLEEP)
    return have


def _creation_record(net: str, a: str, raw: dict | None) -> dict:
    if not raw:
        return {"net": net, "address": a, "status": "not_found"}
    tx = raw.get("txHash") or raw.get("hash") or ""
    genesis = not str(tx).startswith("0x")
    ts = 0 if genesis else int(raw["timestamp"])
    block = 0 if genesis else int(raw["blockNumber"])
    idx = raw.get("transactionIndex")
    return {"net": net, "address": a, "status": "found", "ts": ts, "block": block,
            "index": None if idx is None else int(idx), "tx_hash": tx,
            "creator": (raw.get("contractCreator") or raw.get("from") or "").lower() or None,
            "factory": (raw.get("contractFactory") or "").lower() or None}


def parse_etherscan_creation(data: dict, addrs: list[str]) -> dict | None:
    """Đọc phản hồi `getcontractcreation` một cách tường minh: {địa chỉ: bản ghi thô} cho các địa chỉ là contract.
    - status '1' và result là list → các bản ghi (địa chỉ không có trong list = không phải contract);
    - status '0' với message 'No data found' (không địa chỉ nào là contract) → {};
    - mọi dạng khác → None (lỗi: không cache, không suy ra 'not_found')."""
    res, msg = data.get("result"), str(data.get("message", ""))
    if str(data.get("status")) == "1" and isinstance(res, list):
        want = {a.lower() for a in addrs}
        return {r["contractAddress"].lower(): r for r in res
                if isinstance(r, dict) and str(r.get("contractAddress", "")).lower() in want}
    if str(data.get("status")) == "0" and msg.lower().startswith("no data found"):
        return {}
    return None


def fetch_creations(pairs: list[tuple[str, str]]) -> dict:
    """{(net, address): bản ghi}; status 'found' / 'not_found' / 'no_api'. Lỗi mạng: không có trong kết quả (→ unknown)."""
    from address_misuse.etherscan import Etherscan
    have = {(r["net"], r["address"]): r for r in _read(CREATION_CACHE)}
    todo = sorted({p for p in pairs if p not in have})
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with CREATION_CACHE.open("a", encoding="utf-8") as f:
        def put(rec):
            have[(rec["net"], rec["address"])] = rec
            f.write(json.dumps(rec) + "\n")
        for net in sorted({n for n, _ in todo}):
            addrs = [a for n, a in todo if n == net]
            if net in ETHERSCAN_CREATION_NETS:
                es = Etherscan(net)
                for i in range(0, len(addrs), 5):
                    part = addrs[i:i + 5]
                    try:
                        got = parse_etherscan_creation(
                            es.call("contract", "getcontractcreation", contractaddresses=",".join(part)), part)
                    except Exception as e:
                        got, err = None, str(e)[:80]
                    else:
                        err = "phản hồi lạ"
                    if got is None:
                        print(f"  {net} getcontractcreation lỗi ({err}), {len(part)} địa chỉ → unknown", flush=True)
                        continue
                    for a in part:
                        put(_creation_record(net, a, got.get(a)))
                    f.flush()
            elif net in NODEREAL_URL:
                for i in range(0, len(addrs), 10):
                    part = addrs[i:i + 10]
                    res, ok = _nodereal(net, [("nr_getContractCreationTransaction", [a]) for a in part])
                    for a, r, k in zip(part, res, ok):
                        if k:
                            put(_creation_record(net, a, r))
                    f.flush()
                    time.sleep(SLEEP)
            else:
                for a in addrs:
                    put({"net": net, "address": a, "status": "no_api"})
    return have


def creation_index(chain: str, rec: dict) -> dict:
    """Bổ sung vị trí trong block của tx tạo contract (chỉ cần khi cùng block với tx tại `at`)."""
    if rec.get("status") != "found" or rec.get("index") is not None or not str(rec.get("tx_hash", "")).startswith("0x"):
        return rec
    got = fetch_event_txs([(chain, rec["tx_hash"])]).get((chain, rec["tx_hash"]))
    return {**rec, "index": got["index"]} if got else rec
