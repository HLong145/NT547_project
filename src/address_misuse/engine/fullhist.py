"""Lịch sử tài sản ĐẦY ĐỦ của một EOA (coin, internal, ERC-20, ERC-721, ERC-1155) và đếm "rút nhanh" theo CODEBOOK §3.4.

Engine v1 chỉ xem 1.000 tx thường (coin) gần nhất trước `at` (`features.HISTORY_WINDOW`), nên bỏ sót sweeper rút token / NFT
và sweeper hoạt động sau `at`. Module này phục vụ engine v2 (docs/GOLD_PROTOCOL.md §8, tiền đăng ký v2):

- ETH: Etherscan V2 `account/{txlist, txlistinternal, tokentx, tokennfttx, token1155tx}`, trượt `startblock` theo trang 1.000.
- BSC: NodeReal `nr_getAssetTransfers` (cả chiều đi và đến, theo `pageKey`).
- Cache gzip ở `data/raw/<chain>/fullhist/<address>.json.gz`. Tối đa `MAX_EVENTS` sự kiện mỗi loại; vượt thì `truncated`.

Rút nhanh (`fast_withdrawals`): một lần nhận tài sản X (từ ví khác) và trong ≤ `WINDOW_S` giây có một lần chuyển X ra, lượng ra
(cộng phí gas nếu là coin và phí biết được) ∈ [`MIN_RATIO`, `MAX_RATIO`] × lượng vào, tới ví khác ví đã gửi, và tx rút không đem
tài sản nào về lại địa chỉ (loại swap; CODEBOOK ca 7d). Engine không đọc nhãn sàn của explorer (ca 7a), nên đếm cả rút về sàn.

    python -X utf8 -m address_misuse.engine.fullhist fetch <chain> <address> ...
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import time

import requests

from address_misuse.config import RAW_DIR

WINDOW_S = 600
MIN_RATIO, MAX_RATIO = 0.90, 1.02
MAX_EVENTS = 20_000
ES_ACTIONS = ("txlist", "txlistinternal", "tokentx", "tokennfttx", "token1155tx")
_s = requests.Session()


def path(chain: str, address: str):
    return RAW_DIR / chain / "fullhist" / f"{address.lower()}.json.gz"


def _es(**p) -> dict:
    p.update(chainid=1, apikey=os.environ["ETHERSCAN_API_KEY"])
    r = {}
    for _ in range(8):
        try:
            r = _s.get("https://api.etherscan.io/v2/api", params=p, timeout=60).json()
        except (requests.RequestException, ValueError):
            time.sleep(3)
            continue
        if "rate limit" in str(r.get("result", ""))[:80].lower():
            time.sleep(1.5)
            continue
        return r
    return r


def _eth(a: str) -> tuple[list[dict], bool]:
    out, trunc = [], False
    for act in ES_ACTIONS:
        start, got, seen = 0, 0, set()
        while True:
            r = _es(module="account", action=act, address=a, startblock=start, endblock=99_999_999, page=1, offset=1000,
                    sort="asc")
            res = r.get("result")
            if not isinstance(res, list):
                if r.get("message") not in ("No transactions found", "No records found"):
                    raise RuntimeError(f"etherscan {act} {a}: {str(r)[:200]}")
                break
            new = 0
            for t in res:
                k = (t["hash"], t.get("from"), t.get("to"), t.get("contractAddress"), t.get("tokenID"), t.get("value"),
                     t.get("traceId"), t.get("logIndex"))
                if k in seen:
                    continue
                seen.add(k)
                new += 1
                if act == "txlist" and t.get("isError") == "1":
                    continue
                if act == "txlistinternal" and t.get("isError") == "1":
                    continue
                nat = act in ("txlist", "txlistinternal")
                if act == "tokentx":
                    amt = int(t.get("value") or 0) / 10 ** int(t.get("tokenDecimal") or 0)
                elif nat:
                    amt = int(t.get("value") or 0) / 1e18
                else:
                    amt = float(int(t.get("tokenValue") or 1)) if act == "token1155tx" else 1.0
                asset = "NATIVE" if nat else t["contractAddress"].lower() + ("" if act == "tokentx" else "#" + t.get("tokenID", ""))
                fee = (int(t["gasUsed"]) * int(t["gasPrice"]) / 1e18
                       if act == "txlist" and t["from"].lower() == a else 0.0)
                out.append({"ts": int(t["timeStamp"]), "block": int(t["blockNumber"]), "frm": t["from"].lower(),
                            "to": (t.get("to") or "").lower(), "hash": t["hash"].lower(), "amt": amt, "asset": asset,
                            "fee": fee})
            got += new
            time.sleep(0.22)
            if len(res) < 1000 or new == 0:
                break
            if got >= MAX_EVENTS:
                trunc = True
                break
            start = int(res[-1]["blockNumber"])               # trang kế: từ block cuối (trùng lặp đã loại bằng `seen`)
    return out, trunc


def _nr(params: dict) -> dict:
    from address_misuse.gold_evidence import NODEREAL_URL
    url = NODEREAL_URL["bsc"].format(os.environ["NODEREAL_API_KEY"])
    for _ in range(6):
        try:
            return _s.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "nr_getAssetTransfers", "params": [params]},
                           timeout=90).json()
        except (requests.RequestException, ValueError):
            time.sleep(3)
    raise RuntimeError("NodeReal nr_getAssetTransfers lỗi liên tục")


def _num(v) -> int:
    return int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v or 0)


def _bsc(a: str) -> tuple[list[dict], bool]:
    out, trunc, seen = [], False, set()
    for side in ("fromAddress", "toAddress"):
        key, got = None, 0
        while True:
            p = {"category": ["external", "internal", "20", "721", "1155"], side: a, "maxCount": "0x3e8", "order": "asc",
                 "withMetadata": True}
            if key:
                p["pageKey"] = key
            r = _nr(p)
            if "error" in r:
                raise RuntimeError(f"NodeReal {a}: {r['error']}")
            res = r.get("result") or {}
            for t in res.get("transfers", []):
                cat, v = t["category"], t.get("value") or "0"
                nat = cat in ("external", "internal")
                asset = "NATIVE" if nat else (t.get("contractAddress") or "").lower() + (
                    "#" + str(t.get("tokenId", "")) if cat in ("721", "1155") else "")
                if cat == "721":
                    amt = 1.0
                elif isinstance(v, str) and v.startswith("0x"):
                    dec = t.get("decimal")
                    amt = int(v, 16) / 10 ** (_num(dec) if dec is not None else (18 if nat else 0))
                else:
                    try:
                        amt = float(v)
                    except (TypeError, ValueError):
                        amt = 0.0
                d = {"ts": _num(t.get("blockTimeStamp")), "block": _num(t.get("blockNum")), "frm": (t.get("from") or "").lower(),
                     "to": (t.get("to") or "").lower(), "hash": (t.get("hash") or "").lower(), "amt": amt, "asset": asset,
                     "fee": 0.0}
                k = (d["hash"], d["frm"], d["to"], d["asset"], str(v), cat)
                if k not in seen:
                    seen.add(k)
                    out.append(d)
            got += len(res.get("transfers", []))
            key = res.get("pageKey")
            time.sleep(0.25)
            if not key:
                break
            if got >= MAX_EVENTS:
                trunc = True
                break
    return out, trunc


def fetch(chain: str, address: str, refresh: bool = False) -> dict:
    """{"events": [...], "truncated": bool, "fetched": ts}. Đọc cache nếu có."""
    p = path(chain, address)
    if p.exists() and not refresh:
        with gzip.open(p, "rt", encoding="utf-8") as f:
            return json.load(f)
    a = address.lower()
    ev, trunc = (_eth if chain == "eth" else _bsc)(a)
    ev.sort(key=lambda e: (e["ts"], e["block"]))
    j = {"events": ev, "truncated": trunc, "fetched": int(time.time())}
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt", encoding="utf-8") as f:
        json.dump(j, f)
    return j


def load(chain: str, address: str) -> dict | None:
    p = path(chain, address)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return json.load(f)


def fast_withdrawals(events: list[dict], address: str, window: int = WINDOW_S, lo: float = MIN_RATIO,
                     hi: float = MAX_RATIO) -> list[dict]:
    """Các lần rút nhanh: [{in_ts, out_ts, asset, amt_in, amt_out, to, hash_out}]. Mỗi lần chuyển ra chỉ dùng một lần."""
    a = address.lower()
    ins = [e for e in events if e["to"] == a and e["frm"] != a and e["amt"] > 0]
    outs = [e for e in events if e["frm"] == a and e["to"] != a]
    back = {e["hash"] for e in ins}                          # tx có đem tài sản về lại địa chỉ
    by_asset: dict[str, list[dict]] = {}
    for o in outs:
        by_asset.setdefault(o["asset"], []).append(o)
    used, res = set(), []
    for i in ins:
        for o in by_asset.get(i["asset"], []):
            if o["ts"] < i["ts"]:
                continue
            if o["ts"] > i["ts"] + window:
                break
            k = (o["hash"], o["to"], o["asset"], o["amt"])
            if k in used or o["hash"] == i["hash"] or o["hash"] in back or o["to"] == i["frm"]:
                continue
            r = (o["amt"] + (o.get("fee") or 0.0 if o["asset"] == "NATIVE" else 0.0)) / i["amt"]
            if lo <= r <= hi:
                used.add(k)
                res.append({"in_ts": i["ts"], "out_ts": o["ts"], "asset": i["asset"], "amt_in": i["amt"],
                            "amt_out": o["amt"], "to": o["to"], "hash_out": o["hash"]})
                break
    return res


def fetch_items(items_csv: str, chain: str | None = None) -> None:
    """Tải lịch sử cho mọi mẫu không có code lúc tx (code_at_event ∉ {code, destroyed}) của một file *_items.csv."""
    import pandas as pd
    it = pd.read_csv(items_csv, dtype=str).fillna("-")
    it = it[~it.code_at_event.isin(["code", "destroyed"])].drop_duplicates(["chain", "address"])
    if chain:
        it = it[it.chain == chain]
    err = 0
    for n, r in enumerate(it.itertuples(index=False), 1):
        if path(r.chain, r.address).exists():
            continue
        try:
            j = fetch(r.chain, r.address)
            print(f"[{n}/{len(it)}] {r.item_id} {r.chain} {len(j['events'])}{' (cắt)' if j['truncated'] else ''}", flush=True)
        except Exception as e:                               # lỗi API: bỏ qua, chạy lại sau (cache giữ phần đã tải)
            err += 1
            print(f"[{n}/{len(it)}] {r.item_id} lỗi: {str(e)[:150]}", flush=True)
    print(f"xong, {err} lỗi")


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "fetch-items":
        fetch_items(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
        raise SystemExit(0)
    if len(sys.argv) < 4 or sys.argv[1] != "fetch":
        raise SystemExit(__doc__)
    ch = sys.argv[2]
    for ad in sys.argv[3:]:
        j = fetch(ch, ad)
        fw = fast_withdrawals(j["events"], ad)
        print(ch, ad, len(j["events"]), "sự kiện", "(cắt)" if j["truncated"] else "", len(fw), "lần rút nhanh")
