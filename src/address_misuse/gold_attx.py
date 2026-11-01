"""Delegate EIP-7702 lúc tx (CODEBOOK ca 13, v0.6.4): với mỗi mẫu có thể là 7702, lấy danh sách ủy quyền (authorizationList)
của tx mẫu, khôi phục người ký (secp256k1) và giữ các ủy quyền của CHÍNH địa chỉ mẫu. Kết quả `data/gold/delegate_attx.csv`
(item_id, chain, address, delegate, nonce, auth_chain_id, n_auth_in_tx) để bảng `delegate_lookup.csv` có cả delegate đứng đích
trong tx mẫu, không chỉ delegate hôm nay. Không chứa nhãn. Chạy lại được; tx đã tra thì bỏ qua (cache JSON trong data/interim).

    python -X utf8 -m address_misuse.gold_attx fetch
"""
from __future__ import annotations

import json
import os
import time

import pandas as pd
import requests
from Crypto.Hash import keccak

from address_misuse.gold_evidence import NODEREAL_URL

_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def keccak256(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    lam = (3 * a[0] * a[0]) * pow(2 * a[1], -1, _P) % _P if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _rlp_int(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b if len(b) == 1 and b[0] < 0x80 else bytes([0x80 + len(b)]) + b


def _rlp_bytes(b: bytes) -> bytes:
    return b if len(b) == 1 and b[0] < 0x80 else bytes([0x80 + len(b)]) + b


def _rlp_list(items: list[bytes]) -> bytes:
    body = b"".join(items)
    if len(body) < 56:
        return bytes([0xC0 + len(body)]) + body
    ln = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(ln)]) + ln + body


def auth_digest(chain_id: int, delegate: str, nonce: int) -> bytes:
    """EIP-7702: keccak(0x05 || rlp([chain_id, address, nonce]))."""
    return keccak256(b"\x05" + _rlp_list([_rlp_int(chain_id), _rlp_bytes(bytes.fromhex(delegate[2:])), _rlp_int(nonce)]))


def recover_authority(a: dict) -> str:
    """Địa chỉ người ký một ủy quyền {chainId, address, nonce, yParity, r, s} (số hex)."""
    h = auth_digest(int(a["chainId"], 16), a["address"], int(a["nonce"], 16))
    r, s, v = int(a["r"], 16), int(a["s"], 16), int(a.get("yParity", a.get("v", "0x0")), 16)
    y = pow((pow(r, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if y % 2 != v:
        y = _P - y
    e, ri = int.from_bytes(h, "big"), pow(r, -1, _N)
    q = _add(_mul(s * ri % _N, (r, y)), _mul((-e * ri) % _N, _G))
    return "0x" + keccak256(q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big"))[-20:].hex()


def own_authorizations(address: str, tx: dict) -> list[dict]:
    """Các ủy quyền trong tx do chính `address` ký: [{delegate, nonce, auth_chain_id}] (không xét có hiệu lực hay không)."""
    out = []
    for a in tx.get("authorizationList") or []:
        try:
            who = recover_authority(a)
        except Exception:                                  # chữ ký hỏng: bỏ, tx không áp dụng được
            continue
        if who == address.lower():
            out.append({"delegate": a["address"].lower(), "nonce": int(a["nonce"], 16), "auth_chain_id": int(a["chainId"], 16)})
    return out


def _get_tx(chain: str, tx_hash: str) -> dict | None:
    for _ in range(6):
        try:
            if chain == "bsc":
                url = NODEREAL_URL["bsc"].format(os.environ["NODEREAL_API_KEY"])
                r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionByHash", "params": [tx_hash]}, timeout=60).json()
            else:
                r = requests.get("https://api.etherscan.io/v2/api", params=dict(
                    chainid=1, module="proxy", action="eth_getTransactionByHash", txhash=tx_hash, apikey=os.environ["ETHERSCAN_API_KEY"]), timeout=40).json()
            res = r.get("result")
            if isinstance(res, dict):
                return res
            if res is None and "error" not in r:
                return None
        except requests.RequestException:
            pass
        time.sleep(1.5)
    return None


def candidates(items: pd.DataFrame) -> pd.DataFrame:
    """Mẫu có thể đã ủy quyền 7702: code_at_event là 7702 / unknown hoặc có delegate hôm nay."""
    return items[items.code_at_event.isin(["7702", "unknown"]) | (items.delegate_7702 != "-")]


def build(items: pd.DataFrame, cache: dict | None = None) -> tuple[pd.DataFrame, dict]:
    cache = {} if cache is None else cache
    rows = []
    for _, r in candidates(items).iterrows():
        j = cache.get(r.item_id)
        if j is None:
            tx = _get_tx(r.chain, r.tx_hash)
            if tx is None:
                continue
            j = {"n_auth": len(tx.get("authorizationList") or []), "mine": own_authorizations(r.address, tx)}
            cache[r.item_id] = j
        for m in j["mine"]:
            rows.append({"item_id": r.item_id, "chain": r.chain, "address": r.address, **m, "n_auth_in_tx": j["n_auth"]})
    cols = ["item_id", "chain", "address", "delegate", "nonce", "auth_chain_id", "n_auth_in_tx"]
    return pd.DataFrame(rows, columns=cols), cache


if __name__ == "__main__":
    import sys
    from pathlib import Path

    from dotenv import load_dotenv

    gold = Path(__file__).resolve().parents[2] / "data" / "gold"
    cache_p = Path(__file__).resolve().parents[2] / "data" / "interim" / "attx_cache.json"
    if len(sys.argv) < 2 or sys.argv[1] != "fetch":
        raise SystemExit(__doc__)
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    items = pd.read_csv(gold / "main_items.csv", dtype=str).fillna("-")
    cache = json.loads(cache_p.read_text(encoding="utf-8")) if cache_p.exists() else {}
    t, cache = build(items, cache)
    cache_p.parent.mkdir(parents=True, exist_ok=True)
    cache_p.write_text(json.dumps(cache), encoding="utf-8")
    t.to_csv(gold / "delegate_attx.csv", index=False, lineterminator="\n")
    print(f"{len(t)} ủy quyền của chính địa chỉ, {t.delegate.nunique()} delegate → {gold / 'delegate_attx.csv'}")
