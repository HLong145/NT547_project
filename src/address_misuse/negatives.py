"""D4 — tập âm N1–N4, N6, N8 (N7: known_multichain.py). Định nghĩa: docs/PLAN_V2.md §D4.

python -X utf8 -m address_misuse.negatives n1 [--per-chain 200 --seed 0]   → data/interim/n1_random_unflagged.parquet
python -X utf8 -m address_misuse.negatives n6                              → data/interim/n6_benign_7702_delegates.parquet
python -X utf8 -m address_misuse.negatives scan [--period recent|early]    → data/raw/<chain>/block_scan[_early].parquet
python -X utf8 -m address_misuse.negatives from-scan [--per-chain 400]     → n8_normal_txs, n2_contract_calls,
                                                                              n3_text_messages (.parquet)
python -X utf8 -m address_misuse.negatives n4 [--per-chain 200]            → data/interim/n4_exchange_deposits.parquet
python -X utf8 -m address_misuse.negatives n4-verify                       (sau engine.prepare history) → cột `kept`

N1: địa chỉ ứng viên của tác giả (cùng nguồn GitHub/StackExchange, có tx) mà rule KHÔNG gắn cờ → đo recall / tìm FN.
    Kèm trạng thái code hiện tại trên chính chain (EOA / contract / 7702) để chia tầng khi gán nhãn.
N6: implementation smart wallet EIP-7702 hợp lệ (MetaMask, Coinbase, Uniswap, Ambire, eth-infinitism). Mỗi ứng viên
    được KIỂM CHỨNG: tên contract đã verify trên Blockscout (không cần key) phải khớp và có code trên ETH.
    Cột `in_author_delegate_set` chỉ để tham khảo: tập symexec_results kind = eip7702_delegate của tác giả là
    MỌI delegate đã phân tích (kể cả ví hợp lệ như MetaMask), không phải tập delegate độc.
    Lưu ý: dữ liệu tác giả KHÔNG có EOA ủy quyền lành tính (mọi delegation đều từ EOA lộ key/ADDR) → EOA cho N6
    cần lấy từ dữ liệu on-chain mới (BigQuery, D1).
N8/N2/N3: tx trong block ngẫu nhiên (đợt "recent" 2023-01 → nay, "early" 2020–2022) — mức tx, đích là `target`,
    ngữ cảnh là value + input.
    N8 = 1 tx ngẫu nhiên mỗi block; N2 = gọi contract (có code) bằng selector hay gặp trong misuse;
    N3 = input là văn bản đọc được, gửi tới EOA. Trạng thái code của đích là trạng thái HIỆN TẠI.
N4: địa chỉ nạp sàn (EOA chuyển coin về ví nóng sàn). Sau khi có lịch sử, `n4-verify` chỉ giữ địa chỉ có hành vi
    địa chỉ nạp (≥ 90% tx gửi đi là về hub, mang ≥ 90% coin đã nhận); phần lớn người gửi tới hub là người dùng thường.
"""

import argparse
import gzip
import json
import random
import time

import pandas as pd
import requests

from address_misuse.config import INTERIM_DIR, NETWORKS, RAW_DIR, SEED_DIR
from address_misuse.crosschain_matrix import _code_record, rpc_batch
from address_misuse.rules import is_hex_readable

BLOCKSCOUT = "https://eth.blockscout.com/api/v2/smart-contracts/{}"

# địa chỉ → (tên mong đợi trên Blockscout, mô tả). Sai địa chỉ thì tên không khớp → bị loại, không vào tập âm.
N6_CANDIDATES = {
    "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b": ("EIP7702StatelessDeleGator", "MetaMask Delegation Framework"),
    "0x7702cb554e6bfb442cb743a7df23154544a7176c": ("EIP7702Proxy", "Coinbase Smart Wallet"),
    "0x000000009b1d0af20d8c6d0a44e162d11f9b8f00": ("CaliburEntry", "Uniswap Calibur"),
    "0x4cd241e8d1510e30b2076397afc7508ae59c66c9": ("Simple7702Account", "eth-infinitism ERC-4337 v0.8"),
    "0x5a7fc11397e9a8ad41bf10bf13f22b0a63f96f6d": ("AmbireAccount7702", "Ambire Wallet"),
}


def code_states(addresses: list[str], network: str) -> list[str | None]:
    """none / code / 7702 cho từng địa chỉ trên một mạng (None nếu RPC lỗi)."""
    out = []
    for i in range(0, len(addresses), 100):
        chunk = addresses[i:i + 100]
        try:
            codes = rpc_batch(network, [("eth_getCode", [a, "latest"]) for a in chunk])
        except Exception:
            codes = [None] * len(chunk)
        for a, c in zip(chunk, codes):
            r = _code_record(a, c)
            out.append(None if r.get("err") else "7702" if r.get("d") else "code" if r.get("h") else "none")
    return out


# ---------------------------------------------------------------- N1

def misuse_keys() -> set[tuple[str, str]]:
    keys = set()
    for name in ("ca_misuse", "eoa_misuse"):
        d = pd.read_parquet(SEED_DIR / f"{name}.parquet", columns=["chain", "address"])
        keys |= set(zip(d.chain, d.address.str.lower()))
    return keys


def sample_n1(cand: pd.DataFrame, flagged: set, per_chain: int, seed: int = 0) -> pd.DataFrame:
    """Mẫu ngẫu nhiên (chain, address) có tx nhưng không bị gắn cờ; bỏ trùng giữa hai nguồn."""
    parts = []
    for i, (chain, g) in enumerate(sorted(cand[cand.n_tx > 0].groupby("chain"), key=lambda x: x[0])):
        pool = g.sample(min(len(g), per_chain * 5), random_state=seed + i).drop_duplicates(["chain", "address"])
        keep = [(c, a.lower()) not in flagged for c, a in zip(pool.chain, pool.address)]
        parts.append(pool[keep].head(per_chain))
    return pd.concat(parts, ignore_index=True)[["chain", "source", "address", "n_tx", "balance_wei"]]


def cmd_n1(per_chain: int, seed: int):
    cand = pd.read_parquet(SEED_DIR / "candidate_addresses.parquet")
    df = sample_n1(cand, misuse_keys(), per_chain, seed)
    df["code_state"] = None
    for chain, idx in df.groupby("chain").groups.items():
        df.loc[idx, "code_state"] = code_states(df.loc[idx, "address"].tolist(), chain)
    out = INTERIM_DIR / "n1_random_unflagged.parquet"
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"Ghi {out} ({len(df)} dòng)")
    print(df.groupby(["chain", "code_state"], dropna=False).size().to_string())


# ---------------------------------------------------------------- N6

def blockscout_name(address: str, retries: int = 3) -> str | None:
    for attempt in range(retries):
        try:
            r = requests.get(BLOCKSCOUT.format(address), timeout=30)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            d = r.json()
            return d.get("name") if d.get("is_verified") else None
        except Exception:
            time.sleep(3 * (attempt + 1))
    return None


def author_delegate_set() -> set[str]:
    sx = pd.read_parquet(SEED_DIR / "symexec_results.parquet", columns=["kind", "address"])
    return set(sx[sx.kind == "eip7702_delegate"].address.str.lower())


def classify_n6(rows: list[dict], author_set: set[str]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["name_ok"] = df.verified_name == df.expected_name
    df["in_author_delegate_set"] = df.address.isin(author_set)
    df["kept"] = df.name_ok & (df.code_eth == "code")
    return df


def cmd_n6():
    addrs = list(N6_CANDIDATES)
    states = {n: code_states(addrs, n) for n in NETWORKS}
    rows = []
    for i, a in enumerate(addrs):
        expected, desc = N6_CANDIDATES[a]
        rows.append({"address": a, "wallet": desc, "expected_name": expected, "verified_name": blockscout_name(a),
                     **{f"code_{n}": states[n][i] for n in NETWORKS},
                     "networks_with_code": ",".join(n for n in NETWORKS if states[n][i] == "code")})
    df = classify_n6(rows, author_delegate_set())
    out = INTERIM_DIR / "n6_benign_7702_delegates.parquet"
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    pd.set_option("display.width", 200)
    print(df[["wallet", "verified_name", "name_ok", "in_author_delegate_set", "networks_with_code", "kept"]]
          .to_string(index=False))
    print(f"\nGiữ {int(df.kept.sum())}/{len(df)} delegate lành tính.")


# ---------------------------------------------------------------- quét block ngẫu nhiên (N2, N3, N8)

# đợt quét: tên → (từ, tới, nguồn RPC). "recent" là đợt đầu; "early" bổ sung để tập train (trước 02/2023, D8) có
# mẫu âm. publicnode ETH đã xoá block trước 09/2022 nên đợt "early" dùng RPC NodeReal (cần NODEREAL_API_KEY).
SCAN_PERIODS = {"recent": (1_672_531_200, None, "publicnode"),               # 2023-01-01 → nay
                "early": (1_577_836_800, 1_672_531_200, "nodereal")}       # 2020-01-01 → 2023-01-01
SCAN_BLOCKS = {"recent": 400, "early": 600}
SCAN_INPUT_MAX = 4_096                            # giữ tối đa 4.096 ký tự hex input (đủ cho selector và transfer)
MISUSE_SELECTORS_TOP = 30
PRUNED_BEFORE = {"eth": 15_500_000}             # publicnode ETH không còn block cũ hơn (lỗi 4444)


def scan_path(chain: str, period: str = "recent"):
    return RAW_DIR / chain / ("block_scan.parquet" if period == "recent" else f"block_scan_{period}.parquet")


def _nodereal_blocks(chain: str, calls: list[tuple[str, list]], retries: int = 5) -> list:
    """Như `rpc_batch` nhưng qua RPC NodeReal (có block cũ), gọi từng lệnh; lỗi không in URL vì URL chứa API key."""
    import os

    from address_misuse.engine.prepare import NODEREAL_CHAIN_URL
    url = NODEREAL_CHAIN_URL.format(chain, os.environ["NODEREAL_API_KEY"])
    out = []
    for method, params in calls:
        err = None
        for attempt in range(retries):
            try:
                j = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                                  timeout=90).json()
                if "result" in j:
                    out.append(j["result"])
                    break
                err = j.get("error")
            except Exception as e:
                err = type(e).__name__
            time.sleep(2 * 2 ** attempt)
        else:
            raise RuntimeError(f"NodeReal {chain} {method}: {str(err)[:200]}")
    return out


def _rpc(chain: str, calls: list[tuple[str, list]], source: str = "publicnode") -> list:
    return _nodereal_blocks(chain, calls) if source == "nodereal" else rpc_batch(chain, calls, timeout=90)


def _block(chain: str, number: int | str, full: bool = False, source: str = "publicnode") -> dict:
    tag = number if isinstance(number, str) else hex(number)
    return _rpc(chain, [("eth_getBlockByNumber", [tag, full])], source)[0]


def block_at(chain: str, ts: int, source: str = "publicnode") -> int:
    """Block đầu tiên có timestamp ≥ ts (tìm nhị phân)."""
    lo = PRUNED_BEFORE.get(chain, 1) if source == "publicnode" else 1
    hi = int(_block(chain, "latest", source=source)["number"], 16)
    while lo < hi:
        mid = (lo + hi) // 2
        if int(_block(chain, mid, source=source)["timestamp"], 16) < ts:
            lo = mid + 1
        else:
            hi = mid
    return lo


def scan_rows(chain: str, block: dict) -> list[dict]:
    ts, num = int(block["timestamp"], 16), int(block["number"], 16)
    rows = []
    for t in block["transactions"]:
        inp = t.get("input") or "0x"
        rows.append({"chain": chain, "block_number": num, "block_ts": ts, "tx_index": int(t["transactionIndex"], 16),
                     "hash": t["hash"], "from": t["from"].lower(), "target": (t.get("to") or "").lower() or None,
                     "value_wei": str(int(t["value"], 16)), "gas_price": int(t.get("gasPrice") or "0x0", 16),
                     "tx_type": int(t.get("type") or "0x0", 16), "input_len": (len(inp) - 2) // 2,
                     "input": inp[:SCAN_INPUT_MAX], "selector": inp[:10] if len(inp) >= 10 else None,
                     "readable": inp != "0x" and is_hex_readable(inp)})
    return rows


def cmd_scan(period: str, n_blocks: int | None, seed: int):
    """Tải block ngẫu nhiên của một đợt quét (SCAN_PERIODS) trên ETH và BSC, đủ tx."""
    start_ts, end_ts, source = SCAN_PERIODS[period]
    n_blocks = n_blocks or SCAN_BLOCKS[period]
    rng = random.Random(seed)
    for chain in ("eth", "bsc"):
        out = scan_path(chain, period)
        if out.exists():
            print(f"{chain}: đã có {out}")
            continue
        start = block_at(chain, start_ts, source)
        end = (block_at(chain, end_ts, source) - 1 if end_ts else
               int(_block(chain, "latest", source=source)["number"], 16))
        blocks = sorted(rng.sample(range(start, end + 1), n_blocks))
        print(f"{chain} {period}: {n_blocks} block ngẫu nhiên trong [{start:,}, {end:,}] ({source})", flush=True)
        rows = []
        for i in range(0, len(blocks), 5):
            got = _rpc(chain, [("eth_getBlockByNumber", [hex(b), True]) for b in blocks[i:i + 5]], source)
            for b in got:
                if b:
                    rows += scan_rows(chain, b)
            if (i // 5) % 20 == 0:
                print(f"  {i + 5}/{len(blocks)} block, {len(rows):,} tx", flush=True)
        out.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_parquet(out, index=False)
        print(f"  ghi {out} ({len(rows):,} tx)")


def ordinary_txs(chain: str, period: str = "recent") -> pd.DataFrame:
    """Tx thường trong block đã quét: bỏ tạo contract, tx hệ thống (gas price 0, đích 0x…1000 trên BSC)
    và tx gửi tới địa chỉ đã bị gắn cờ misuse."""
    d = pd.read_parquet(scan_path(chain, period))
    flagged = {a for c, a in misuse_keys() if c == chain}
    keep = d.target.notna() & (d.gas_price > 0) & ~d.target.fillna("").str.startswith("0x" + "0" * 34)
    return d[keep & ~d.target.isin(flagged)].reset_index(drop=True)


def misuse_selectors(top: int = MISUSE_SELECTORS_TOP) -> pd.Series:
    """Selector hay gặp nhất trong tx gọi tới địa chỉ CA Misuse (đếm số địa chỉ khác nhau, không đếm số tx),
    lấy từ txlist đã cache của địa chỉ dương (pilot ETH + mẫu đánh giá BSC)."""
    m = pd.read_parquet(INTERIM_DIR / "crosschain_matrix.parquet", columns=["chain", "address"])
    cnt = {}
    for chain, a in zip(m.chain, m.address):
        p = RAW_DIR / chain / "txlist" / f"{a}.json.gz"
        if not p.exists():
            continue
        with gzip.open(p, "rt", encoding="utf-8") as f:
            txs = json.load(f)["result"]
        calls = [t["input"] for t in txs if (t.get("to") or "").lower() == a and len(t.get("input") or "") >= 10]
        for s in {i[:10] for i in calls if not is_hex_readable(i)} - {"0x00000000"}:     # bỏ tin nhắn văn bản
            cnt[s] = cnt.get(s, 0) + 1
    return pd.Series(cnt, dtype=int).sort_values(ascending=False).head(top)


def _with_state(df: pd.DataFrame, chain: str) -> pd.DataFrame:
    targets = sorted(set(df.target))
    state = dict(zip(targets, code_states(targets, chain)))
    return df.assign(target_state=df.target.map(state))


def cmd_from_scan(per_chain: int, seed: int):
    """N8 (1 tx ngẫu nhiên/block), N2 (gọi contract bằng selector misuse phổ biến), N3 (văn bản gửi tới EOA)."""
    sels = misuse_selectors()
    print(f"selector misuse phổ biến ({len(sels)}): {', '.join(sels.index[:10])} …")
    out = {"n8_normal_txs": [], "n2_contract_calls": [], "n3_text_messages": []}
    for j, period in enumerate(SCAN_PERIODS):                 # mỗi đợt quét lấy mẫu riêng (đợt cũ không đổi)
        for i, chain in enumerate(("eth", "bsc")):
            if not scan_path(chain, period).exists():
                continue
            d = ordinary_txs(chain, period)
            rs = seed + i + 10 * j
            n8 = d.groupby("block_number").sample(1, random_state=rs)
            out["n8_normal_txs"].append(_with_state(n8.head(SCAN_BLOCKS[period]), chain).assign(period=period))
            n2 = d[d.selector.isin(sels.index) & ~d.index.isin(n8.index)]
            n2 = _with_state(n2.sample(min(len(n2), per_chain * 3), random_state=rs), chain)
            out["n2_contract_calls"].append(n2[n2.target_state == "code"].head(per_chain).assign(period=period))
            n3 = d[d.readable]
            n3 = _with_state(n3.sample(min(len(n3), per_chain * 2), random_state=rs), chain)
            out["n3_text_messages"].append(n3[n3.target_state.isin(["none", "7702"])].head(per_chain)
                                           .assign(period=period))
    for name, parts in out.items():
        df = pd.concat(parts, ignore_index=True)
        df.to_parquet(INTERIM_DIR / f"{name}.parquet", index=False)
        print(f"{name}: " + ", ".join(f"{c}/{p} {n}" for (c, p), n in df.groupby(["chain", "period"]).size().items()))


# ---------------------------------------------------------------- N4

# Ví nóng sàn làm "hub": địa chỉ nạp của sàn chuyển hết tiền về đây. Nhãn chỉ để tham khảo (Etherscan chặn đọc tự động);
# mỗi hub được KIỂM CHỨNG bằng hành vi: phần lớn người gửi gần đây là EOA chuyển gần hết số dư về hub.
N4_HUBS = {
    "eth": {"0x28c6c06298d514db089934071355e5743bf21d60": "Binance 14",
            "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance 15",
            "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance 16",
            "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase 10"},
    "bsc": {"0x8894e0a0c962cb723c1976a4421c95949be2d4e3": "Binance hot wallet 6",
            "0xe2fc31f816a9b94326492132018c3aecc4a93ae1": "Binance hot wallet 7"},
}


def cmd_n4(per_chain: int, seed: int):
    """Địa chỉ nạp sàn: EOA gửi tx thường (không calldata) tới hub trong 1.000 tx gần nhất của hub.

    Hành vi auto-sweep được kiểm tra sau bằng lịch sử của chính địa chỉ nạp (engine.prepare history)."""
    import os

    from address_misuse.engine.prepare import nodereal_transfers
    key = os.environ["NODEREAL_API_KEY"]
    rows = []
    for chain, hubs in N4_HUBS.items():
        for hub, label in hubs.items():
            prm = {"category": ["external"], "address": hub, "addressType": "to", "order": "desc", "maxCount": "0x3e8"}
            txs = nodereal_transfers(chain, key, prm).get("transfers") or []
            plain = [t for t in txs if (t.get("input") or "0x") == "0x" and int(t["value"], 16) > 0]
            print(f"{chain} {label}: {len(txs)} tx tới, {len(plain)} chuyển coin thường, "
                  f"{len({t['from'] for t in plain})} người gửi", flush=True)
            for t in plain:
                rows.append({"chain": chain, "address": t["from"].lower(), "hub": hub, "hub_label": label,
                             "block_number": int(t["blockNum"], 16), "value_wei": str(int(t["value"], 16))})
    df = pd.DataFrame(rows).drop_duplicates(["chain", "address"])
    flagged = misuse_keys()
    df = df[[(c, a) not in flagged for c, a in zip(df.chain, df.address)]]
    parts = []
    for i, (chain, g) in enumerate(df.groupby("chain")):
        g = g.sample(min(len(g), per_chain * 2), random_state=seed + i)
        g = g.assign(code_state=code_states(g.address.tolist(), chain))
        parts.append(g[g.code_state == "none"].head(per_chain))
    out = pd.concat(parts, ignore_index=True)
    out.to_parquet(INTERIM_DIR / "n4_exchange_deposits.parquet", index=False)
    print("n4_exchange_deposits: " + ", ".join(f"{c} {n}" for c, n in out.groupby("chain").size().items()))


N4_FORWARD_MIN = 0.9          # địa chỉ nạp: ≥ 90% tx gửi đi là về hub, và chuyển về hub ≥ 90% lượng coin nhận


def n4_deposit_like(txs: pd.DataFrame, address: str, hub: str) -> bool:
    """Hành vi auto-sweep của địa chỉ nạp: gần như mọi tx gửi đi là về hub, mang theo gần hết coin đã nhận."""
    inc, out = txs[txs.to_address == address], txs[txs.from_address == address]
    if not len(inc) or not len(out):
        return False
    to_hub = out[out.to_address == hub]
    return (len(to_hub) / len(out) >= N4_FORWARD_MIN
            and to_hub.value.astype(float).sum() >= N4_FORWARD_MIN * inc.value.astype(float).sum())


def cmd_n4_verify():
    """Gắn `kept` cho N4 sau khi đã có lịch sử (`engine.prepare history`); chỉ giữ địa chỉ đúng hành vi địa chỉ nạp."""
    from address_misuse.engine.features import load_txlist
    path = INTERIM_DIR / "n4_exchange_deposits.parquet"
    df = pd.read_parquet(path)
    kept = []
    for r in df.itertuples():
        t = load_txlist(r.address, r.chain)
        kept.append(None if t is None else n4_deposit_like(t, r.address, r.hub))
    df["kept"] = kept
    df.to_parquet(path, index=False)
    print(df.groupby(["chain", "hub_label"]).kept.agg(["size", "sum"]).to_string())
    print(f"thiếu lịch sử: {df.kept.isna().sum()}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("n1")
    p.add_argument("--per-chain", type=int, default=200)
    p.add_argument("--seed", type=int, default=0)
    sub.add_parser("n6")
    p = sub.add_parser("scan")
    p.add_argument("--period", choices=list(SCAN_PERIODS), default="recent")
    p.add_argument("--blocks", type=int, default=None, help="mặc định SCAN_BLOCKS[period]")
    p.add_argument("--seed", type=int, default=0)
    sub.add_parser("n4-verify")
    for name, n in (("from-scan", 400), ("n4", 200)):
        p = sub.add_parser(name)
        p.add_argument("--per-chain", type=int, default=n)
        p.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    if a.cmd == "n1":
        cmd_n1(a.per_chain, a.seed)
    elif a.cmd == "n6":
        cmd_n6()
    elif a.cmd == "scan":
        cmd_scan(a.period, a.blocks, a.seed)
    elif a.cmd == "from-scan":
        cmd_from_scan(a.per_chain, a.seed)
    elif a.cmd == "n4-verify":
        cmd_n4_verify()
    else:
        cmd_n4(a.per_chain, a.seed)


if __name__ == "__main__":
    main()
