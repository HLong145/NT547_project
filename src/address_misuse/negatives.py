"""D4 — tập âm N1 và N6 (N7: known_multichain.py). Định nghĩa: docs/PLAN_V2.md §D4.

python -X utf8 -m address_misuse.negatives n1 [--per-chain 200 --seed 0]   → data/interim/n1_random_unflagged.parquet
python -X utf8 -m address_misuse.negatives n6                              → data/interim/n6_benign_7702_delegates.parquet

N1: địa chỉ ứng viên của tác giả (cùng nguồn GitHub/StackExchange, có tx) mà rule KHÔNG gắn cờ → đo recall / tìm FN.
    Kèm trạng thái code hiện tại trên chính chain (EOA / contract / 7702) để chia tầng khi gán nhãn.
N6: implementation smart wallet EIP-7702 hợp lệ (MetaMask, Coinbase, Uniswap, Ambire, eth-infinitism). Mỗi ứng viên
    được KIỂM CHỨNG: tên contract đã verify trên Blockscout (không cần key) phải khớp và có code trên ETH.
    Cột `in_author_delegate_set` chỉ để tham khảo: tập symexec_results kind = eip7702_delegate của tác giả là
    MỌI delegate đã phân tích (kể cả ví hợp lệ như MetaMask), không phải tập delegate độc.
    Lưu ý: dữ liệu tác giả KHÔNG có EOA ủy quyền lành tính (mọi delegation đều từ EOA lộ key/ADDR) → EOA cho N6
    cần lấy từ dữ liệu on-chain mới (BigQuery, D1).
"""

import argparse
import time

import pandas as pd
import requests

from address_misuse.config import INTERIM_DIR, NETWORKS, SEED_DIR
from address_misuse.crosschain_matrix import _code_record, rpc_batch

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


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("n1")
    p.add_argument("--per-chain", type=int, default=200)
    p.add_argument("--seed", type=int, default=0)
    sub.add_parser("n6")
    a = ap.parse_args()
    if a.cmd == "n1":
        cmd_n1(a.per_chain, a.seed)
    else:
        cmd_n6()


if __name__ == "__main__":
    main()
