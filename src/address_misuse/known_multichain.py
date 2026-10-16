"""Tập âm N7 — contract hợp lệ được deploy CÙNG địa chỉ trên nhiều chain (Type 4 KHÔNG được báo nhầm).

python -X utf8 -m address_misuse.known_multichain
Kết quả: data/interim/n7_multichain_contracts.parquet

Danh sách ứng viên dưới đây là địa chỉ công khai, được dùng rộng rãi. Mỗi địa chỉ được KIỂM CHỨNG on-chain:
chỉ giữ địa chỉ có code ở >= 3 mạng; ghi lại bytecode có giống nhau giữa các mạng không.
"""

import pandas as pd

from address_misuse.config import INTERIM_DIR, NETWORKS, SEED_DIR
from address_misuse.crosschain_matrix import _code_record, rpc_batch

CANDIDATES = {
    # Hạ tầng triển khai (CREATE2 factory, deployer)
    "0x4e59b44847b379578588920ca78fbf26c0b4956c": "Deterministic Deployment Proxy (Arachnid CREATE2)",
    "0xba5ed099633d3b313e4d5f7bdc1305d3c28ba5ed": "CreateX factory",
    "0x0000000000ffe8b47b3e2130213b802212439497": "ImmutableCreate2Factory",
    "0x914d7fec6aac8cd542e72bca78b30650d45643d7": "Safe Singleton Factory",
    # Tiện ích
    "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    # Safe (Gnosis Safe)
    "0xd9db270c1b5e3bd161e8c8503c55ceabee709552": "Safe v1.3.0 singleton",
    "0x3e5c63644e683549055b9be8653de26e0b4cd36e": "Safe v1.3.0 L2 singleton",
    "0xa6b71e26c5e0845f74c812102ca7114b6a896ab2": "Safe v1.3.0 ProxyFactory",
    "0x41675c099f32341bf84bfc5382af534df5c7461a": "Safe v1.4.1 singleton",
    "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67": "Safe v1.4.1 ProxyFactory",
    # ERC-4337 Account Abstraction
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": "ERC-4337 EntryPoint v0.6",
    "0x0000000071727de22e5e9d8baf0edac6f37da032": "ERC-4337 EntryPoint v0.7",
    # DEX aggregator / marketplace
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Aggregation Router v5",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Aggregation Router v6",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "OpenSea Seaport 1.5",
    "0x0000000000000068f116a894984e2db1123eb395": "OpenSea Seaport 1.6",
}
MIN_NETWORKS = 3


def probe_candidates(addresses: list[str], networks) -> dict[str, dict[str, dict]]:
    """{mạng: {địa chỉ: bản ghi _code_record}}; cả mạng lỗi thì mọi địa chỉ ghi err."""
    out = {}
    for n in networks:
        try:
            codes = rpc_batch(n, [("eth_getCode", [a, "latest"]) for a in addresses])
        except Exception:
            codes = [None] * len(addresses)
        out[n] = {a: _code_record(a, c) for a, c in zip(addresses, codes)}
    return out


def summarize_candidates(records: dict[str, dict[str, dict]], names: dict[str, str]) -> pd.DataFrame:
    rows = []
    for a, name in names.items():
        states = {n: recs.get(a, {"a": a, "err": 1}) for n, recs in records.items()}
        with_code = [n for n, r in states.items() if r.get("h")]          # bỏ 7702 và mạng không có code
        hashes = {states[n]["h"] for n in with_code}
        rows.append({"address": a, "name": name, "n_networks_with_code": len(with_code),
                     "networks_with_code": ",".join(with_code), "identical_bytecode": len(hashes) == 1,
                     "n_distinct_bytecode": len(hashes), "kept": len(with_code) >= MIN_NETWORKS,
                     "errors": ",".join(n for n, r in states.items() if r.get("err"))})
    return pd.DataFrame(rows)


def main():
    df = summarize_candidates(probe_candidates(list(CANDIDATES), NETWORKS), CANDIDATES)

    # Có địa chỉ N7 nào nằm trong danh sách misuse của tác giả không? (kỳ vọng: không, hoặc chỉ ở chain chưa deploy)
    ca = pd.read_parquet(SEED_DIR / "ca_misuse.parquet", columns=["chain", "address", "subtype"])
    hit = ca[ca.address.isin(df.address)].drop_duplicates()
    found = {}
    for r in hit.itertuples():
        found.setdefault(r.address, []).append(f"{r.chain}:{r.subtype}")
    df["in_author_ca_misuse"] = [",".join(found.get(a, [])) for a in df.address]

    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(INTERIM_DIR / "n7_multichain_contracts.parquet", index=False)
    pd.set_option("display.width", 200)
    print(df[["name", "n_networks_with_code", "identical_bytecode", "kept", "in_author_ca_misuse", "errors"]]
          .to_string(index=False))
    print(f"\nGiữ {int(df.kept.sum())}/{len(df)} contract (code ở >= {MIN_NETWORKS} mạng).")


if __name__ == "__main__":
    main()
