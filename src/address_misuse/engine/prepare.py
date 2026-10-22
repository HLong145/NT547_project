"""Dữ liệu bổ sung cho engine (RISK_SCORE.md §6). Mỗi bước có cache, chạy lại chỉ làm phần còn thiếu.

python -m address_misuse.engine.prepare creation    # thời điểm tạo contract trên chính chain (NCD về sau có code)
python -m address_misuse.engine.prepare delegates   # symexec cho delegate EIP-7702 chưa có kết quả
python -m address_misuse.engine.prepare history     # txlist Etherscan cho địa chỉ ETH âm (N1/N6/N7), không có trong BigQuery
"""

import argparse
import json
import os

import pandas as pd
import requests

from address_misuse.config import INTERIM_DIR, SEED_DIR
from address_misuse.engine.features import (ENGINE_CODE, ENGINE_CREATION, ENGINE_SYMEXEC, MATRIX, TXLIST_DIR,
                                            load_symexec)

NODEREAL_URL = "https://bsc-mainnet.nodereal.io/v1/{}"
HISTORY_MAX_RECORDS = 10_000
HISTORY_MAX_RECORDS_INFRA = 1_000     # N6/N7: mẫu 1.000 tx đầu, ghi `truncated`


def _nodereal_creation(address: str, key: str) -> dict | None:
    r = requests.post(NODEREAL_URL.format(key), json={"jsonrpc": "2.0", "id": 1, "method":
                                                      "nr_getContractCreationTransaction", "params": [address]},
                      timeout=30).json()
    return r.get("result") or None


def cmd_creation():
    m = pd.read_parquet(MATRIX)
    todo = m[(m.misuse_chain_state == "code") & (m.subtype == "NCD")][["chain", "address"]]
    old = pd.read_parquet(ENGINE_CREATION) if ENGINE_CREATION.exists() else pd.DataFrame(
        columns=["chain", "address", "create_ts", "create_block", "source"])
    done = set(zip(old.chain, old.address))
    todo = todo[[k not in done for k in zip(todo.chain, todo.address)]]
    print(f"thời điểm tạo contract: {len(todo)} địa chỉ cần tra", flush=True)
    rows = []
    eth = todo[todo.chain == "eth"].address.tolist()
    if eth:
        from address_misuse.etherscan import Etherscan
        for a, r in Etherscan("eth").contract_creation(eth).items():
            rows.append({"chain": "eth", "address": a, "create_ts": int(r["timestamp"]),
                         "create_block": int(r["blockNumber"]), "source": "etherscan"})
    bsc = todo[todo.chain == "bsc"].address.tolist()
    key = os.environ.get("NODEREAL_API_KEY")
    if bsc and not key:
        print("  bỏ qua BSC: thiếu NODEREAL_API_KEY")
    for a in bsc if key else []:
        r = _nodereal_creation(a, key)
        if r:
            rows.append({"chain": "bsc", "address": a, "create_ts": int(r["timestamp"]),
                         "create_block": int(r["blockNumber"]), "source": "nodereal"})
    found = {(r["chain"], r["address"]) for r in rows}
    rows += [{"chain": c, "address": a, "create_ts": None, "create_block": None, "source": "not_found"}
             for c, a in zip(todo.chain, todo.address) if (c, a) not in found]
    out = pd.concat([old, pd.DataFrame(rows)], ignore_index=True)
    out.to_parquet(ENGINE_CREATION, index=False)
    print(f"  tìm được {len(found)}/{len(todo)}; ghi {ENGINE_CREATION} ({len(out)} dòng)")


def cmd_delegates(timeout: float = 120, workers: int = 2):
    from address_misuse.crosschain import get_code
    from address_misuse.reproduce_symexec import run_isolated
    want = set()
    if ENGINE_CODE.exists():
        c = pd.read_parquet(ENGINE_CODE).query("state == '7702'")
        want |= set(zip(c.net, c.delegate))
    d = pd.read_parquet(SEED_DIR / "eip7702_delegations.parquet")
    want |= set(zip(d.chain, d.delegate))
    sx = load_symexec()
    todo = sorted(k for k in want if k not in sx and k[0] in ("eth", "bsc"))
    print(f"symexec delegate 7702: {len(want)} delegate, {len(todo)} chưa có kết quả", flush=True)
    tasks = []
    for chain, a in todo:
        try:
            code = get_code(chain, a)
        except Exception as e:                                # RPC lỗi: lần chạy sau thử lại
            print(f"  getCode lỗi {chain} {a}: {e!r:.80}")
            continue
        if code and code != "0x":
            tasks.append((chain, "eip7702_delegate", a, code, timeout))
    with ENGINE_SYMEXEC.open("a", encoding="utf-8") as f:
        for i, r in enumerate(run_isolated(tasks, workers=workers, hard_limit=timeout + 60, max_mem_mb=1500), 1):
            f.write(json.dumps(r) + "\n")
            f.flush()
            print(f"  {i}/{len(tasks)} {r['chain']} {r['address'][:10]} {r['status']}", flush=True)


def negative_eth_addresses() -> dict[str, list[str]]:
    n1 = pd.read_parquet(INTERIM_DIR / "n1_random_unflagged.parquet").query("chain == 'eth'").address
    n6 = pd.read_parquet(INTERIM_DIR / "n6_benign_7702_delegates.parquet").query("kept").address
    n7 = pd.read_parquet(INTERIM_DIR / "n7_multichain_contracts.parquet").query("kept").address
    return {"N1": sorted(set(n1.str.lower())), "N6+N7": sorted(set(pd.concat([n6, n7]).str.lower()))}


def cmd_history():
    """N1 lấy tối đa 10k tx; N6/N7 (hạ tầng, hàng triệu tx, Etherscan ~45 s/trang) chỉ lấy 1.000 tx đầu."""
    from address_misuse.etherscan import Etherscan
    from address_misuse.reproduce_rules import fetch_txlist
    es = Etherscan("eth")
    for grp, max_records in (("N1", HISTORY_MAX_RECORDS), ("N6+N7", HISTORY_MAX_RECORDS_INFRA)):
        addrs = [a for a in negative_eth_addresses()[grp] if not (TXLIST_DIR / f"{a}.json.gz").exists()]
        print(f"txlist Etherscan {grp}: {len(addrs)} địa chỉ (tối đa {max_records:,} tx/địa chỉ)", flush=True)
        for i, a in enumerate(addrs, 1):
            fetch_txlist(es, a, max_records=max_records)
            if i % 25 == 0 or i == len(addrs):
                print(f"  {i}/{len(addrs)}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["creation", "delegates", "history"])
    ap.add_argument("--timeout", type=float, default=120, help="giây symexec mỗi delegate")
    a = ap.parse_args()
    {"creation": cmd_creation, "delegates": lambda: cmd_delegates(a.timeout), "history": cmd_history}[a.step]()


if __name__ == "__main__":
    main()
