"""D3b bước 2–3: từ thống kê BigQuery (`l2_fetch`) ra misuse trên L2 bằng đúng luật của tác giả (PLAN_V2 §D3b).

python -X utf8 -m address_misuse.l2_misuse state --chain op       # getCode 8 mạng cho địa chỉ có tx đến thành công
python -X utf8 -m address_misuse.l2_misuse txlist --chain op      # txlist + thời điểm tạo contract cho ứng viên
python -X utf8 -m address_misuse.l2_misuse rules --chain op       # chạy rules.py → data/interim/l2_misuse_<chain>.parquet

Ứng viên (theo trạng thái code HIỆN TẠI trên L2, giống cách tác giả làm trên ETH/BSC):
- KEY: địa chỉ suy ra từ key lộ (`seed/candidate_pk_addresses`) có tx đến;
- NCD: không có code trên L2; PCD: có code trên L2 (contract được tạo sau tx đến đầu tiên mới có thể là PCD);
- Type 4 (XC): có code ở mạng khác trong 8 mạng của D3 (`xc_code/code_<net>.jsonl`, dùng chung cache với D3).
Nguồn txlist: Optimism qua Blockscout (API tương thích Etherscan, không cần key). Arbitrum: Blockscout chặn
(Cloudflare 403) → Etherscan V2 (gói free có arb), chỉ chạy khi không có job Etherscan nào khác (D6).
Lưu ý Arbitrum: `gasUsed` gồm cả phần phí L1, nên điều kiện NCD `gasUsed ≤ 30.000` của tác giả sẽ bỏ sót; ghi rõ khi
báo kết quả.
"""

import argparse
import gzip
import json
import time

import pandas as pd
import requests

from address_misuse.config import INTERIM_DIR, NETWORKS, RAW_DIR, SEED_DIR
from address_misuse.crosschain_matrix import XC_DIR, load_code, probe_network, rpc_batch
from address_misuse.engine.features import txlist_path
from address_misuse.rules import detect_ca_misuse, detect_eoa_key

BLOCKSCOUT_API = {"op": "https://optimism.blockscout.com/api"}
MAX_RECORDS = 10_000
PAGE = 1_000
XC_NETS = [n for n in NETWORKS]


GAS_PROXY_OK = {"op", "polygon"}      # gas_used chỉ là gas thực thi L2 → > 21.000 là dấu hiệu gọi hàm


def pk_addresses() -> set[str]:
    return set(pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet").address.str.lower())


def activity(chain: str) -> pd.DataFrame:
    """Địa chỉ đáng xét: key lộ có tx đến thành công, hoặc có tx đến thành công dạng gọi hàm (NCD/PCD cần calldata).
    Arbitrum không lọc được theo gas (gồm phí L1) nên giữ mọi địa chỉ có tx đến thành công."""
    df = pd.read_parquet(RAW_DIR / chain / "bq_l2_activity_inbound.parquet")
    pk = df.address.isin(pk_addresses())
    call = df.n_in_ok_gas_gt_21000 > 0 if chain in GAS_PROXY_OK else df.n_in_ok > 0
    return df[(df.n_in_ok > 0) & (pk | call)].reset_index(drop=True)


def cmd_state(chain: str):
    XC_DIR.mkdir(parents=True, exist_ok=True)
    addrs = sorted(activity(chain).address)
    print(f"{chain}: {len(addrs):,} địa chỉ đáng xét; getCode trên chính {chain} trước", flush=True)
    probe_network(chain, addrs)
    st = load_code(chain).set_index("address")[f"{chain}_state"]
    none = [a for a in addrs if st.get(a) == "none"]                # chỉ NCD cần biết có code ở mạng khác (Type 4)
    print(f"không có code trên {chain}: {len(none):,} → getCode {len(XC_NETS) - 1} mạng còn lại", flush=True)
    for n in [x for x in XC_NETS if x != chain]:
        probe_network(n, none)


def candidates(chain: str) -> pd.DataFrame:
    df = activity(chain)
    for n in XC_NETS:
        df = df.merge(load_code(n)[["address", f"{n}_state"]], on="address", how="left")
    df["is_pk"] = df.address.isin(pk_addresses())
    st = df[f"{chain}_state"]
    others = [n for n in XC_NETS if n != chain]
    df["xc_nets"] = [",".join(n for n in others if r[f"{n}_state"] == "code") for _, r in df.iterrows()]
    df["kind"] = "OTHER"
    df.loc[st == "none", "kind"] = "NCD"
    df.loc[st == "code", "kind"] = "PCD"
    df.loc[st == "7702", "kind"] = "7702"
    df.loc[df.is_pk, "kind"] = "KEY"
    df.loc[st.isna(), "kind"] = "UNKNOWN"
    df["xc"] = df.xc_nets != ""
    return df


BS_GAP = 0.35                         # giây giữa hai lần gọi Blockscout (gọi dồn thì bị 429)
_last_call = [0.0]


def _bs_get(chain: str, params: dict, retries: int = 6) -> dict:
    err = None
    for attempt in range(retries):
        time.sleep(max(0.0, _last_call[0] + BS_GAP - time.monotonic()))
        _last_call[0] = time.monotonic()
        try:
            r = requests.get(BLOCKSCOUT_API[chain], params=params, timeout=120)
            if r.status_code == 200:
                return r.json()
            err = f"HTTP {r.status_code}"
        except Exception as e:
            err = str(e)
        time.sleep((15 if err == "HTTP 429" else 2) * (attempt + 1))
    raise RuntimeError(f"Blockscout {chain}: {err}")


def fetch_txlist(chain: str, address: str) -> None:
    p = txlist_path(chain, address)
    if p.exists():
        return
    out, page, truncated = [], 1, False
    while True:
        j = _bs_get(chain, {"module": "account", "action": "txlist", "address": address, "page": page,
                            "offset": PAGE, "sort": "asc"})
        res = j.get("result") or []
        if not isinstance(res, list):
            raise RuntimeError(f"Blockscout {chain} {address}: {str(res)[:120]}")
        out += res
        if len(res) < PAGE:
            break
        if len(out) >= MAX_RECORDS:
            truncated = True
            break
        page += 1
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt", encoding="utf-8") as f:
        json.dump({"result": out, "truncated": truncated, "source": "blockscout"}, f)


def creation_path(chain: str):
    return RAW_DIR / chain / "creation.jsonl"


def fetch_creations(chain: str, addresses: list[str]) -> None:
    """`getcontractcreation` (Blockscout) + timestamp của block tạo (RPC). Lỗi thì không ghi (lần sau thử lại)."""
    path = creation_path(chain)
    done = {json.loads(x)["address"] for x in path.read_text(encoding="utf-8").splitlines()} if path.exists() else set()
    todo = [a for a in addresses if a not in done]
    with path.open("a", encoding="utf-8") as f:
        for i in range(0, len(todo), 5):
            chunk = todo[i:i + 5]
            try:
                res = _bs_get(chain, {"module": "contract", "action": "getcontractcreation",
                                      "contractaddresses": ",".join(chunk)}).get("result") or []
            except RuntimeError as e:
                print(f"  lỗi {e}", flush=True)
                continue
            by = {r["contractAddress"].lower(): r for r in res if r.get("blockNumber")}
            blocks = sorted({int(r["blockNumber"]) for r in by.values()})
            try:                                            # publicnode giới hạn theo IP, dùng chung với getCode
                ts = dict(zip(blocks, rpc_batch(chain, [("eth_getBlockByNumber", [hex(b), False]) for b in blocks])))
            except RuntimeError as e:
                print(f"  lỗi {e}", flush=True)
                continue
            for a in chunk:
                r = by.get(a)
                if r and not ts.get(int(r["blockNumber"])):
                    continue                                # chưa có timestamp: lần sau thử lại
                if r:
                    c = {"blockNumber": r["blockNumber"], "timestamp": str(int(ts[int(r["blockNumber"])]["timestamp"], 16)),
                         "contractCreator": r.get("contractCreator"), "txHash": r.get("txHash")}
                else:
                    c = {}
                f.write(json.dumps({"address": a, "creation": c}) + "\n")
            f.flush()


def load_creations(chain: str) -> dict:
    p = creation_path(chain)
    if not p.exists():
        return {}
    return {r["address"]: r["creation"] for r in map(json.loads, p.read_text(encoding="utf-8").splitlines())}


def cmd_txlist(chain: str, kinds: list[str]):
    if chain not in BLOCKSCOUT_API:
        raise SystemExit(f"{chain}: chưa có nguồn txlist không cần Etherscan (xem docstring)")
    c = candidates(chain)
    c = c[c.kind.isin(kinds)]
    print(f"{chain}: ứng viên {c.kind.value_counts().to_dict()}", flush=True)
    fetch_creations(chain, sorted(c.address[c.kind == "PCD"]))
    todo = [a for a in c.address if not txlist_path(chain, a).exists()]
    print(f"txlist cần tải: {len(todo):,}", flush=True)
    for i, a in enumerate(todo, 1):
        try:
            fetch_txlist(chain, a)
        except RuntimeError as e:
            print(f"  lỗi {e}", flush=True)
        if i % 200 == 0 or i == len(todo):
            print(f"  {i:,}/{len(todo):,}", flush=True)


def _load(chain: str, address: str) -> tuple[list[dict], bool] | None:
    p = txlist_path(chain, address)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        d = json.load(f)
    txs = d["result"]
    for t in txs:                                           # Blockscout: có methodId, không có functionName
        t["methodId"] = t.get("methodId") or ((t.get("input") or "0x")[:10] if len(t.get("input") or "") >= 10 else "0x")
        t.setdefault("functionName", "?" if len(t.get("input") or "") >= 10 else "")
        t["to"] = (t.get("to") or "").lower()
        t["from"] = (t.get("from") or "").lower()
    return txs, bool(d.get("truncated"))


def cmd_rules(chain: str):
    c = candidates(chain)
    cre = load_creations(chain)
    rows = []
    for r in c.itertuples():
        got = _load(chain, r.address)
        if got is None:
            continue
        txs, truncated = got
        if r.kind == "KEY":
            res = detect_eoa_key(r.address, txs)
        elif r.kind in ("NCD", "PCD"):
            creation = cre.get(r.address) or None if r.kind == "PCD" else None
            res = detect_ca_misuse(r.address, txs, chain, creation=creation)
        else:
            continue
        ts = [int(t["timeStamp"]) for t in txs if t["hash"] in {f["hash"] for f in res.flagged}]
        rows.append({"chain": chain, "address": r.address, "kind": r.kind, "subtype": res.subtype, "xc": r.xc,
                     "xc_nets": r.xc_nets, "n_tx": res.n_tx, "n_misuse_tx": res.n_misuse_tx,
                     "cost_wei": str(res.cost_wei), "cost_native": res.cost_wei / 1e18, "truncated": truncated,
                     "first_misuse_ts": min(ts) if ts else None, "last_misuse_ts": max(ts) if ts else None})
    df = pd.DataFrame(rows)
    out = INTERIM_DIR / f"l2_misuse_{chain}.parquet"
    df.to_parquet(out, index=False)
    pos = df[df.n_misuse_tx > 0]
    print(f"{chain}: chạy luật trên {len(df):,} địa chỉ có txlist → {len(pos):,} dương")
    if len(pos):
        g = pos.groupby(["subtype", "xc"]).agg(n=("address", "size"), tx=("n_misuse_tx", "sum"),
                                                loss=("cost_native", "sum"))
        print(g.to_string())
    print(f"ghi {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["state", "txlist", "rules", "summary"])
    ap.add_argument("--chain", choices=["arb", "op", "polygon"], required=True)
    ap.add_argument("--kinds", nargs="+", default=["KEY", "NCD", "PCD"])
    a = ap.parse_args()
    if a.step == "state":
        cmd_state(a.chain)
    elif a.step == "txlist":
        cmd_txlist(a.chain, a.kinds)
    elif a.step == "rules":
        cmd_rules(a.chain)
    else:
        c = candidates(a.chain)
        print(pd.crosstab(c.kind, c.xc, margins=True).to_string())


if __name__ == "__main__":
    main()
