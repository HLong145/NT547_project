"""D3b bước 2–3: từ thống kê BigQuery (`l2_fetch`) ra misuse trên L2 bằng đúng luật của tác giả (PLAN_V2 §D3b).

python -X utf8 -m address_misuse.l2_misuse state --chain op       # getCode 8 mạng cho địa chỉ có tx đến thành công
python -X utf8 -m address_misuse.l2_misuse txlist --chain op      # txlist + thời điểm tạo contract cho ứng viên
python -X utf8 -m address_misuse.l2_misuse rules --chain op       # chạy rules.py → data/interim/l2_misuse_<chain>.parquet
python -X utf8 -m address_misuse.l2_misuse delegates --chain op   # symexec delegate 7702 trên L2 → l2_delegates_<chain>

Ứng viên (theo trạng thái code HIỆN TẠI trên L2, giống cách tác giả làm trên ETH/BSC):
- KEY: địa chỉ suy ra từ key lộ (`seed/candidate_pk_addresses`) có tx đến;
- NCD: không có code trên L2; PCD: có code trên L2 (contract được tạo sau tx đến đầu tiên mới có thể là PCD);
- Type 4 (XC): có code ở mạng khác trong 8 mạng của D3 (`xc_code/code_<net>.jsonl`, dùng chung cache với D3).
Nguồn txlist: Arbitrum, Polygon qua Etherscan V2 (gói free có hai chain này). Optimism: Etherscan free không hỗ trợ,
Routescan không có OP → Blockscout, nhưng không có key chỉ được 10 lượt rồi bị chặn nhiều phút; cần key miễn phí
(dev.blockscout.com) đặt trong `.env` là `BLOCKSCOUT_API_KEY`.
Lưu ý Arbitrum: `gasUsed` gồm cả phần phí L1, nên điều kiện NCD `gasUsed ≤ 30.000` của tác giả sẽ bỏ sót; ghi rõ khi
báo kết quả.
"""

import argparse
import gzip
import json
import os
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


def author_ca_addresses() -> set[str]:
    return set(pd.read_parquet(SEED_DIR / "ca_misuse.parquet", columns=["address"]).address.str.lower())


def activity(chain: str, focus: str = "all") -> pd.DataFrame:
    """Địa chỉ đáng xét: key lộ có tx đến thành công, hoặc có tx đến thành công dạng gọi hàm (NCD/PCD cần calldata).
    Arbitrum không lọc được theo gas (gồm phí L1) nên giữ mọi địa chỉ có tx đến thành công.
    `focus="author"`: chỉ key lộ + địa chỉ tác giả đã kết luận misuse CA trên ETH/BSC (câu hỏi cross-chain trực tiếp)."""
    df = pd.read_parquet(RAW_DIR / chain / "bq_l2_activity_inbound.parquet")
    pk = df.address.isin(pk_addresses())
    call = df.n_in_ok_gas_gt_21000 > 0 if chain in GAS_PROXY_OK else df.n_in_ok > 0
    keep = (df.n_in_ok > 0) & (pk | call)
    if focus == "author":
        keep &= pk | df.address.isin(author_ca_addresses())
    return df[keep].reset_index(drop=True)


def cmd_state(chain: str, focus: str = "all"):
    XC_DIR.mkdir(parents=True, exist_ok=True)
    addrs = sorted(activity(chain, focus).address)
    print(f"{chain}: {len(addrs):,} địa chỉ đáng xét; getCode trên chính {chain} trước", flush=True)
    probe_network(chain, addrs)
    st = load_code(chain).set_index("address")[f"{chain}_state"]
    none = [a for a in addrs if st.get(a) == "none"]                # chỉ NCD cần biết có code ở mạng khác (Type 4)
    print(f"không có code trên {chain}: {len(none):,} → getCode {len(XC_NETS) - 1} mạng còn lại", flush=True)
    for n in [x for x in XC_NETS if x != chain]:
        probe_network(n, none)


def candidates(chain: str, focus: str = "all") -> pd.DataFrame:
    df = activity(chain, focus)
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
    df.loc[st.isna(), "kind"] = "UNKNOWN"
    df.loc[df.is_pk, "kind"] = "KEY"                            # KEY chỉ cần txlist, không cần trạng thái code
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
            key = os.environ.get("BLOCKSCOUT_API_KEY")
            r = requests.get(BLOCKSCOUT_API[chain], params={**params, **({"apikey": key} if key else {})}, timeout=120)
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


ETHERSCAN_FREE = {"arb", "polygon"}


def cmd_txlist(chain: str, kinds: list[str], focus: str = "all", max_records: int = MAX_RECORDS):
    c = candidates(chain, focus)
    c = c[c.kind.isin(kinds)]
    print(f"{chain}: ứng viên {c.kind.value_counts().to_dict()}", flush=True)
    pcd = sorted(c.address[c.kind == "PCD"])
    if chain in ETHERSCAN_FREE:
        from address_misuse.etherscan import Etherscan
        from address_misuse import reproduce_rules as rr
        es = Etherscan(chain)
        rr.fetch_creations(es, pcd)
        get = lambda a: rr.fetch_txlist(es, a, max_records=max_records)         # noqa: E731
    else:
        fetch_creations(chain, pcd)
        get = lambda a: fetch_txlist(chain, a)                                   # noqa: E731
    todo = [a for a in c.address if not txlist_path(chain, a).exists()]
    print(f"txlist cần tải: {len(todo):,}", flush=True)
    for i, a in enumerate(todo, 1):
        try:
            get(a)
        except Exception as e:
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


def cmd_rules(chain: str, focus: str = "all"):
    c = candidates(chain, focus)
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
            if r.kind == "PCD" and creation is None and not any(t["to"] == "" for t in txs):
                continue        # có code nhưng không biết lúc tạo: luật tác giả sẽ coi là NCD → bỏ, không đoán
            res = detect_ca_misuse(r.address, txs, chain, creation=creation)
        else:
            continue
        alt = None
        if r.kind == "NCD" and chain not in GAS_PROXY_OK:
            # Arbitrum: gasUsed gồm phí L1 → điều kiện gasUsed ≤ 30.000 của tác giả loại phần lớn tx (chỉ 17,5% tx gọi hàm
            # tới NCD đạt). Địa chỉ không có code thì gas thực thi L2 chỉ là phần nội tại → biến thể bỏ điều kiện gas.
            alt = detect_ca_misuse(r.address, [{**t, "gasUsed": "21000"} for t in txs], chain, creation=None)
        ts = [int(t["timeStamp"]) for t in txs if t["hash"] in {f["hash"] for f in res.flagged}]
        valued = [f for f in res.flagged if f.get("value_wei", 0) > 0]      # KEY: bỏ tx value 0 (lệnh sweep 7702)
        rows.append({"chain": chain, "address": r.address, "kind": r.kind, "subtype": res.subtype, "xc": r.xc,
                     "xc_nets": r.xc_nets, "n_tx": res.n_tx, "n_misuse_tx": res.n_misuse_tx,
                     "cost_wei": str(res.cost_wei), "cost_native": res.cost_wei / 1e18, "truncated": truncated,
                     "n_misuse_value_tx": len(valued),
                     "value_native": sum(f["value_wei"] for f in valued) / 1e18,
                     "author_ca": r.address in author_ca_addresses_cached(),
                     "n_misuse_tx_nogas": None if alt is None else alt.n_misuse_tx,
                     "cost_native_nogas": None if alt is None else alt.cost_wei / 1e18,
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


_AUTHOR_CA: set[str] = set()


def author_ca_addresses_cached() -> set[str]:
    if not _AUTHOR_CA:
        _AUTHOR_CA.update(author_ca_addresses())
    return _AUTHOR_CA


def cmd_delegates(chain: str, timeout: float, workers: int):
    """Delegate 7702 của các địa chỉ đáng xét trên L2: lấy code trên chính L2, bytecode trùng delegate ETH đã có
    symexec (D6) thì dùng lại, còn lại chạy symexec. Điều kiện ADDR của tác giả: `transfer_all_eth` | `transfer_msg_value`."""
    import hashlib
    from address_misuse.d6_new import _symexec_flags
    from address_misuse.engine.features import ENGINE_SYMEXEC
    from address_misuse.reproduce_symexec import run_isolated
    raw = pd.DataFrame([json.loads(x) for x in (XC_DIR / f"code_{chain}.jsonl").read_text(encoding="utf-8").splitlines()])
    raw = raw[raw.err.isna()] if "err" in raw else raw
    raw = raw.drop_duplicates("a", keep="last")
    raw = raw[raw.a.isin(set(activity(chain).address)) & raw.d.notna()]
    raw["d"] = raw.d.str.lower()
    pk = pk_addresses()
    n_eoa = raw.d.value_counts()
    n_pk = raw[raw.a.isin(pk)].d.value_counts()
    dels = n_eoa.index.tolist()
    codes = {}
    for i in range(0, len(dels), 20):
        chunk = dels[i:i + 20]
        codes.update(zip(chunk, rpc_batch(chain, [("eth_getCode", [a, "latest"]) for a in chunk], timeout=60)))
    h = {a: hashlib.sha256((c or "").encode()).hexdigest()[:16] for a, c in codes.items()}

    def flags_by_hash():
        eth = _symexec_flags()                                  # cùng bytecode → cùng kết quả symexec
        rows = [json.loads(x) for x in ENGINE_SYMEXEC.read_text(encoding="utf-8").splitlines() if x.strip()]             if ENGINE_SYMEXEC.exists() else []
        own = {r["address"]: {"all_eth": bool(r["ours_transfer_all_eth"]), "msg_value": bool(r["ours_transfer_msg_value"]),
                              "input_amount": bool(r["ours_transfer_input_amount"]),
                              "delegatecall": bool(r["ours_delegatecall"]), "source": f"ours_{chain}"}
               for r in rows if r.get("chain") == chain and r.get("status") == "ok"}
        return eth, own

    eth, own = flags_by_hash()
    d6 = pd.read_parquet(INTERIM_DIR / "d6_delegates.parquet") if (INTERIM_DIR / "d6_delegates.parquet").exists() else None
    eth_hash = {} if d6 is None else {r.code_hash: eth[r.delegate] for r in d6.itertuples() if r.delegate in eth}
    tasks, seen = [], set()
    for a in dels:
        c = codes.get(a)
        if a in own or not c or c == "0x" or h[a] in eth_hash or h[a] in seen:
            continue
        seen.add(h[a])
        tasks.append((chain, "eip7702_delegate", a, c, timeout))
    print(f"{chain}: {len(dels)} delegate 7702, {int(n_eoa.sum()):,} EOA (key lộ {int(n_pk.sum()):,}); "
          f"trùng bytecode delegate ETH: {sum(h[a] in eth_hash for a in dels)}; cần symexec {len(tasks)}", flush=True)
    with ENGINE_SYMEXEC.open("a", encoding="utf-8") as f:
        for i, r in enumerate(run_isolated(tasks, workers=workers, hard_limit=timeout + 60, max_mem_mb=1500), 1):
            f.write(json.dumps(r) + "\n")
            f.flush()
            print(f"  {i}/{len(tasks)} {r['address'][:10]} {r.get('status')}", flush=True)
    eth, own = flags_by_hash()
    own_hash = {h[a]: v for a, v in own.items() if a in h}
    rows = []
    for a in dels:
        fl = own.get(a) or own_hash.get(h[a]) or eth_hash.get(h[a])
        rows.append({"chain": chain, "delegate": a, "n_eoa": int(n_eoa[a]), "n_eoa_pk": int(n_pk.get(a, 0)),
                     "code_hash": h[a], "has_code": codes.get(a) not in (None, "", "0x"),
                     "source": None if fl is None else fl["source"],
                     **{k: (None if fl is None else fl[k]) for k in ("all_eth", "msg_value", "input_amount", "delegatecall")},
                     "author_rule": None if fl is None else bool(fl["all_eth"] or fl["msg_value"])})
    out = pd.DataFrame(rows)
    path = INTERIM_DIR / f"l2_delegates_{chain}.parquet"
    out.to_parquet(path, index=False)
    ok = out.author_rule == True                                # noqa: E712
    print(f"có kết quả {out.author_rule.notna().sum()}/{len(out)}; đủ điều kiện ADDR: {int(ok.sum())} delegate, "
          f"{int(out.n_eoa[ok].sum()):,} EOA (key lộ {int(out.n_eoa_pk[ok].sum()):,}) → {path}")
    print(out.sort_values("n_eoa", ascending=False).head(12)[["delegate", "n_eoa", "n_eoa_pk", "source", "all_eth",
                                                            "msg_value", "input_amount", "author_rule"]].to_string(index=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["state", "txlist", "rules", "summary", "delegates"])
    ap.add_argument("--chain", choices=["arb", "op", "polygon"], required=True)
    ap.add_argument("--kinds", nargs="+", default=["KEY", "NCD", "PCD"])
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--max-records", type=int, default=MAX_RECORDS,
                    help="txlist tối đa mỗi địa chỉ (lượt đầu 1000 cho nhanh; địa chỉ bị cắt có cờ `truncated`)")
    ap.add_argument("--focus", choices=["all", "author"], default="all",
                    help="author: chỉ key lộ + dương CA của tác giả trên ETH/BSC")
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    if a.step == "state":
        cmd_state(a.chain, a.focus)
    elif a.step == "txlist":
        cmd_txlist(a.chain, a.kinds, a.focus, a.max_records)
    elif a.step == "rules":
        cmd_rules(a.chain, a.focus)
    elif a.step == "delegates":
        cmd_delegates(a.chain, a.timeout, a.workers)
    else:
        c = candidates(a.chain, a.focus)
        print(pd.crosstab(c.kind, c.xc, margins=True).to_string())


if __name__ == "__main__":
    main()
