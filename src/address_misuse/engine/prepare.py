"""Dữ liệu bổ sung cho engine (RISK_SCORE.md §6). Mỗi bước có cache, chạy lại chỉ làm phần còn thiếu.

python -m address_misuse.engine.prepare creation    # thời điểm tạo contract trên chính chain (NCD về sau có code,
                                                    # PCD của mẫu đánh giá, N5)
python -m address_misuse.engine.prepare delegates   # symexec cho delegate EIP-7702 chưa có kết quả
python -m address_misuse.engine.prepare contracts   # symexec cho contract trong mẫu đánh giá chưa có kết quả (chủ yếu âm)
python -m address_misuse.engine.prepare sample      # mẫu đánh giá cố định (dương theo nhóm × chain, seed 0)
python -m address_misuse.engine.prepare history     # txlist cho địa chỉ không có trong BigQuery (ETH âm, mọi địa chỉ BSC)
python -m address_misuse.engine.prepare windows     # 1.000 tx gần nhất trước `at` cho mẫu âm theo tx có txlist bị cắt

Lịch sử: ETH âm N1/N6/N7 từ Etherscan; BSC (dương trong mẫu + âm) và các tập âm mới (N2–N4, N8) từ NodeReal
`nr_getTransactionByAddress`, đổi sang đúng định dạng txlist Etherscan để dùng chung `txlist_frame`.
"""

import argparse
import gzip
import json
import os
import time
from datetime import datetime, timezone

import pandas as pd
import requests

from address_misuse.config import INTERIM_DIR, SEED_DIR
from address_misuse.engine.features import (ENGINE_CODE, ENGINE_CREATION, ENGINE_SYMEXEC, HISTORY_WINDOW, MATRIX,
                                            load_symexec, txlist_path, txwin_path)

NODEREAL_URL = "https://bsc-mainnet.nodereal.io/v1/{}"
NODEREAL_CHAIN_URL = "https://{}-mainnet.nodereal.io/v1/{}"
ENGINE_SAMPLE = INTERIM_DIR / "engine_eval_sample.parquet"
SAMPLE_SIZES = {"NCD": 300, "PCD": 200, "KEY": 150, "ADDR": 150}     # mỗi chain
HISTORY_MAX_RECORDS = 10_000
HISTORY_MAX_RECORDS_INFRA = 1_000     # hạ tầng (N6/N7, đích của N2–N4/N8): 1.000 tx đầu, ghi `truncated`
ZERO = "0x" + "0" * 40
BYZANTIUM = {"eth": 4_370_000}     # trước block này receipt chưa có status


def _nodereal_creation(address: str, key: str) -> dict | None:
    r = requests.post(NODEREAL_URL.format(key), json={"jsonrpc": "2.0", "id": 1, "method":
                                                      "nr_getContractCreationTransaction", "params": [address]},
                      timeout=30).json()
    return r.get("result") or None


def cmd_creation():
    m = pd.read_parquet(MATRIX)
    todo = m[(m.misuse_chain_state == "code") & (m.subtype == "NCD")][["chain", "address"]]
    # PCD + N5: cần thời điểm tạo để chọn tx trước (PCD, Rule 2) / sau (N5) khi tạo (engine.evaluate.pick_event)
    s = pd.read_parquet(ENGINE_SAMPLE).query("subtype == 'PCD'")[["chain", "address"]]
    n5 = INTERIM_DIR / "n5_recovery_contracts.parquet"
    n5 = pd.read_parquet(n5).query("kept")[["chain", "address"]] if n5.exists() else s.iloc[:0]
    todo = pd.concat([todo, s, n5]).assign(address=lambda d: d.address.str.lower()).drop_duplicates()
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


def cmd_contracts(timeout: float = 120, workers: int = 4):
    """Symexec mọi contract trong `engine_eval` chưa có kết quả. Trước đây chỉ dương (ứng viên của tác giả) có symexec,
    âm nhận điểm mặc định UNKNOWN_CODE → S_bytecode lệch theo nhãn (FINDINGS 2026-10-24). Proxy chưa có trong
    `proxy_map` được phân tích trên chính bytecode proxy (có DELEGATECALL → không phải T2)."""
    from address_misuse.crosschain import get_code
    from address_misuse.engine.features import FeatureStore
    from address_misuse.reproduce_symexec import run_isolated
    ev = pd.read_parquet(INTERIM_DIR / "engine_eval.parquet").query("state == 'code'")
    fs = FeatureStore()
    todo = sorted({(r.chain, r.address) for r in ev.itertuples() if fs._symexec_of(r.chain, r.address) is None})
    print(f"contract trong mẫu đánh giá: {ev[['chain', 'address']].drop_duplicates().shape[0]}, chưa có symexec: "
          f"{len(todo)}", flush=True)
    tasks = []
    for chain, a in todo:
        try:
            code = get_code(chain, a)
        except Exception as e:                                # RPC lỗi: lần chạy sau thử lại
            print(f"  getCode lỗi {chain} {a}: {e!r:.80}")
            continue
        if code and code != "0x":
            tasks.append((chain, "eval_contract", a, code, timeout))
    print(f"chạy symexec {len(tasks)} contract, {workers} tiến trình, timeout {timeout:.0f}s", flush=True)
    with ENGINE_SYMEXEC.open("a", encoding="utf-8") as f:
        for i, r in enumerate(run_isolated(tasks, workers=workers, hard_limit=timeout + 60, max_mem_mb=1500), 1):
            f.write(json.dumps(r) + "\n")
            f.flush()
            if i % 20 == 0 or i == len(tasks):
                print(f"  {i}/{len(tasks)}", flush=True)


def cmd_sample(seed: int = 0):
    """Mẫu dương cố định cho đánh giá engine: SAMPLE_SIZES địa chỉ mỗi nhóm × chain (không trùng địa chỉ)."""
    if ENGINE_SAMPLE.exists():
        print(f"đã có {ENGINE_SAMPLE}; xoá file nếu muốn lấy lại")
        return
    ca = pd.read_parquet(MATRIX)[["chain", "address", "subtype"]]
    eoa = pd.read_parquet(SEED_DIR / "eoa_misuse.parquet")[["chain", "address", "subtype"]]
    df = pd.concat([ca, eoa], ignore_index=True)
    df["address"] = df.address.str.lower()
    parts = []
    for (_, sub), g in df.drop_duplicates(["chain", "address"]).groupby(["chain", "subtype"]):
        parts.append(g.sample(min(SAMPLE_SIZES[sub], len(g)), random_state=seed))
    out = pd.concat(parts, ignore_index=True)
    out.to_parquet(ENGINE_SAMPLE, index=False)
    print(out.groupby(["chain", "subtype"]).size().to_string())


def negative_addresses() -> dict[tuple[str, str], list[str]]:
    """(nhóm, chain) → địa chỉ cần lịch sử. N2–N4/N8 lấy cột `target` (địa chỉ nhận tx) nếu có."""
    out = {}
    n1 = pd.read_parquet(INTERIM_DIR / "n1_random_unflagged.parquet")
    for ch in ("eth", "bsc"):
        out[("N1", ch)] = sorted(set(n1[n1.chain == ch].address.str.lower()))
    n6 = pd.read_parquet(INTERIM_DIR / "n6_benign_7702_delegates.parquet").query("kept").address
    n7 = pd.read_parquet(INTERIM_DIR / "n7_multichain_contracts.parquet").query("kept").address
    out[("N6+N7", "eth")] = sorted(set(pd.concat([n6, n7]).str.lower()))
    out[("N7", "bsc")] = sorted(set(n7.str.lower()))
    p = INTERIM_DIR / "n5_recovery_contracts.parquet"
    if p.exists():
        n5 = pd.read_parquet(p).query("kept")
        for ch, g in n5.groupby("chain"):
            out[("N5", ch)] = sorted(set(g.address.str.lower()))
    for name in ("n2_contract_calls", "n3_text_messages", "n4_exchange_deposits", "n8_normal_txs"):
        p = INTERIM_DIR / f"{name}.parquet"
        if p.exists():
            d = pd.read_parquet(p)
            col = "target" if "target" in d else "address"
            for ch, g in d.groupby("chain"):
                out[(name.split("_")[0].upper(), ch)] = sorted(set(g[col].str.lower()))
    return out


def _nodereal_record(t: dict, idx: int, chain: str = "eth") -> dict:
    """Bản ghi `nr_getTransactionByAddress` → bản ghi txlist kiểu Etherscan.

    NodeReal không trả transactionIndex: dùng thứ tự trong block theo kết quả `asc` (đủ cho rule sweep, vốn chỉ cần
    tx nạp đứng trước tx rút). Trước Byzantium NodeReal trả status 0 cho mọi tx; dùng cùng quy ước với BigQuery
    (lỗi ⇔ dùng hết gas)."""
    ca = (t.get("contractAddress") or "").lower()
    ca = "" if ca == ZERO else ca
    to = (t.get("to") or "").lower()
    block = int(t["blockNum"], 16)
    if block < BYZANTIUM.get(chain, 0):
        status = int(int(t.get("gasUsed") or 0) < int(t.get("gas") or 0))
    else:
        status = int(t.get("receiptsStatus") or 0)
    return {"blockNumber": str(block), "transactionIndex": str(idx),
            "timeStamp": str(int(t["blockTimeStamp"])), "hash": t.get("hash"), "from": (t.get("from") or "").lower(),
            "to": "" if (ca and to in ("", ZERO)) else to, "value": str(int(t["value"], 16)), "gas": str(t.get("gas")),
            "gasPrice": str(t.get("gasPrice") or 0), "gasUsed": str(t.get("gasUsed") or 0),
            "isError": "0" if status == 1 else "1", "txreceipt_status": str(status), "input": t.get("input") or "0x",
            "contractAddress": ca}


def nodereal_transfers(chain: str, key: str, params: dict, retries: int = 5) -> dict:
    """Một lần gọi `nr_getTransactionByAddress` (250 CU), thử lại khi lỗi. Lỗi không in URL vì URL chứa API key."""
    err = None
    for attempt in range(retries):
        try:
            j = requests.post(NODEREAL_CHAIN_URL.format(chain, key), json={
                "jsonrpc": "2.0", "id": 1, "method": "nr_getTransactionByAddress", "params": [params]},
                timeout=120).json()
            if "error" not in j:
                return j.get("result") or {}
            err = j["error"]
        except Exception as e:
            err = type(e).__name__
        time.sleep(2 * 2 ** attempt)
    raise RuntimeError(f"NodeReal {chain} {params.get('address')}: {str(err)[:200]}")


def nodereal_txlist(chain: str, address: str, key: str, max_records: int) -> tuple[list[dict], bool]:
    """Tx ngoài (external) của địa chỉ theo thứ tự thời gian, tối đa `max_records` (1.000 tx/trang)."""
    out, page = [], None
    while True:
        prm = {"category": ["external"], "address": address, "order": "asc", "maxCount": "0x3e8"}
        if page:
            prm["pageKey"] = page
        res = nodereal_transfers(chain, key, prm)
        out += res.get("transfers") or []
        page = res.get("pageKey")
        if not page or len(out) >= max_records:
            break
    truncated = bool(page) or len(out) > max_records
    recs, prev, idx = [], None, 0
    for t in out[:max_records]:
        idx = idx + 1 if t["blockNum"] == prev else 0
        prev = t["blockNum"]
        recs.append(_nodereal_record(t, idx, chain))
    return recs, truncated


def fetch_nodereal(chain: str, address: str, key: str, max_records: int) -> None:
    p = txlist_path(chain, address)
    if p.exists():
        return
    txs, truncated = nodereal_txlist(chain, address, key, max_records)
    rec = {"address": address, "chain": chain, "source": "nodereal",
           "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "truncated": truncated,
           "result": txs}
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(rec, f)
    tmp.replace(p)


def cmd_history():
    """ETH N1 (≤ 10k tx) và N6/N7 (1.000 tx đầu, Etherscan ~45 s/trang với hạ tầng) qua Etherscan;
    BSC (dương trong mẫu đánh giá + âm) và các tập âm mới qua NodeReal."""
    from address_misuse.etherscan import Etherscan
    from address_misuse.reproduce_rules import fetch_txlist
    neg = negative_addresses()
    es = Etherscan("eth")
    # dương ETH cũng lấy txlist (trước chỉ có BigQuery, không input): cùng nguồn với âm, chạy được bộ lọc IDM / T3
    pos_eth = sorted(set(pd.read_parquet(ENGINE_SAMPLE).query("chain == 'eth'").address)) if ENGINE_SAMPLE.exists() else []
    for grp, addrs, max_records in (("dương", pos_eth, HISTORY_MAX_RECORDS), ("N1", neg[("N1", "eth")], HISTORY_MAX_RECORDS),
                                    ("N6+N7", neg[("N6+N7", "eth")], HISTORY_MAX_RECORDS_INFRA)):
        addrs = [a for a in addrs if not txlist_path("eth", a).exists()]
        print(f"txlist Etherscan {grp} eth: {len(addrs)} địa chỉ (tối đa {max_records:,} tx/địa chỉ)", flush=True)
        for i, a in enumerate(addrs, 1):
            fetch_txlist(es, a, max_records=max_records)
            if i % 25 == 0 or i == len(addrs):
                print(f"  {i}/{len(addrs)}", flush=True)
    key = os.environ.get("NODEREAL_API_KEY")
    if not key:
        print("bỏ qua NodeReal: thiếu NODEREAL_API_KEY")
        return
    jobs = []
    if ENGINE_SAMPLE.exists():
        s = pd.read_parquet(ENGINE_SAMPLE).query("chain == 'bsc'")
        jobs.append(("dương", "bsc", sorted(set(s.address)), HISTORY_MAX_RECORDS))
    jobs.append(("N1", "bsc", neg[("N1", "bsc")], HISTORY_MAX_RECORDS))
    jobs.append(("N7", "bsc", neg[("N7", "bsc")], HISTORY_MAX_RECORDS_INFRA))
    for (grp, ch), addrs in sorted(neg.items()):
        if grp in ("N2", "N3", "N4", "N8"):
            jobs.append((grp, ch, addrs, HISTORY_MAX_RECORDS_INFRA))
        elif grp == "N5":                                         # contract recovery: ít tx, lấy như dương
            jobs.append((grp, ch, addrs, HISTORY_MAX_RECORDS))
    for grp, ch, addrs, max_records in jobs:
        addrs = [a for a in addrs if not txlist_path(ch, a).exists()]
        print(f"txlist NodeReal {grp} {ch}: {len(addrs)} địa chỉ (tối đa {max_records:,} tx/địa chỉ)", flush=True)
        for i, a in enumerate(addrs, 1):
            try:
                fetch_nodereal(ch, a, key, max_records)
            except RuntimeError as e:                             # lần chạy sau thử lại
                print(f"  lỗi {e}", flush=True)
            if i % 50 == 0 or i == len(addrs):
                print(f"  {i}/{len(addrs)}", flush=True)


def window_targets() -> pd.DataFrame:
    """Mẫu âm theo tx (N2, N3, N8) mà txlist đã cache bị cắt (1.000 tx đầu) trước `at`: lịch sử gần `at` bị thiếu."""
    parts = [pd.read_parquet(INTERIM_DIR / f"{n}.parquet", columns=["chain", "target", "block_number", "block_ts"])
             for n in ("n2_contract_calls", "n3_text_messages", "n8_normal_txs")]
    d = pd.concat(parts, ignore_index=True).rename(columns={"target": "address"})
    d["address"] = d.address.str.lower()
    last = {}
    for k in set(zip(d.chain, d.address)):
        p = txlist_path(*k)
        if p.exists():
            with gzip.open(p, "rt", encoding="utf-8") as f:
                rec = json.load(f)
            ts = [int(t["timeStamp"]) for t in rec["result"]]
            last[k] = max(ts) if rec.get("truncated") and ts else None
    d["cut_ts"] = [last.get(k) for k in zip(d.chain, d.address)]
    d = d[d.cut_ts.notna() & (d.block_ts > d.cut_ts)]
    return d.drop_duplicates(["chain", "address", "block_ts"])


WINDOW_SPAN_BSC = 99_999          # NodeReal giới hạn khoảng block mỗi lần gọi (BSC chấp nhận ~1e5)
WINDOW_MAX_CALLS = 30


def _window_nodereal(chain: str, address: str, block: int, key: str) -> tuple[list[dict], bool]:
    """Lùi từng đoạn `WINDOW_SPAN_BSC` block từ `block - 1` tới khi đủ `HISTORY_WINDOW` tx (desc)."""
    out, hi = [], block - 1
    for _ in range(WINDOW_MAX_CALLS):
        lo = max(0, hi - WINDOW_SPAN_BSC)
        res = nodereal_transfers(chain, key, {"category": ["external"], "address": address, "order": "desc",
                                              "maxCount": hex(HISTORY_WINDOW - len(out)), "fromBlock": hex(lo),
                                              "toBlock": hex(hi)})
        out += res.get("transfers") or []
        if len(out) >= HISTORY_WINDOW or lo == 0:
            return out[:HISTORY_WINDOW], True
        hi = lo - 1
    return out, False


def fetch_window(chain: str, address: str, block: int, at: int, key: str | None, es=None) -> None:
    """`HISTORY_WINDOW` tx gần nhất trước block `block`: ETH qua Etherscan (một lần gọi desc), BSC qua NodeReal."""
    p = txwin_path(chain, address, at)
    if p.exists():
        return
    if chain == "eth":
        data = es.call("account", "txlist", address=address, startblock=0, endblock=block - 1, page=1,
                       offset=HISTORY_WINDOW, sort="desc")
        recs, complete, source = list(reversed(data.get("result") or [])), True, "etherscan"
    else:
        out, complete = _window_nodereal(chain, address, block, key)
        recs, prev, idx = [], None, 0
        for t in reversed(out):                                   # về thứ tự tăng dần để đánh transactionIndex
            idx = idx + 1 if t["blockNum"] == prev else 0
            prev = t["blockNum"]
            recs.append(_nodereal_record(t, idx, chain))
        source = "nodereal"
    rec = {"address": address, "chain": chain, "source": source, "to_block": block - 1, "at": at, "complete": complete,
           "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "result": recs}
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(rec, f)
    tmp.replace(p)


def cmd_windows(workers: int = 4):
    from concurrent.futures import ThreadPoolExecutor
    from address_misuse.etherscan import Etherscan
    key = os.environ.get("NODEREAL_API_KEY")
    es = Etherscan("eth")
    d = window_targets()
    if not key:
        print("thiếu NODEREAL_API_KEY: chỉ lấy ETH", flush=True)
        d = d[d.chain == "eth"]
    todo = [r for r in d.itertuples() if not txwin_path(r.chain, r.address, r.block_ts).exists()]
    print(f"cửa sổ lịch sử: {len(d)} mẫu có txlist bị cắt trước at, còn {len(todo)} cần lấy", flush=True)

    def job(r):
        try:
            fetch_window(r.chain, r.address, int(r.block_number), int(r.block_ts), key, es)
            return None
        except Exception as e:                                     # lần chạy sau thử lại
            return str(e)[:120]

    err = 0
    with ThreadPoolExecutor(workers) as ex:
        for i, e in enumerate(ex.map(job, todo), 1):
            err += e is not None
            if i % 100 == 0 or i == len(todo):
                print(f"  {i}/{len(todo)} (lỗi {err})", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["creation", "delegates", "contracts", "sample", "history", "windows"])
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=120, help="giây symexec mỗi delegate")
    a = ap.parse_args()
    {"creation": cmd_creation, "delegates": lambda: cmd_delegates(a.timeout), "contracts": lambda: cmd_contracts(a.timeout),
     "sample": cmd_sample,
     "history": cmd_history, "windows": lambda: cmd_windows(a.workers)}[a.step]()


if __name__ == "__main__":
    main()
