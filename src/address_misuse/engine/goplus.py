"""Baseline GoPlus Address Security API (PLAN_V2 §4): công cụ cảnh báo địa chỉ có sẵn, miễn phí, không cần key.

python -m address_misuse.engine.goplus fetch [--workers 3]   → data/raw/goplus/address_security.jsonl (tự tiếp tục)
python -m address_misuse.engine.goplus summary               → tỉ lệ bị gắn cờ theo nhóm mẫu

Cảnh báo = bất kỳ cờ độc hại nào (`FLAGS`) bằng 1, hoặc `number_of_malicious_contracts_created` > 0.
Giới hạn (ghi trong paper): GoPlus trả trạng thái **hiện tại** (lúc tra, `fetched_at`), không phải tại `at` của mẫu
→ GoPlus được lợi vì biết sau sự việc; ngược lại GoPlus chỉ có một nhãn cho mỗi địa chỉ, không xét ngữ cảnh tx.
"""

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import requests

from address_misuse.config import INTERIM_DIR, RAW_DIR

URL = "https://api.gopluslabs.io/api/v1/address_security/{}"
CHAIN_ID = {"eth": "1", "bsc": "56"}
CACHE = RAW_DIR / "goplus" / "address_security.jsonl"
EVAL = INTERIM_DIR / "engine_eval.parquet"
FLAGS = ["cybercrime", "money_laundering", "financial_crime", "darkweb_transactions", "phishing_activities",
         "fake_kyc", "blacklist_doubt", "stealing_attack", "blackmail_activities", "sanctioned",
         "malicious_mining_activities", "mixer", "fake_token", "honeypot_related_address", "gas_abuse", "reinit",
         "fake_standard_interface"]
RETRIES = 5


def load_cache() -> pd.DataFrame:
    if not CACHE.exists():
        return pd.DataFrame(columns=["chain", "address", "fetched_at", "result"])
    rows = [json.loads(l) for l in CACHE.read_text(encoding="utf-8").splitlines() if l.strip()]
    return pd.DataFrame(rows).drop_duplicates(["chain", "address"], keep="last")


def flagged(result: dict | None) -> bool | None:
    if not result:
        return None
    return any(result.get(k) == "1" for k in FLAGS) or int(result.get("number_of_malicious_contracts_created") or 0) > 0


def flags_frame() -> pd.DataFrame:
    """(chain, address) → goplus_flag (bool), goplus_types (các cờ bật), fetched_at."""
    c = load_cache()
    if not len(c):
        return pd.DataFrame(columns=["chain", "address", "goplus_flag", "goplus_types", "fetched_at"])
    c["goplus_flag"] = [flagged(r) for r in c.result]
    c["goplus_types"] = [",".join(k for k in FLAGS if (r or {}).get(k) == "1") for r in c.result]
    return c[["chain", "address", "goplus_flag", "goplus_types", "fetched_at"]]


def query(chain: str, address: str, session: requests.Session) -> dict:
    for i in range(RETRIES):
        try:
            r = session.get(URL.format(address), params={"chain_id": CHAIN_ID[chain]}, timeout=30)
            j = r.json()
            if r.status_code == 200 and j.get("code") == 1 and j.get("result") is not None:
                return {"chain": chain, "address": address, "fetched_at": int(time.time()), "result": j["result"]}
        except (requests.RequestException, ValueError):
            pass
        time.sleep(2 ** i)                                   # code ≠ 1 thường là quá giới hạn tốc độ (4029)
    return {"chain": chain, "address": address, "fetched_at": int(time.time()), "result": None}


def cmd_fetch(workers: int):
    df = pd.read_parquet(EVAL)
    todo = df[df.chain.isin(CHAIN_ID)][["chain", "address"]].drop_duplicates()
    done = load_cache()
    done = set(zip(done.chain, done.address)) if len(done) else set()
    todo = [(c, a) for c, a in zip(todo.chain, todo.address) if (c, a) not in done]
    print(f"GoPlus: {len(todo)} địa chỉ chưa tra ({len(done)} đã có)", flush=True)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    s = requests.Session()
    n_err = 0
    with ThreadPoolExecutor(workers) as ex, CACHE.open("a", encoding="utf-8") as f:
        for i, row in enumerate(ex.map(lambda k: query(*k, s), todo), 1):
            if row["result"] is None:
                n_err += 1
                continue                                     # không ghi: lần chạy sau tra lại
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            if i % 200 == 0:
                f.flush()
                print(f"  {i}/{len(todo)} (lỗi {n_err})", flush=True)
    print(f"xong, lỗi {n_err}")


def cmd_summary():
    df = pd.read_parquet(EVAL).merge(flags_frame(), on=["chain", "address"], how="left")
    t = df.groupby(["grp", "chain"]).agg(n=("label", "size"), tra=("goplus_flag", lambda x: x.notna().mean()),
                                         co=("goplus_flag", lambda x: x.fillna(False).astype(bool).mean())).round(3)
    print(t.to_string())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["fetch", "summary"])
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    cmd_fetch(a.workers) if a.cmd == "fetch" else cmd_summary()


if __name__ == "__main__":
    main()
