"""Đo độ trễ thêm của kiểm tra phía ví (PLAN_V2 §5 "Hiệu năng"; mục tiêu < 150 ms).

python -X utf8 -m address_misuse.wallet.bench [--n 300] [--timeout 0.3 0.15]
    → data/interim/wallet_bench.json + bảng p50/p95/p99

Lấy ngẫu nhiên `n` địa chỉ đích trong tập test (`engine_eval.parquet`, cả dương lẫn âm, ETH + BSC). Mỗi địa chỉ:
- lạnh: chưa có cache (gọi getCode 8 mạng song song, chờ tối đa `timeout`);
- ấm: gọi lại ngay (cache theo địa chỉ, ví thật sẽ trúng cache khi người dùng gửi lại cho cùng địa chỉ).
Ghi thêm tỉ lệ mạng không trả kịp, RAM của process, thời gian nạp bảng.
"""

import argparse
import json
import time

import numpy as np
import pandas as pd
import psutil

from address_misuse.config import INTERIM_DIR
from address_misuse.wallet.online import OnlineStore

EVAL = INTERIM_DIR / "engine_eval.parquet"
OUT = INTERIM_DIR / "wallet_bench.json"


def pct(x) -> dict:
    x = np.asarray(x, float)
    return {"p50": float(np.percentile(x, 50)), "p95": float(np.percentile(x, 95)),
            "p99": float(np.percentile(x, 99)), "max": float(x.max())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--timeout", type=float, nargs="+", default=[0.3, 0.15])
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    d = pd.read_parquet(EVAL).query("split == 'test'").drop_duplicates(["chain", "address"])
    d = d.sample(min(a.n, len(d)), random_state=a.seed)
    proc = psutil.Process()
    rss0 = proc.memory_info().rss / 2**20
    t = time.perf_counter()
    st = OnlineStore()
    load_s = time.perf_counter() - t
    st.warm()
    out = {"n": len(d), "load_s": load_s, "rss_mb": proc.memory_info().rss / 2**20 - rss0, "runs": {}}
    for to in a.timeout:
        st.timeout, st.cache = to, {}
        cold, warm, missed, dec = [], [], [], []
        for r in d.itertuples():
            c = st.check(r.address, r.chain, use_cache=False)
            w = st.check(r.address, r.chain)
            cold.append(c["ms_total"])
            warm.append(w["ms_total"])
            missed.append(len(c["missed_nets"]))
            dec.append(c["decision"])
        out["runs"][str(to)] = {"cold_ms": pct(cold), "warm_ms": pct(warm),
                                "share_all_nets": float(np.mean(np.array(missed) == 0)),
                                "mean_missed_nets": float(np.mean(missed)),
                                "under_150ms_cold": float(np.mean(np.array(cold) < 150)),
                                "decisions": pd.Series(dec).value_counts().to_dict()}
    out["cpu_percent"] = proc.cpu_percent(interval=None)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{out['n']} địa chỉ test; nạp bảng {load_s:.1f}s, RAM thêm {out['rss_mb']:.0f} MB")
    for to, r in out["runs"].items():
        c, w = r["cold_ms"], r["warm_ms"]
        print(f"timeout {float(to) * 1000:.0f} ms: lạnh p50 {c['p50']:.0f} / p95 {c['p95']:.0f} / p99 {c['p99']:.0f} ms "
              f"(< 150 ms: {r['under_150ms_cold']:.0%}); ấm p50 {w['p50']:.3f} / p99 {w['p99']:.3f} ms; "
              f"đủ 8 mạng {r['share_all_nets']:.0%}, thiếu TB {r['mean_missed_nets']:.2f} mạng; {r['decisions']}")
    print(f"ghi {OUT}")


if __name__ == "__main__":
    main()
