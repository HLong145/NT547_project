"""Chạy lại symbolic execution trên bytecode của tác giả và so sánh với kết quả họ công bố.

python -m address_misuse.reproduce_symexec [--timeout 120] [--sample-misuse 150] [--workers 4]
python -m address_misuse.reproduce_symexec --summary-only      # chỉ tổng hợp từ file đã có
python -m address_misuse.reproduce_symexec --retry-failed --workers 1 --max-mem-mb 850   # chạy lại contract lỗi

Mỗi contract chạy trong một process riêng (bị kill nếu quá timeout + grace) → một contract làm crash
engine (tràn stack C, z3 hết bộ nhớ) không kéo sập cả lượt chạy. Kết quả ghi nối tiếp vào
data/interim/symexec_repro.jsonl ngay khi xong từng contract; chạy lại sẽ bỏ qua contract đã có (resume).
Tổng hợp cuối: data/interim/symexec_repro.parquet
"""

import argparse
import json
import sys
import threading
import time
from multiprocessing import Pipe, Process

import psutil

import pandas as pd

from address_misuse.config import INTERIM_DIR, SEED_DIR

FLAGS = ["delegatecall", "transfer_all_eth", "transfer_msg_value", "transfer_input_amount"]
JSONL = INTERIM_DIR / "symexec_repro.jsonl"
KEY = ["chain", "kind", "address"]


def _run(args) -> dict:
    from address_misuse.symexec import analyze
    chain, kind, address, bytecode, timeout = args
    try:
        res = analyze(address, bytecode, timeout_sec=timeout)
        row = {f"ours_{f}": bool(res[f]["valid"]) for f in FLAGS}
        row.update(ours_time_s=res["time"], ours_timed_out=res["timed_out"], status="ok", error=None)
    except BaseException as e:  # lỗi của engine trên một contract không được làm hỏng cả lượt chạy
        row = {f"ours_{f}": None for f in FLAGS}
        row.update(ours_time_s=None, ours_timed_out=None, status="error", error=repr(e)[:300])
    return {"chain": chain, "kind": kind, "address": address, **row}


def _child(args, conn):
    # Engine đệ quy theo basic block → chạy trong thread có stack lớn để tránh tràn stack C trên Windows.
    sys.setrecursionlimit(100_000)
    threading.stack_size(128 * 1024 * 1024)  # Windows: phải < 256 MB
    out = {}
    t = threading.Thread(target=lambda: out.update(_run(args)))
    t.start()
    t.join()
    conn.send(out)
    conn.close()


def _failed(task, status, error):
    chain, kind, address, _, _ = task
    return {"chain": chain, "kind": kind, "address": address, **{f"ours_{f}": None for f in FLAGS},
            "ours_time_s": None, "ours_timed_out": None, "status": status, "error": error}


def _rss_mb(pid: int) -> float:
    try:
        return psutil.Process(pid).memory_info().rss / 2**20
    except psutil.Error:
        return 0.0


def run_isolated(tasks, workers: int, hard_limit: float, max_mem_mb: float = 2500):
    """Chạy song song, mỗi task một process; yield từng kết quả ngay khi xong.
    Process bị kill nếu quá hard_limit giây hoặc dùng quá max_mem_mb RAM."""
    pending, running, done = list(reversed(tasks)), {}, 0
    while pending or running:
        while pending and len(running) < workers:
            task = pending.pop()
            parent, child = Pipe(duplex=False)
            p = Process(target=_child, args=(task, child), daemon=True)
            p.start()
            child.close()
            running[p.pid] = (p, parent, time.monotonic(), task)
        for pid, (p, conn, start, task) in list(running.items()):
            row = None
            try:
                ready = conn.poll()
            except (BrokenPipeError, OSError):  # process con chết, pipe đã đóng
                ready = False
            if ready:
                try:
                    row = conn.recv()
                except EOFError:
                    p.join(5)
                    row = _failed(task, "crash", f"exitcode={p.exitcode}")
            elif not p.is_alive():
                p.join()
                try:  # có thể kết quả đã gửi xong ngay trước khi process thoát
                    row = conn.recv() if conn.poll() else None
                except (EOFError, OSError):
                    row = None
                row = row or _failed(task, "crash", f"exitcode={p.exitcode}")
            elif time.monotonic() - start > hard_limit:
                p.kill()
                p.join()
                row = _failed(task, "killed", f"quá {hard_limit:.0f}s")
            elif (mem := _rss_mb(p.pid)) > max_mem_mb:
                p.kill()
                p.join()
                row = _failed(task, "oom", f"RAM {mem:.0f} MB > {max_mem_mb:.0f} MB")
            if row is not None:
                p.join(5)
                conn.close()
                del running[pid]
                done += 1
                yield row
        time.sleep(0.1)


def summarize():
    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 20)
    rows = [json.loads(l) for l in JSONL.read_text(encoding="utf-8").splitlines() if l.strip()]
    sr = pd.read_parquet(SEED_DIR / "symexec_results.parquet")
    out = pd.DataFrame(rows).drop_duplicates(KEY, keep="last").merge(sr, on=KEY)
    out.to_parquet(INTERIM_DIR / "symexec_repro.parquet", index=False)

    print(f"\n{len(out)} contract | trạng thái: {out.status.value_counts().to_dict()}")
    ok = out[out.status == "ok"]
    print(f"hết thời gian mềm (kết quả một phần): {int(ok.ours_timed_out.sum())}")
    agree = lambda g: pd.Series({f: round(float((g[f"ours_{f}"] == g[f].astype(bool)).mean()), 3) for f in FLAGS})
    print("\nTỉ lệ trùng với tác giả (trên contract chạy xong):")
    print(pd.concat([ok.groupby("kind").apply(agree, include_groups=False),
                     agree(ok).to_frame("ALL").T]).assign(n=list(ok.groupby("kind").size()) + [len(ok)]))
    full = ok[~ok.ours_timed_out.astype(bool)]
    print(f"\nChỉ contract không timeout ({len(full)}): "
          + json.dumps({f: round(float((full[f'ours_{f}'] == full[f].astype(bool)).mean()), 3) for f in FLAGS}))
    for f in FLAGS:
        a, o = ok[f].astype(bool), ok[f"ours_{f}"].astype(bool)
        print(f"  {f:22s} tác giả=1/ta=0: {int((a & ~o).sum()):3d}   tác giả=0/ta=1: {int((~a & o).sum()):3d}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=120, help="timeout mềm của engine (giây)")
    ap.add_argument("--grace", type=float, default=60, help="thêm giây trước khi kill process")
    ap.add_argument("--sample-misuse", type=int, default=150, help="số contract kind=misuse_address lấy mẫu")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max-mem-mb", type=float, default=2500, help="kill process con nếu RAM vượt ngưỡng")
    ap.add_argument("--retry-failed", action="store_true", help="chạy lại các contract oom/killed/crash/error")
    ap.add_argument("--summary-only", action="store_true")
    a = ap.parse_args()

    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    if not a.summary_only:
        bc = pd.read_parquet(SEED_DIR / "bytecode.parquet")
        sr = pd.read_parquet(SEED_DIR / "symexec_results.parquet")
        jobs = sr.merge(bc, on=KEY)
        jobs = jobs[jobs.bytecode.str.len() > 2]
        n_mis = int((jobs.kind == "misuse_address").sum())
        misuse = jobs[jobs.kind == "misuse_address"].sample(min(a.sample_misuse, n_mis), random_state=0)
        jobs = pd.concat([jobs[jobs.kind != "misuse_address"], misuse])

        done = set()
        if JSONL.exists():
            last = {}
            for l in JSONL.read_text(encoding="utf-8").splitlines():
                if l.strip():
                    r = json.loads(l)
                    last[tuple(r[k] for k in KEY)] = r["status"]
            done = {k for k, st in last.items() if st == "ok" or not a.retry_failed}
        tasks = [(r.chain, r.kind, r.address, r.bytecode, a.timeout) for r in jobs.itertuples()
                 if (r.chain, r.kind, r.address) not in done]
        print(f"{len(jobs)} contract, đã có {len(jobs) - len(tasks)}, cần chạy {len(tasks)} "
              f"(timeout {a.timeout:.0f}s + grace {a.grace:.0f}s, {a.workers} process, RAM ≤ {a.max_mem_mb:.0f} MB)", flush=True)

        t0 = time.monotonic()
        with JSONL.open("a", encoding="utf-8") as f:
            for i, row in enumerate(run_isolated(tasks, a.workers, a.timeout + a.grace, a.max_mem_mb), 1):
                f.write(json.dumps(row) + "\n")
                f.flush()
                if row["status"] != "ok":
                    print(f"  [{row['status']}] {row['chain']} {row['kind']} {row['address']}: {row['error']}", flush=True)
                if i % 10 == 0 or i == len(tasks):
                    print(f"  {i}/{len(tasks)}  ({time.monotonic() - t0:.0f}s)", flush=True)
    summarize()


if __name__ == "__main__":
    main()
