"""D7: OSINT GitHub cho S_osint. Với mỗi địa chỉ, tra GitHub code search: bao nhiêu file / repo công khai nhắc tới nó và
ngữ cảnh (đường dẫn test / ví dụ / README). Chỉ dùng địa chỉ công khai; không đọc, không lưu nội dung file, càng không có
private key. Token trong `.env` (`GITHUB_TOKEN`, không cần scope nào).

python -X utf8 -m address_misuse.osint_github run [--limit N]    # tra theo thứ tự ưu tiên, resume được
python -X utf8 -m address_misuse.osint_github summary            # thống kê theo nhãn (dương / âm)

Thứ tự ưu tiên: dương theo thiệt hại giảm dần, rồi âm xáo ngẫu nhiên (seed cố định), vì S_osint phải chạy CÙNG quy trình cho
mọi mẫu (RISK_SCORE §2.3). Code search giới hạn 10 lượt/phút nên ~6,5 s/địa chỉ; kết quả cache ở
`data/raw/osint/github.jsonl` (mỗi dòng một địa chỉ), nên dừng lúc nào cũng được.
"""

import argparse
import json
import os
import re
import time

import numpy as np
import pandas as pd
import requests

from address_misuse.config import FINAL_DIR, RAW_DIR

OUT = RAW_DIR / "osint" / "github.jsonl"
GAP = 6.5                                                 # giây giữa hai lượt (code search: 10 lượt/phút)
CONTEXT_RE = re.compile(r"(^|/)(tests?|__tests__|spec|mocks?|examples?|samples?|fixtures?|demo|docs?|scripts?)(/|$)|"
                        r"readme|\.test\.|\.spec\.|\.md$|\.t\.sol$", re.I)


def queue(seed: int = 0) -> list[str]:
    """Địa chỉ (chữ thường) cần tra, theo thứ tự ưu tiên; ETH và BSC dùng chung một chuỗi địa chỉ nên chỉ tra một lần."""
    ds = pd.read_parquet(FINAL_DIR / "dataset_v2.parquet")
    ds["a"] = ds.address.str.lower()
    pos = ds[ds.label == 1].assign(loss=lambda d: pd.to_numeric(d.loss_native, errors="coerce").fillna(0))
    pos = pos.sort_values("loss", ascending=False).a.drop_duplicates().tolist()
    neg = ds[(ds.label == 0) & ~ds.a.isin(set(pos))].a.drop_duplicates().tolist()
    np.random.default_rng(seed).shuffle(neg)
    return pos + neg


def done() -> set[str]:
    if not OUT.exists():
        return set()
    with open(OUT, encoding="utf-8") as f:
        return {json.loads(line)["address"] for line in f if line.strip()}


def search(address: str, token: str) -> dict:
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    for attempt in range(8):
        r = requests.get("https://api.github.com/search/code", params={"q": f'"{address}"', "per_page": 100}, headers=h, timeout=60)
        if r.status_code == 200:
            j = r.json()
            items = j.get("items") or []
            paths = [it["path"] for it in items]
            repos = sorted({it["repository"]["full_name"] for it in items})
            return {"address": address, "total_count": j.get("total_count", 0), "incomplete": j.get("incomplete_results", False),
                    "n_items": len(items), "n_repos": len(repos), "repos": repos[:10],
                    "n_context": sum(bool(CONTEXT_RE.search(p)) for p in paths), "paths": paths[:5], "ts": int(time.time())}
        if r.status_code in (403, 429):                   # giới hạn thứ cấp hoặc hết lượt: chờ theo header
            wait = int(r.headers.get("Retry-After") or 0)
            reset = int(r.headers.get("X-RateLimit-Reset") or 0)
            if not wait and r.headers.get("X-RateLimit-Remaining") == "0":
                wait = max(0, reset - int(time.time())) + 2
            wait = wait or 60 * (attempt + 1)
            print(f"  GitHub {r.status_code}, chờ {wait}s", flush=True)
            time.sleep(wait)
            continue
        if r.status_code == 422:                          # truy vấn không hợp lệ: ghi nhận, không thử lại
            return {"address": address, "total_count": None, "error": "422", "ts": int(time.time())}
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"GitHub search {address}: không có kết quả sau 8 lần thử")


def run(limit: int | None = None) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("thiếu GITHUB_TOKEN trong .env")
    have = done()
    todo = [a for a in queue() if a not in have]
    if limit:
        todo = todo[:limit]
    print(f"cần tra {len(todo):,} địa chỉ (đã có {len(have):,})", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    for i, a in enumerate(todo, 1):
        t = time.monotonic()
        rec = search(a, token)
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if i % 50 == 0 or i == len(todo):
            print(f"  {i:,}/{len(todo):,} ({time.monotonic() - t0:.0f}s)", flush=True)
        time.sleep(max(0.0, GAP - (time.monotonic() - t)))


def summary() -> None:
    d = pd.read_json(OUT, lines=True)
    ds = pd.read_parquet(FINAL_DIR / "dataset_v2.parquet")
    ds["address"] = ds.address.str.lower()
    m = ds[["address", "label", "grp"]].drop_duplicates("address").merge(d, on="address", how="inner")
    m["hit"] = m.total_count.fillna(0) > 0
    print(f"{len(d):,} địa chỉ đã tra, {int(m.hit.sum()):,} có kết quả")
    print(m.groupby("label").agg(n=("hit", "size"), hit=("hit", "mean"), median_files=("total_count", "median")).round(3).to_string())
    print(m.groupby("grp").agg(n=("hit", "size"), hit=("hit", "mean")).round(3).to_string())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "summary"])
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    run(a.limit) if a.cmd == "run" else summary()


if __name__ == "__main__":
    main()
