"""Tên hàm theo selector, thay cho `functionName = "?"` ở dữ liệu không phải Etherscan (NodeReal, Blockscout).

Luật NCD của tác giả cần `functionName != ""`, mà Etherscan chỉ gắn tên khi selector có trong cơ sở chữ ký hàm của nó.
Gán "?" cho mọi input ≥ 10 ký tự làm NCD gắn cờ nhiều hơn tác giả. Ở đây ta học ánh xạ selector → tên từ chính các
txlist ETH của Etherscan đã tải (`data/raw/eth/txlist`): selector được coi là "có tên" nếu ≥ 50% tx ETH mang selector đó
có `functionName`, còn lại là "" (selector chưa từng gặp cũng là ""). Xấp xỉ, vì Etherscan còn dựa vào ABI của từng
contract: kiểm giữ lại một nửa số địa chỉ (học trên nửa kia) cho độ chính xác 0,70 (precision 0,73, recall 0,74), so với
0,57 nếu gán "?" cho mọi input ≥ 10 ký tự. Số liệu NCD ở BSC / L2 vì vậy là ước lượng, không phải số chính xác.

python -m address_misuse.selectors build   → data/interim/known_selectors.parquet (selector, function_name)
"""

import argparse
import gzip
import json
from collections import Counter
from functools import lru_cache

import pandas as pd

from address_misuse.config import INTERIM_DIR, RAW_DIR

OUT = INTERIM_DIR / "known_selectors.parquet"
NAMED_RATE = 0.5                                        # tỉ lệ tx ETH có functionName để coi selector là có tên


def build() -> pd.DataFrame:
    names: dict[str, Counter] = {}
    rate: dict[str, list[int]] = {}
    files = list((RAW_DIR / "eth" / "txlist").glob("*.json.gz"))
    for p in files:
        try:
            with gzip.open(p, "rt", encoding="utf-8") as f:
                txs = json.load(f).get("result") or []
        except (OSError, ValueError):
            continue
        for t in txs:
            fn, inp = t.get("functionName") or "", t.get("input") or "0x"
            if len(inp) >= 10:
                r = rate.setdefault(inp[:10].lower(), [0, 0])
                r[0] += bool(fn)
                r[1] += 1
                if fn:
                    names.setdefault(inp[:10].lower(), Counter())[fn] += 1
    df = pd.DataFrame([{"selector": s, "function_name": names[s].most_common(1)[0][0]}
                       for s, (named, n) in sorted(rate.items()) if named / n >= NAMED_RATE])
    df.to_parquet(OUT, index=False)
    print(f"{len(files)} txlist ETH → {len(df)} selector có tên → {OUT}")
    return df


@lru_cache(maxsize=1)
def known() -> dict[str, str]:
    if not OUT.exists():
        raise FileNotFoundError(f"thiếu {OUT}: chạy `python -m address_misuse.selectors build`")
    d = pd.read_parquet(OUT)
    return dict(zip(d.selector, d.function_name))


def function_name(input_hex: str | None) -> str:
    """Tên hàm Etherscan sẽ gắn cho `input`; "" nếu selector chưa từng được Etherscan gắn tên."""
    inp = input_hex or "0x"
    return known().get(inp[:10].lower(), "") if len(inp) >= 10 else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build"])
    ap.parse_args()
    build()


if __name__ == "__main__":
    main()
