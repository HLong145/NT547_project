"""Lô 2 của mẫu vàng (GOLD_PROTOCOL §2.7): âm dự phòng theo lô 50 + mẫu kiểm nhất quán của A.

- Âm dự phòng: các lô `--batches` của `draw_reserve` (thứ tự cố định tính từ trước khi gán, khớp `main_reserve_key.csv`).
  Bằng chứng tính bằng đúng `sample_gold.main_evidence` như lô 1 (tra trạng thái hôm nay mới cho các địa chỉ này).
- Mẫu kiểm nhất quán: `--per-batch` mẫu mỗi lô, rút ngẫu nhiên (seed cố định) từ các mẫu A đã gán đôi ở lô 1 mà nhãn cuối là
  dương. Dùng lại đúng dòng bằng chứng của `main_items.csv` (cùng ảnh chụp A đã thấy). Không tính vào ước lượng; chỉ đo độ
  nhất quán của A (A gán lại sau nhiều tuần, không biết đó là mẫu cũ).
- Đổi tên mọi mẫu (L001…) và xáo; ánh xạ về R####/G### chỉ có ở `batch2_key.csv` (gitignore, không đưa A).

    python -X utf8 -m address_misuse.gold_batch2 build --batches 1 2
    python -X utf8 -m address_misuse.gold_batch2 sheet
"""
from __future__ import annotations

import argparse
import hashlib

import numpy as np
import pandas as pd

from address_misuse.config import GOLD_DIR

ITEMS = GOLD_DIR / "batch2_items.csv"
KEY = GOLD_DIR / "batch2_key.csv"
SHEET_OUT = GOLD_DIR / "annotator_batch2_A.xlsx"
SEED = 20261108
LOOKUP2 = GOLD_DIR / "delegate_lookup_batch2.csv"   # delegate mới của lô 2 (bảng lô 1 đã đăng ký trước, không sửa)
A_DOUBLE = [GOLD_DIR / "annotator_main_double_A.xlsx", GOLD_DIR / "annotator_main_official_A.xlsx"]


def reserve_rows(batches: list[int]) -> pd.DataFrame:
    """Dòng dự phòng của các lô, rút lại từ dataset_v2 (cần `at`, `tx_hash`) và kiểm khớp với main_reserve_key.csv."""
    from address_misuse.config import FINAL_DIR
    from address_misuse.sample_gold import draw_reserve, engine_flag
    ds = pd.read_parquet(FINAL_DIR / "dataset_v2.parquet")
    ds["flag"] = engine_flag(ds)
    r = draw_reserve(ds, 0)
    key = pd.read_csv(GOLD_DIR / "main_reserve_key.csv", dtype=str)
    for c in ("item_id", "chain", "address", "cell"):
        if not (r[c].astype(str).values == key[c].values).all():
            raise SystemExit(f"rút lại danh sách dự phòng lệch main_reserve_key.csv ở cột {c}")
    if not (r.batch.astype(str).values == key.batch.values).all():
        raise SystemExit("lệch cột batch")
    return r[r.batch.isin(batches)].reset_index(drop=True)


def consistency_rows(n: int, seed: int = SEED) -> pd.DataFrame:
    """`n` mẫu A đã gán đôi ở lô 1 (cổng + κ chính thức) mà nhãn cuối là dương; dòng bằng chứng lấy từ main_items.csv."""
    from address_misuse.sample_gold import read_labels
    seen = set()
    for p in A_DOUBLE:
        seen |= set(read_labels(p).item_id)
    gold = pd.read_csv(GOLD_DIR / "gold_final.csv", dtype=str)
    pos = gold[(gold.is_misuse == "1") & gold.item_id.isin(seen)].item_id.sort_values().tolist()
    pick = sorted(np.random.default_rng(seed).choice(pos, size=n, replace=False).tolist())
    items = pd.read_csv(GOLD_DIR / "main_items.csv", dtype=str).fillna("-")
    return items[items.item_id.isin(pick)].reset_index(drop=True)


def build(batches: list[int], per_batch: int = 12) -> None:
    from address_misuse.sample_gold import MAIN_COLS, load_sources, main_evidence
    if ITEMS.exists() or KEY.exists():
        raise SystemExit(f"{ITEMS.name} / {KEY.name} đã có, không ghi đè")
    r = reserve_rows(batches)
    ev = main_evidence(r, load_sources())
    c = consistency_rows(per_batch * len(batches))
    allit = pd.concat([ev.assign(_src="reserve"), c.reindex(columns=MAIN_COLS).assign(_src="consistency")],
                      ignore_index=True)
    allit = allit.iloc[np.random.default_rng(SEED + 1).permutation(len(allit))].reset_index(drop=True)
    allit["orig_id"] = allit.item_id
    allit["item_id"] = [f"L{i + 1:03d}" for i in range(len(allit))]
    bmap = dict(zip(r.item_id, r.batch))
    key = allit[["item_id", "orig_id", "_src", "chain", "address"]].rename(columns={"_src": "source"})
    key["batch"] = key.orig_id.map(bmap).fillna(0).astype(int)
    key.to_csv(KEY, index=False, encoding="utf-8", lineterminator="\n")
    allit[MAIN_COLS].to_csv(ITEMS, index=False, encoding="utf-8")
    print(f"Ghi {len(allit)} mẫu ({len(ev)} dự phòng lô {batches}, {len(c)} kiểm nhất quán) → {ITEMS}; ánh xạ → {KEY}")
    for f in (ITEMS, KEY):
        print(f"  sha256 {f.name}: {hashlib.sha256(f.read_bytes()).hexdigest()}")


def new_delegates(items: pd.DataFrame, attx: pd.DataFrame | None = None) -> pd.DataFrame:
    """(chain, delegate) trong lô 2 (delegate hôm nay + ủy quyền trong tx mẫu) mà delegate_lookup.csv chưa có."""
    d = items[items.delegate_7702 != "-"][["chain", "delegate_7702"]].rename(columns={"delegate_7702": "delegate"})
    if attx is not None and len(attx):
        d = pd.concat([d, attx[["chain", "delegate"]]])
    d = d.assign(delegate=d.delegate.str.lower()).drop_duplicates()
    have = set()
    for f in (GOLD_DIR / "delegate_lookup.csv", LOOKUP2):
        if f.exists():
            lk = pd.read_csv(f, dtype=str, keep_default_na=False)
            have |= set(zip(lk.chain, lk.delegate.str.lower()))
    return d[[k not in have for k in zip(d.chain, d.delegate)]].reset_index(drop=True)


def check() -> None:
    import json

    from address_misuse import gold_attx
    from address_misuse.config import INTERIM_DIR
    items = pd.read_csv(ITEMS, dtype=str).fillna("-")
    cp = INTERIM_DIR / "attx_cache_batch2.json"
    cache = json.loads(cp.read_text(encoding="utf-8")) if cp.exists() else {}
    t, cache = gold_attx.build(items, cache)
    cp.write_text(json.dumps(cache), encoding="utf-8")
    t.to_csv(GOLD_DIR / "delegate_attx_batch2.csv", index=False, lineterminator="\n")
    nd = new_delegates(items, t)
    print(f"{len(gold_attx.candidates(items))} mẫu có thể 7702, {len(t)} ủy quyền của chính địa chỉ; "
          f"{len(nd)} delegate chưa có trong delegate_lookup.csv")
    if len(nd):
        print(nd.to_string())


def sheet() -> None:
    from address_misuse.sample_gold import GUIDE_MAIN, write_sheet
    nd = new_delegates(pd.read_csv(ITEMS, dtype=str).fillna("-"),
                       pd.read_csv(GOLD_DIR / "delegate_attx_batch2.csv", dtype=str))
    if len(nd):
        raise SystemExit(f"{len(nd)} delegate chưa có trong delegate_lookup.csv: phân loại + A, B rà trước (GOLD_PROTOCOL §2.3)")
    if LOOKUP2.exists():
        from address_misuse.sample_gold import check_delegates
        errs = check_delegates(pd.read_csv(LOOKUP2, dtype=str, keep_default_na=False), strict=True)
        if errs:
            raise SystemExit(f"{LOOKUP2.name} chưa được A, B rà xong (§2.3): " + "; ".join(errs))
    items = pd.read_csv(ITEMS, dtype=str).fillna("-")
    guide = [g for g in GUIDE_MAIN if not g.startswith("Thứ tự:")]
    guide.insert(-1, "Lô 2: một file. Mỗi phiên tối đa ~40 mẫu. Gán như lô 1, theo cùng CODEBOOK v0.6.4; bảng delegate = delegate_lookup.csv + delegate_lookup_batch2.csv.")
    write_sheet(items, SHEET_OUT, guide)
    print(f"Ghi {len(items)} mẫu → {SHEET_OUT}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--batches", type=int, nargs="+", default=[1, 2])
    b.add_argument("--per-batch", type=int, default=12)
    sub.add_parser("check")
    sub.add_parser("sheet")
    a = ap.parse_args()
    if a.cmd == "build":
        build(a.batches, a.per_batch)
    elif a.cmd == "check":
        check()
    else:
        sheet()
