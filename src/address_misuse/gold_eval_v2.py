"""Đánh giá engine v2 (GOLD_PROTOCOL §10) trên nhãn vàng.

- `dev`: lô 1 (758 mẫu). v2 được thiết kế SAU khi xem FN của v1 trên lô 1, nên đây là kết quả **trong mẫu / khám phá**, không
  thay kết quả chính (v1 đóng băng). Báo kèm các bản bỏ từng luật (ablation) và độ phủ lịch sử.
- `heldout`: lô 2 (khi A gán xong; §10.3). Chưa có nhãn lô 2 lúc viết module này.

    python -X utf8 -m address_misuse.gold_eval_v2 dev [--boot 1000]
"""
from __future__ import annotations

import argparse
import json

import pandas as pd

from address_misuse.config import GOLD_DIR, INTERIM_DIR
from address_misuse.engine import v2
from address_misuse.gold_eval import ca7_unlabelled, delegate_decided, evaluate
from address_misuse.gold_final import OUT as GOLD_FINAL, _frame, _pool, _short, detector_flags

DEV_OUT = INTERIM_DIR / "gold_eval_v2_dev.json"


def addr_flags(key: pd.DataFrame, rows: pd.DataFrame, col: str) -> pd.DataFrame:
    """Cờ theo địa chỉ từ cột dòng `col` (có dòng nào trong khung bị cảnh báo), cùng khuôn với `gold_final.detector_flags`."""
    g = rows.groupby(["chain", "address"]).agg(f=(col, "any"), R=("R_frozen", "max"),
                                                hard=("hard_v2", lambda x: ",".join(sorted(set(x.dropna())))))
    k = key.join(g, on=["chain", "address"])
    return k[["item_id"]].assign(flag=k.f.astype(bool), flag_design=k.f.astype(bool), R=k.R, hard=k.hard)


def dev(boot: int = 1000) -> dict:
    gold = pd.read_csv(GOLD_FINAL, dtype=str, keep_default_na=False)
    key = pd.read_csv(GOLD_DIR / "main_key.csv", dtype=str)
    items = pd.read_csv(GOLD_DIR / "main_items.csv", dtype=str, keep_default_na=False)
    v1 = detector_flags(key)
    e = _pool()
    lo1 = set(zip(key.chain, key.address))
    e = e[[k in lo1 for k in zip(e.chain, e.address)]]
    fast = v2.fast_counts(e)
    need = items[~items.code_at_event.isin(["code", "destroyed"])]
    res = {"coverage": {"need_history": int(len(need)),
                        "have_history": int(sum((c, a) in fast for c, a in zip(need.chain, need.address)))}}
    dd, ca7 = delegate_decided(items), ca7_unlabelled(gold)
    runs = {"main_addr": {}, "main_row": dict(unit="row"), "b_no_key_addr": dict(exclude_strata=("+KEY", "+ADDR")),
            "j_no_delegate": dict(exclude_items=dd), "k_ca7_flip": dict(flip_to_negative=ca7),
            "k_ca7_drop": dict(exclude_items=ca7)}
    res["v1"] = _short(evaluate(_frame(gold, key, v1), boot=boot))
    for cut in ("at", "now"):
        r = v2.flags_rows(e, fast, cut)
        r["f_ncd"] = r.f_frozen | r.ncd_call
        r["f_swp"] = r.f_frozen | r.sweeper_full
        fl = addr_flags(key, r, "f_v2")
        out = {name: _short(evaluate(_frame(gold, key, fl), boot=boot, **kw)) for name, kw in runs.items()}
        out["ablation_v1_plus_ncd"] = _short(evaluate(_frame(gold, key, addr_flags(key, r, "f_ncd")), boot=boot))
        out["ablation_v1_plus_sweeper"] = _short(evaluate(_frame(gold, key, addr_flags(key, r, "f_swp")), boot=boot))
        d = _frame(gold, key, fl).merge(v1[["item_id", "flag"]].rename(columns={"flag": "v1"}), on="item_id")
        new = d[d.flag & ~d.v1]
        out["new_flags"] = {"n": int(len(new)), "gold_pos": int((new.gold == "1").sum()), "gold_neg": int((new.gold == "0").sum()),
                            "by_rule": new.hard.str.split(",").explode().value_counts().to_dict(),
                            "neg_by_stratum": new[new.gold == "0"].stratum.value_counts().to_dict()}
        res[f"v2_{cut}"] = out
    res["note"] = ("TRONG MẪU (lô 1 dùng để thiết kế v2). v1 = detector đóng băng 994bb2b. Ngưỡng v2 từ CODEBOOK §3.4, không chỉnh "
                   f"theo nhãn vàng. CI bootstrap phân tầng {boot} lần.")
    DEV_OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return res


def _print(res: dict) -> None:
    print("độ phủ lịch sử:", res["coverage"])
    rows = [("v1 (đóng băng)", res["v1"])]
    for cut in ("at", "now"):
        rows += [(f"v2-{cut} {k}", v) for k, v in res[f"v2_{cut}"].items() if isinstance(v, dict) and "precision" in v]
    print(f"{'bản':38} {'n':>4} {'P':>6} {'R':>6} {'F1':>6} {'FPR':>7}  CI95 recall")
    for k, v in rows:
        print(f"{k:38} {v['n_labelled']:>4} {v['precision']:>6.3f} {v['recall']:>6.3f} {v['f1']:>6.3f} {v['fpr']:>7.4f}  "
              f"{v['recall_ci'][0]:.3f}–{v['recall_ci'][1]:.3f}")
    for cut in ("at", "now"):
        print(f"cờ mới v2-{cut}:", res[f"v2_{cut}"]["new_flags"])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dev")
    d.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    _print(dev(a.boot))
