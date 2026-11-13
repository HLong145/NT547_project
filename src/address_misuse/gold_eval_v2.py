"""Đánh giá engine v2 (GOLD_PROTOCOL §10) trên nhãn vàng.

- `dev`: lô 1 (758 mẫu). v2 được thiết kế SAU khi xem FN của v1 trên lô 1, nên đây là kết quả **trong mẫu / khám phá**, không
  thay kết quả chính (v1 đóng băng). Báo kèm các bản bỏ từng luật (ablation) và độ phủ lịch sử.
- `heldout`: lô 2 (A gán một mình, §10.3), báo đúng §10.4: (a) nhất quán của A trên 24 mẫu kiểm, (b) held-out trên 100 âm
  dự phòng (trọng số (cell_n − k) / n₂), (c) gộp lô 1 ∪ lô 2 (trọng số cell_n / (k + n₂)). Mã viết sau khi giao lô 2 cho A,
  TRƯỚC khi có nhãn; không chỉnh sau khi xem kết quả.

    python -X utf8 -m address_misuse.gold_eval_v2 dev [--boot 1000]
    python -X utf8 -m address_misuse.gold_eval_v2 heldout [--boot 1000]
"""
from __future__ import annotations

import argparse
import json
import math

import pandas as pd

from address_misuse.config import GOLD_DIR, INTERIM_DIR
from address_misuse.engine import v2
from address_misuse.gold_eval import ca7_unlabelled, delegate_decided, evaluate
from address_misuse.gold_final import OUT as GOLD_FINAL, _frame, _pool, _short, detector_flags

DEV_OUT = INTERIM_DIR / "gold_eval_v2_dev.json"
HELDOUT_OUT = INTERIM_DIR / "gold_eval_v2_heldout.json"
B2_LABELS = GOLD_DIR / "annotator_batch2_A.xlsx"
B2_GOLD = GOLD_DIR / "batch2_gold.csv"            # nhãn cuối lô 2 theo mã gốc (gitignore như gold_final.csv)
LABEL_KEEP = ["is_misuse", "type", "subtype", "xc_chain", "malicious", "confidence", "note"]
FRAME_COLS = ["item_id", "stratum", "cell", "cell_n", "cell_rows", "n_rows", "label", "double", "gold", "type", "note",
              "gold_source", "chain", "address"]


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


# ------------------------------------------------------------------ lô 2 (held-out, §10.4)

def _binom_cdf(j: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(j + 1)) if j >= 0 else 0.0


def cp_interval(k: int, n: int, alpha: float = 0.05) -> list[float]:
    """CI Clopper–Pearson hai phía (nhị thức chính xác, chia đôi; không cần scipy)."""
    def solve(f):                                        # f(p) giảm theo p: tìm p với f(p) = alpha / 2
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) > alpha / 2 else (lo, mid)
        return (lo + hi) / 2
    lower = 0.0 if k == 0 else solve(lambda p: _binom_cdf(k - 1, n, p) - (1 - alpha))  # P(X ≥ k) = alpha/2
    upper = 1.0 if k >= n else solve(lambda p: _binom_cdf(k, n, p))                    # P(X ≤ k) = alpha/2
    return [round(lower, 4), round(upper, 4)]


def batch2_labels() -> pd.DataFrame:
    """Nhãn A của lô 2, kiểm hình thức (CODEBOOK §2), nối khoá: thêm `orig_id` (R#### / G###), `source`, `batch`."""
    from address_misuse.sample_gold import check_labels, read_labels
    lab = read_labels(B2_LABELS)
    errs = check_labels(lab)
    if errs:
        raise SystemExit(f"{len(errs)} lỗi hình thức trong {B2_LABELS.name}:\n  " + "\n  ".join(errs[:30]))
    key = pd.read_csv(GOLD_DIR / "batch2_key.csv", dtype=str)
    d = key.merge(lab, on="item_id", how="left", validate="1:1", suffixes=("", "_lab"))
    if (d.is_misuse.fillna("") == "").any():
        raise SystemExit(f"thiếu nhãn ở {int((d.is_misuse.fillna('') == '').sum())} mẫu")
    if "address_lab" in d and (d.address_lab.str.lower() != d.address.str.lower()).any():
        raise SystemExit("địa chỉ trong file gán lệch batch2_key.csv")
    for c in LABEL_KEEP:
        if c not in d:
            d[c] = ""
    return d


def consistency(lab: pd.DataFrame) -> dict:
    """(a) A gán lại 24 mẫu cũ: tỉ lệ khác nhãn lượt đầu của chính A (file dùng để rút mẫu) và khác nhãn cuối lô 1."""
    from address_misuse.gold_batch2 import A_DOUBLE
    from address_misuse.sample_gold import read_labels
    old = pd.concat([read_labels(p) for p in A_DOUBLE]).drop_duplicates("item_id").set_index("item_id")
    gold = pd.read_csv(GOLD_FINAL, dtype=str, keep_default_na=False).set_index("item_id")
    c = lab[lab.source == "consistency"].set_index("orig_id")
    n, out = len(c), {"n": len(c)}
    for name, ref in (("vs_A_first", old), ("vs_gold_final", gold)):
        r = ref.reindex(c.index)
        dm = c.is_misuse != r.is_misuse
        dt = dm | (c.type.str.upper() != r.type.str.upper())
        out[name] = {"is_misuse_diff": int(dm.sum()), "is_misuse_rate": round(float(dm.mean()), 4),
                     "is_misuse_ci": cp_interval(int(dm.sum()), n), "type_diff": int(dt.sum()),
                     "type_rate": round(float(dt.mean()), 4), "type_ci": cp_interval(int(dt.sum()), n),
                     "diff_items": sorted(c.index[dt].tolist())}
    return out


def batch2_frames(lab: pd.DataFrame, key1: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Khung cho 100 âm dự phòng (mã gốc R####). Trả (held-out, gộp):
    - held-out: `cell_n` − k (phần chưa gán sau lô 1), `cell_rows` − số dòng lô 1 của ô; `gold_weights` chia cho n₂.
    - gộp: giữ `cell_n` gốc; nối với khung lô 1 thì `gold_weights` chia cho k + n₂."""
    rk = pd.read_csv(GOLD_DIR / "main_reserve_key.csv", dtype=str)
    r = lab[lab.source == "reserve"][["orig_id", *LABEL_KEEP]].rename(columns={"orig_id": "item_id", "is_misuse": "gold"})
    d = rk.merge(r, on="item_id", how="inner", validate="1:1")
    if len(d) != len(r):
        raise SystemExit("mẫu dự phòng lô 2 không có trong main_reserve_key.csv")
    for c in ("cell_n", "cell_rows", "n_rows", "k"):
        d[c] = pd.to_numeric(d[c])
    k1 = key1.assign(n_rows=pd.to_numeric(key1.n_rows)).groupby("cell").agg(k1=("item_id", "size"), r1=("n_rows", "sum"))
    d = d.join(k1, on="cell")
    if (d.k1 != d.k).any():
        raise SystemExit("cột k của main_reserve_key.csv lệch số mẫu lô 1 trong ô")
    d["gold_source"] = "batch2_A"
    return d.assign(cell_n=d.cell_n - d.k1, cell_rows=d.cell_rows - d.r1), d


def _raw(fr: pd.DataFrame) -> dict:
    g = fr.gold.astype(str)
    pos, neg = fr[g == "1"], fr[g == "0"]
    return {"n": int(len(fr)), "pos": int(len(pos)), "neg": int(len(neg)), "unknown": int((g == "?").sum()),
            "tp": int(pos.flag.sum()), "fn": int((~pos.flag).sum()), "fp": int(neg.flag.sum()), "tn": int((~neg.flag).sum()),
            "fpr_ci_cp": cp_interval(int(neg.flag.sum()), len(neg)) if len(neg) else None,
            "pos_items": sorted(pos.item_id.tolist()), "fp_items": sorted(neg.item_id[neg.flag].tolist())}


def heldout(boot: int = 1000) -> dict:
    lab = batch2_labels()
    key1 = pd.read_csv(GOLD_DIR / "main_key.csv", dtype=str)
    gold1 = pd.read_csv(GOLD_FINAL, dtype=str, keep_default_na=False)
    items1 = pd.read_csv(GOLD_DIR / "main_items.csv", dtype=str, keep_default_na=False)
    items2 = pd.read_csv(GOLD_DIR / "batch2_items.csv", dtype=str, keep_default_na=False).merge(
        lab[["item_id", "orig_id", "source"]], on="item_id", validate="1:1")
    items2 = items2[items2.source == "reserve"].assign(item_id=lambda x: x.orig_id)
    held, comb2 = batch2_frames(lab, key1)
    lab[["item_id", "orig_id", "source", "chain", "address", *LABEL_KEEP]].to_csv(B2_GOLD, index=False, encoding="utf-8")

    rs = lab[lab.source == "reserve"]
    res = {"a_consistency": consistency(lab),
           "labels_reserve": {"is_misuse": rs.is_misuse.value_counts().to_dict(),
                              "type": rs.type.str.upper().value_counts().to_dict(),
                              "confidence": rs.confidence.str.lower().value_counts().to_dict()}}
    keys = pd.concat([key1[["item_id", "chain", "address", "flag"]], comb2[["item_id", "chain", "address", "flag"]]],
                     ignore_index=True)
    e = _pool()
    want = set(zip(keys.chain, keys.address))
    e = e[[k in want for k in zip(e.chain, e.address)]]
    fast = v2.fast_counts(e)
    need2 = items2[~items2.code_at_event.isin(["code", "destroyed"])]
    res["coverage_batch2"] = {"need_history": int(len(need2)),
                              "have_history": int(sum((c, a) in fast for c, a in zip(need2.chain, need2.address)))}
    flags = {"v1": detector_flags(keys)}
    for cut in ("at", "now"):
        flags[f"v2_{cut}"] = addr_flags(keys, v2.flags_rows(e, fast, cut), "f_v2")

    dd = delegate_decided(pd.concat([items1, items2], ignore_index=True))
    ca7 = ca7_unlabelled(gold1) + ca7_unlabelled(comb2)
    runs = {"main_addr": {}, "main_row": dict(unit="row"), "b_no_key_addr": dict(exclude_strata=("+KEY", "+ADDR")),
            "j_no_delegate": dict(exclude_items=dd), "k_ca7_flip": dict(flip_to_negative=ca7),
            "k_ca7_drop": dict(exclude_items=ca7), "unknown_one": dict(unknown="one"), "unknown_drop": dict(unknown="drop")}
    for name, fl in flags.items():
        f = fl[["item_id", "flag", "R", "hard"]]
        h = held[FRAME_COLS].merge(f, on="item_id", validate="1:1")
        r = {"raw": _raw(h)}
        for unk in ("zero", "one", "drop"):
            r[f"weighted_{unk}"] = _short(evaluate(h, boot=boot, unknown=unk))
        r["weighted_row"] = _short(evaluate(h, boot=boot, unit="row"))
        res[f"b_heldout_{name}"] = r
        c = pd.concat([_frame(gold1, key1, fl)[FRAME_COLS + ["flag", "R", "hard"]],
                       comb2[FRAME_COLS].merge(f, on="item_id", validate="1:1")], ignore_index=True)
        for col in ("cell_n", "cell_rows", "n_rows"):
            c[col] = pd.to_numeric(c[col])
        res[f"c_combined_{name}"] = {k: _short(evaluate(c, boot=boot, **kw)) for k, kw in runs.items()}
    res["note"] = ("GOLD_PROTOCOL §10.4. (b) miền = phần chưa gán (sau lô 1) của 10 ô âm không cờ thiết kế; trọng số "
                   "(cell_n − k) / n₂; v1/v2 chưa từng thấy các mẫu này. (c) lô 1 ∪ lô 2, trọng số cell_n / (k + n₂); v2 gộp có "
                   "phần lô 1 trong mẫu. 24 mẫu kiểm không vào ước lượng. "
                   f"CI bootstrap phân tầng {boot} lần; CP = Clopper–Pearson hai phía.")
    HELDOUT_OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return res


def _print_heldout(res: dict) -> None:
    print("(a) nhất quán A:", json.dumps(res["a_consistency"], ensure_ascii=False))
    print("nhãn dự phòng:", res["labels_reserve"], "| độ phủ lịch sử lô 2:", res["coverage_batch2"])
    for name in ("v1", "v2_at", "v2_now"):
        b = res[f"b_heldout_{name}"]
        w = b["weighted_zero"]
        print(f"(b) {name:7} thô: bắt {b['raw']['tp']}/{b['raw']['pos']} dương, FP {b['raw']['fp']}/{b['raw']['neg']} "
              f"{b['raw']['fpr_ci_cp']} | trọng số: R {w['recall']} FPR {w['fpr']} {w['fpr_ci']}")
    print(f"{'(c) gộp':30} {'n':>4} {'P':>6} {'R':>6} {'F1':>6} {'FPR':>7}  CI95 recall   dương ẩn (điểm/cận)")
    for name in ("v1", "v2_at", "v2_now"):
        for k, v in res[f"c_combined_{name}"].items():
            print(f"{name + ' ' + k:30} {v['n_labelled']:>4} {v['precision']:>6.3f} {v['recall']:>6.3f} {v['f1']:>6.3f} "
                  f"{v['fpr']:>7.4f}  {v['recall_ci'][0]:.3f}–{v['recall_ci'][1]:.3f}  "
                  f"{v.get('hidden_positive_point', 0):.1f}/{v.get('hidden_positive_upper', 0):.1f}")


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
    h = sub.add_parser("heldout")
    h.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    if a.cmd == "dev":
        _print(dev(a.boot))
    else:
        _print_heldout(heldout(a.boot))
