"""D5 bước cuối: nhãn vàng cuối của 758 mẫu lô 1 và đánh giá engine ĐÃ ĐÓNG BĂNG theo quy tắc báo đăng ký trước (GOLD_PROTOCOL §2.5,
§2.6, §4).

python -X utf8 -m address_misuse.gold_final build      → data/gold/gold_final.csv (không commit: chứa nhãn, xem .gitignore)
python -X utf8 -m address_misuse.gold_final evaluate   → data/interim/gold_eval.json + bảng tóm tắt

Nguồn nhãn (`gold_source`):
- `gate_agreed` / `gate_adjudicated`: 50 mẫu cổng κ, nhãn lượt gán lại `_r2` khi A và B đồng ý is_misuse + type, còn lại theo
  ARBITRATION_gate50.md (lượt 2, lượt 3).
- `official_agreed` / `official_adjudicated`: 200 mẫu κ chính thức, đồng ý hoặc theo ARBITRATION_official.md.
- `single` / `single_corrected`: 508 mẫu gán đơn của B; 3 chỗ sửa đã duyệt ở ARBITRATION_relabel.md (§2.6).
Mẫu đồng ý is_misuse + type nhưng khác subtype: subtype `?` (chỉ xảy ra giữa KEY và 7702, cùng T5). Khác `malicious`: `?`.
`confidence` lấy mức thấp hơn. `note` của mẫu đồng ý = ghép note của A và B (độ nhạy ca 7 đọc từ đây, nên tập ca 7 là bản rộng).

Detector đóng băng: `engine_eval.parquet` + `engine_metrics.json` commit 994bb2b (2026-10-24), trước tag `prereg-gold-v0.6`:
cảnh báo = luật cứng hoặc risk(w học) ≥ τ_warn = 63,01 (`detector_flags`). Cờ `main_key.flag` (chia ô F/u lúc lấy mẫu) tính nhầm
bằng cột R của parquet; nó chỉ là biến thiết kế (trọng số HT vẫn đúng), được kiểm lại cho khớp và báo kèm để đối chiếu.
"""

import argparse
import json
import time

import numpy as np
import pandas as pd
import requests

from address_misuse.config import GOLD_DIR, INTERIM_DIR, rpc_url
from address_misuse.engine.metrics import risk
from address_misuse.gold_eval import ca7_unlabelled, delegate_decided, delegate_named, evaluate
from address_misuse.sample_gold import cohen_kappa, read_labels

OUT = GOLD_DIR / "gold_final.csv"
EVAL_OUT = INTERIM_DIR / "gold_eval.json"
T3_CACHE = INTERIM_DIR / "gold_t3_recipient.json"
COLS = ["is_misuse", "type", "subtype", "xc_chain", "malicious", "confidence", "note"]
CONF_ORDER = {"low": 0, "medium": 1, "high": 2}

# Nhãn phân xử: base = người được xét đúng (A/B); các trường ghi ở đây ghi đè lên base.
GATE_ADJ = {   # ARBITRATION_gate50.md, lượt 2 (2026-11-01) + lượt 3 (2026-11-03); A xác nhận 2026-11-03
    "G033": ("A", dict(is_misuse="1", type="T5", subtype="KEY")),
    "G085": ("B", dict(is_misuse="1", type="T5", subtype="7702")),
    "G108": ("B", dict(is_misuse="1", type="T5", subtype="7702")),
    "G194": ("A", dict(is_misuse="1", type="T5", subtype="KEY", confidence="low", note="+ ca 7d (bridge)")),
    "G075": ("B", dict(is_misuse="1", type="T5", subtype="7702", malicious="?", confidence="medium")),
    "G183": ("B", dict(is_misuse="1", type="T5", subtype="7702", malicious="1", confidence="medium")),
}
_G1 = dict(is_misuse="1", type="T5", subtype="7702", xc_chain="-", malicious="?", confidence="medium")
_NONE = dict(is_misuse="0", type="NONE", subtype="-", xc_chain="-", malicious="-", confidence="medium")
OFFICIAL_ADJ = {   # ARBITRATION_official.md (B duyệt, A xác nhận 2026-11-05)
    **{i: ("B", _G1) for i in ("G233", "G281", "G427", "G443", "G474", "G583", "G674", "G524")},
    "G321": ("A", _G1),
    "G502": ("A", {**_G1, "malicious": "1"}),
    "G318": ("B", dict(is_misuse="1", type="T4", subtype="NCD", xc_chain="base", malicious="0", confidence="high")),
    "G489": ("B", dict(is_misuse="1", type="T4", subtype="NCD", xc_chain="base", malicious="0", confidence="high")),
    "G466": ("A", dict(is_misuse="1", type="T1", subtype="NCD", xc_chain="-", malicious="0", confidence="medium")),
    "G617": ("A", dict(is_misuse="1", type="T4", subtype="NCD", xc_chain="eth", malicious="0", confidence="medium")),
    "G370": ("B", _NONE),
    **{i: ("A", _NONE) for i in ("G357", "G526", "G520")},
    "G347": ("B", _NONE),
    "G328": ("A", {**_NONE, "confidence": "low", "note": "1 lần rút nhanh"}),
    "G541": ("B", dict(is_misuse="1", type="T5", subtype="KEY", malicious="1", confidence="low", note="+ ca 7c, ca 7d")),
    "G440": ("B", dict(is_misuse="1", type="T5", subtype="KEY", malicious="1", confidence="low", note="+ ca 7b (nghiêng)")),
    "G624": ("A", dict(is_misuse="1", type="T5", subtype="KEY", malicious="1", confidence="low", note="+ ca 7c (nghiêng)")),
    "G742": ("A", dict(is_misuse="1", type="T5", subtype="KEY", malicious="1", confidence="low", note="+ ca 7d (nghiêng)")),
}
SINGLE_FIX = {     # ARBITRATION_relabel.md (B duyệt, A xác nhận 2026-11-08); sai lệch GOLD_PROTOCOL §8
    "G484": dict(type="T4", xc_chain="base"),
    "G745": dict(is_misuse="0", type="NONE", subtype="-", xc_chain="-", malicious="-", confidence="low",
                 note="1 lần rút nhanh (lần kia là swap qua MetaMask Swap Router, nhận lại LORDS)"),
    "G452": dict(confidence="low", note="+ ca 7b/7c (không kiểm được nhãn ví nhận)"),
}


def _norm(d: pd.DataFrame) -> pd.DataFrame:
    d = d.copy()
    for c in ("is_misuse", "type", "subtype"):
        d[c] = d[c].astype(str).str.strip().str.upper().replace({"": "-", "NAN": "-"})
    for c in ("xc_chain", "malicious", "confidence", "note"):
        d[c] = d[c].fillna("").astype(str).str.strip()
    d["xc_chain"] = d.xc_chain.str.lower().replace({"": "-"})
    d["malicious"] = d.malicious.replace({"": "-"})
    d["confidence"] = d.confidence.str.lower()
    return d.set_index("item_id")


def _apply(row: pd.Series, fix: dict) -> pd.Series:
    row = row.copy()
    for k, v in fix.items():
        if k == "note" and v.startswith("+ "):
            row["note"] = (row["note"] + " | " if row["note"] else "") + v[2:]
        else:
            row[k] = v
    return row


def _double(a_path: str, b_path: str, adj: dict, tag: str) -> pd.DataFrame:
    A, B = _norm(read_labels(GOLD_DIR / a_path)), _norm(read_labels(GOLD_DIR / b_path))
    out = []
    for i in A.index:
        a, b = A.loc[i], B.loc[i]
        if i in adj:
            who, fix = adj[i]
            r = _apply((a if who == "A" else b)[COLS], fix)
            src = f"{tag}_adjudicated"
        elif a.is_misuse != b.is_misuse or a.type != b.type:
            raise SystemExit(f"{i}: A và B bất đồng nhưng không có trong bảng phân xử {tag}")
        else:
            r = a[COLS].copy()
            for c in ("subtype", "xc_chain", "malicious"):
                if a[c] != b[c]:
                    r[c] = "?"
            r["confidence"] = min(a.confidence, b.confidence, key=lambda x: CONF_ORDER.get(x, -1))
            r["note"] = f"A: {a.note} | B: {b.note}"
            src = f"{tag}_agreed"
        r["gold_source"], r["item_id"] = src, i
        out.append(r)
    return pd.DataFrame(out)


def build() -> pd.DataFrame:
    gate = _double("annotator_main_double_r2_A.xlsx", "annotator_main_double_r2_B.xlsx", GATE_ADJ, "gate")
    off = _double("annotator_main_official_A.xlsx", "annotator_main_official_B.xlsx", OFFICIAL_ADJ, "official")
    S = _norm(read_labels(GOLD_DIR / "annotator_main_single_B.xlsx"))
    single = []
    for i in S.index:
        r = S.loc[i, COLS].copy()
        r["gold_source"] = "single"
        if i in SINGLE_FIX:
            r = _apply(r, SINGLE_FIX[i])
            r["gold_source"] = "single_corrected"
        r["item_id"] = i
        single.append(r)
    g = pd.concat([gate, off, pd.DataFrame(single)], ignore_index=True)
    it = pd.read_csv(GOLD_DIR / "main_items.csv", dtype=str)[["item_id", "chain", "address"]]
    g = it.merge(g, on="item_id", how="left", validate="1:1")
    if g.is_misuse.isna().any() or len(g) != len(it):
        raise SystemExit(f"thiếu nhãn ở {int(g.is_misuse.isna().sum())} mẫu")
    bad = ~g.is_misuse.isin(["0", "1", "?"]) | ((g.is_misuse == "1") == (g.type == "NONE"))
    if bad.any():
        raise SystemExit(f"nhãn không nhất quán: {g.item_id[bad].tolist()[:10]}")
    g = g[["item_id", "chain", "address", "gold_source", *COLS]]
    g.to_csv(OUT, index=False, encoding="utf-8")
    print(f"ghi {OUT}: {len(g)} mẫu; is_misuse " + ", ".join(f"{k} {v}" for k, v in g.is_misuse.value_counts().items()))
    print("  nguồn: " + ", ".join(f"{k} {v}" for k, v in g.gold_source.value_counts().items()))
    print("  type: " + ", ".join(f"{k} {v}" for k, v in g.type.value_counts().items()))
    print(f"  subtype '?' (A, B khác KEY/7702): {int((g.subtype == '?').sum())}")
    return g


# ------------------------------------------------------------------ luật cơ học tham chiếu (§4 f)

def t3_recipients(items: pd.DataFrame) -> dict[str, str]:
    """Người nhận trong calldata transfer/transferFrom của các tx ứng viên T3 (cache, RPC công khai, chỉ đọc tx)."""
    cache = json.loads(T3_CACHE.read_text(encoding="utf-8")) if T3_CACHE.exists() else {}
    c = items[items.code_at_event.isin(["code", "destroyed"]) & items.selector.str.lower().isin(["0xa9059cbb", "0x23b872dd"])
              & (items.tx_status == "success")]
    for i, chain, h, sel in zip(c.item_id, c.chain, c.tx_hash, c.selector.str.lower()):
        if i in cache:
            continue
        tx = requests.post(rpc_url(chain), json={"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionByHash",
                                                 "params": [h]}, timeout=30).json().get("result") or {}
        data = tx.get("input", "")
        word = 1 if sel == "0x23b872dd" else 0                 # transferFrom(from, to, v): người nhận là tham số 2
        cache[i] = "0x" + data[10 + 64 * word + 24: 10 + 64 * (word + 1)].lower() if len(data) >= 10 + 64 * (word + 1) else ""
        time.sleep(0.1)
    T3_CACHE.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    return cache


def mechanical(items: pd.DataFrame, lookup: pd.DataFrame, t3: dict[str, str]) -> pd.DataFrame:
    """Luật cơ học tham chiếu v0.6.2 (GOLD_PROTOCOL §4, chỉ dùng cột trong file; bước cần explorer → NONE)."""
    cls = {(c.lower(), d.lower()): f for c, d, f in zip(lookup.chain, lookup.delegate, lookup.final_class)}
    out = []
    for r in items.itertuples():
        m, t = 0, "NONE"
        if r.code_at_event == "none" and r.calldata_kind == "call":
            m, t = 1, ("T4" if r.xc_timing in ("before", "unknown") else "T1")
        elif r.code_at_event in ("code", "destroyed") and t3.get(r.item_id, "") == r.address.lower():
            m, t = 1, "T3"
        elif r.code_at_event == "7702" and cls.get((r.chain.lower(), str(r.delegate_7702).lower())) == "forwarder_sweeper":
            m, t = 1, "T5"
        out.append({"item_id": r.item_id, "mech": str(m), "mech_type": t})
    return pd.DataFrame(out)


# ------------------------------------------------------------------ đánh giá

def _frame(gold: pd.DataFrame, key: pd.DataFrame, flags: pd.DataFrame, design: bool = False) -> pd.DataFrame:
    d = key[["item_id", "stratum", "cell", "cell_n", "cell_rows", "n_rows", "label", "double"]].merge(
        gold[["item_id", "is_misuse", "type", "note", "gold_source", "chain", "address"]], on="item_id", validate="1:1")
    f = flags.assign(flag=flags.flag_design if design else flags.flag)
    return d.merge(f, on="item_id", validate="1:1").rename(columns={"is_misuse": "gold"})


def _pool() -> pd.DataFrame:
    """Khung lấy mẫu như `sample_gold._units`: dòng test hoặc ngoài thời gian, bỏ `excluded`."""
    e = pd.read_parquet(INTERIM_DIR / "engine_eval.parquet")
    e = e[((e.split == "test") | e.out_of_time) & (e.split != "excluded")].copy()
    m = json.loads((INTERIM_DIR / "engine_metrics.json").read_text(encoding="utf-8"))["main"]
    e["R_frozen"] = risk(e, m["weights"])                 # detector đóng băng: trọng số học (engine.metrics), không phải cột R
    e["f_design"] = e.hard.notna() | (e.R >= m["thresholds"]["warn"])
    e["f_frozen"] = e.hard.notna() | (e.R_frozen >= m["thresholds"]["warn"])
    return e


def detector_flags(key: pd.DataFrame) -> pd.DataFrame:
    """Cờ theo địa chỉ (có dòng nào trong khung bị cảnh báo).
    `flag_design` = cờ đã dùng để chia ô F/u khi lấy mẫu (`sample_gold.engine_flag`: cột R của parquet, tính với trọng số mặc
    định, so với τ_warn của trọng số học — lệch, xem GOLD_PROTOCOL §8 2026-11-08); kiểm lại phải khớp `main_key.flag`.
    `flag` = cờ của detector đóng băng thật (luật cứng hoặc risk(w học) ≥ τ_warn), khớp `engine_metrics.json`."""
    e = _pool()
    g = e.groupby(["chain", "address"]).agg(fd=("f_design", "any"), ff=("f_frozen", "any"), R=("R_frozen", "max"),
                                             hard=("hard", lambda x: ",".join(sorted(set(x.dropna())))))
    k = key.join(g, on=["chain", "address"])
    if k.fd.isna().any():
        raise SystemExit(f"{int(k.fd.isna().sum())} địa chỉ của main_key không có trong engine_eval.parquet")
    mism = int((k.fd.astype(bool) != (k.flag.astype(str) == "True")).sum())
    if mism:
        raise SystemExit(f"cờ thiết kế lệch main_key ở {mism} địa chỉ: engine_eval.parquet không còn là bản đóng băng")
    return k[["item_id"]].assign(flag=k.ff.astype(bool), flag_design=k.fd.astype(bool), R=k.R, hard=k.hard)


def _short(m: dict) -> dict:
    keep = ("precision", "recall", "f1", "fpr", "precision_ci", "recall_ci", "f1_ci", "fpr_ci", "tp", "fp", "fn", "tn",
            "hidden_positive_point", "hidden_positive_upper", "recall_lower_bound", "recall_lower_bound_cp", "n_labelled", "unit")
    return {k: (round(v, 4) if isinstance(v, float) else ([round(x, 4) for x in v] if isinstance(v, list) else v))
            for k, v in m.items() if k in keep}


def _anon(a: str) -> str:
    return a[:6] + "…" + a[-4:]


def run_eval(boot: int = 1000) -> dict:
    gold = pd.read_csv(OUT, dtype=str, keep_default_na=False)
    key = pd.read_csv(GOLD_DIR / "main_key.csv", dtype=str)            # chỉ người điều phối mở, sau khi nhãn đã chốt
    items = pd.read_csv(GOLD_DIR / "main_items.csv", dtype=str, keep_default_na=False)
    lookup = pd.read_csv(GOLD_DIR / "delegate_lookup.csv", dtype=str, keep_default_na=False)
    flags = detector_flags(key)
    d = _frame(gold, key, flags)
    dd = delegate_decided(items)
    named = delegate_named(gold, items, lookup)
    ca7 = ca7_unlabelled(gold)
    keyaddr = ("+KEY", "+ADDR")
    runs = {
        "main_addr": dict(),
        "main_row": dict(unit="row"),
        "unknown_one": dict(unknown="one"),
        "unknown_drop": dict(unknown="drop"),
        "b_no_key_addr": dict(exclude_strata=keyaddr),
        "j_no_delegate": dict(exclude_items=dd),
        "j2_no_delegate_any": dict(exclude_items=sorted(set(dd) | set(named))),
        "b_j_combined": dict(exclude_strata=keyaddr, exclude_items=dd),
        "k_ca7_flip": dict(flip_to_negative=ca7),
        "k_ca7_drop": dict(exclude_items=ca7),
    }
    res = {name: _short(evaluate(d, boot=boot, **kw)) for name, kw in runs.items()}
    res["design_flag_addr"] = _short(evaluate(_frame(gold, key, flags, design=True), boot=boot))   # cờ chia ô (lệch), chỉ để đối chiếu
    res["flags"] = {"frozen": int(flags.flag.sum()), "design": int(flags.flag_design.sum()),
                    "frozen_not_design": int((flags.flag & ~flags.flag_design).sum()),
                    "design_not_frozen": int((~flags.flag & flags.flag_design).sum())}
    res["sets"] = {"delegate_decided": len(dd), "delegate_named": len(named), "ca7": len(ca7),
                   "gold_q": int((d.gold == "?").sum())}

    # (f) tập khó: luật cơ học ≠ nhãn cuối
    mech = mechanical(items, lookup, t3_recipients(items))
    m = d.merge(mech, on="item_id")
    hard = m[m.mech != m.gold]
    res["f_mechanical"] = {"n_pos": int((m.mech == "1").sum()), "kappa_vs_gold": round(cohen_kappa(m.mech.tolist(), m.gold.tolist()), 4),
                           "agree": round(float((m.mech == m.gold).mean()), 4), "n_hard": len(hard),
                           "hard_by_stratum": hard.stratum.value_counts().to_dict(),
                           "types": mech.mech_type.value_counts().to_dict()}
    A, B = (_norm(read_labels(GOLD_DIR / f"annotator_main_official_{w}.xlsx")) for w in "AB")
    hid = [i for i in hard.item_id if i in A.index]
    if hid:
        res["f_mechanical"]["kappa_AB_hard_official"] = round(cohen_kappa(A.loc[hid, "is_misuse"].tolist(),
                                                                         B.loc[hid, "is_misuse"].tolist()), 4)
        res["f_mechanical"]["n_hard_official"] = len(hid)

    # (h) silver: nhãn luật của tác giả (dấu tầng) so với nhãn vàng, không trọng số
    s = d.assign(silver=np.where(d.stratum.str[0] == "+", "1", "0"))
    res["h_silver"] = {"agree": round(float((s.silver == s.gold).mean()), 4),
                       "kappa": round(cohen_kappa(s.silver.tolist(), s.gold.tolist()), 4),
                       "gold_pos_rate_by_stratum": {k: round(float((g.gold == "1").mean()), 3)
                                                    for k, g in s.groupby("stratum")}}

    # (g) case study: 5 TP R cao nhất; 5 FP, 5 FN rút ngẫu nhiên seed 0; địa chỉ ẩn bớt
    c = d.assign(flag_b=d.flag.astype(bool))
    tp = (c[c.flag_b & (c.gold == "1")].sample(frac=1, random_state=0)             # R hoà nhau: thứ tự ngẫu nhiên seed 0
          .sort_values("R", ascending=False, kind="stable").head(5))
    fp = c[c.flag_b & (c.gold == "0")]
    fn = c[~c.flag_b & (c.gold == "1")]
    fp, fn = (x.sample(min(5, len(x)), random_state=0) for x in (fp, fn))
    res["g_case_study"] = {name: [{"item_id": r.item_id, "chain": r.chain, "address": _anon(r.address), "stratum": r.stratum,
                                   "type": r.type, "R": round(float(r.R), 2), "hard": r.hard} for r in x.itertuples()]
                           for name, x in (("TP", tp), ("FP", fp), ("FN", fn))}
    res["note"] = ("detector đóng băng: engine_eval.parquet + engine_metrics.json 994bb2b (risk với trọng số học, τ_warn 63,01); trọng số HT theo ô; CI bootstrap phân tầng "
                   f"{boot} lần; ca 7 đọc note nhãn cuối (mẫu đồng ý ghép note A và B)")
    EVAL_OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return res


def _print(res: dict) -> None:
    print(f"{'kịch bản':22} {'n':>4} {'P':>6} {'R':>6} {'F1':>6} {'FPR':>7}  CI95 recall      CI95 precision")
    for k, v in res.items():
        if not isinstance(v, dict) or "precision" not in v:
            continue
        print(f"{k:22} {v['n_labelled']:>4} {v['precision']:>6.3f} {v['recall']:>6.3f} {v['f1']:>6.3f} {v['fpr']:>7.4f}  "
              f"{v['recall_ci'][0]:.3f}–{v['recall_ci'][1]:.3f}     {v['precision_ci'][0]:.3f}–{v['precision_ci'][1]:.3f}")
    m = res["main_addr"]
    print(f"dương ẩn (addr): điểm {m['hidden_positive_point']:.1f}, cận trên {m['hidden_positive_upper']:.1f}; "
          f"cận dưới recall {m['recall_lower_bound']:.3f} (CP {m['recall_lower_bound_cp']:.3f})")
    print("tập:", res["sets"])
    print("(f) luật cơ học:", res["f_mechanical"])
    print("(h) silver:", {k: v for k, v in res["h_silver"].items() if k != "gold_pos_rate_by_stratum"})
    print("    tỉ lệ dương vàng theo tầng:", res["h_silver"]["gold_pos_rate_by_stratum"])
    for k, v in res["g_case_study"].items():
        print(f"(g) {k}: " + "; ".join(f"{x['item_id']} {x['chain']} {x['stratum']} {x['type']} R={x['R']} {x['hard']}" for x in v))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    ev = sub.add_parser("evaluate")
    ev.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    if a.cmd == "build":
        build()
    else:
        _print(run_eval(a.boot))


if __name__ == "__main__":
    main()
