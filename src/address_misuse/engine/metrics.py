"""Module 3 — học trọng số, chọn ngưỡng, P/R/F1/FPR có CI, ROC/PR, baseline và ablation (PLAN_V2 §4, RISK_SCORE §3).

python -m address_misuse.engine.metrics [--boot 1000] [--seed 0]
    đọc  data/interim/engine_eval.parquet (`engine.evaluate`)
    ghi  data/interim/engine_metrics.json, engine_roc.csv (điểm ROC/PR để vẽ trong paper)

Nhãn hiện là **nhãn theo luật của tác giả** (dương) + tập âm N1–N8, chưa phải nhãn vàng D5: số liệu là tạm, chạy
lại khi có nhãn vàng. Quy trình không đổi:
1. Học `w` trên train: logistic regression hệ số không âm trên 4 thành phần S, `w = β / Σβ` → R ∈ [0, 100].
2. Ngưỡng trên val: `τ_warn` = nhỏ nhất sao cho FPR trên N8 ≤ 1%; `τ_block` = nhỏ nhất sao cho precision ≥ 0,95.
3. Trên test và ngoài thời gian: cảnh báo = luật cứng HOẶC R ≥ τ. Báo cáo riêng phần do luật cứng và phần do R.
   P/R/F1/FPR tổng, theo chain, recall theo loại dương, FPR theo nhóm âm; CI 95% bootstrap theo mẫu.
4. Baseline: heuristic `getCode == 0x ∧ có calldata` (T1 của S_bytecode, không có bộ lọc văn bản nếu có `has_call`).
   Rule gốc của Shao et al. không so được vì chính nó sinh nhãn dương.
5. Ablation: bỏ từng S (học lại `w`, chọn lại ngưỡng).
"""

import argparse
import json

import numpy as np
import pandas as pd

from address_misuse.config import INTERIM_DIR

EVAL = INTERIM_DIR / "engine_eval.parquet"
OUT = INTERIM_DIR / "engine_metrics.json"
ROC = INTERIM_DIR / "engine_roc.csv"
COMPS = ["bytecode", "cross", "osint", "history"]
FPR_N8 = 0.01
PREC_BLOCK = 0.95


def fit_nonneg_logistic(X: np.ndarray, y: np.ndarray, l2: float = 1e-3, iters: int = 5000, lr: float = 0.5):
    """Logistic regression, hệ số (trừ hệ số chặn) ≥ 0, gradient chiếu. Trả về (β₀, β)."""
    n, k = X.shape
    b0, b = 0.0, np.zeros(k)
    pos_w = (n - y.sum()) / max(y.sum(), 1)                 # cân bằng lớp: dương ít hơn âm
    sw = np.where(y == 1, pos_w, 1.0)
    sw = sw / sw.mean()
    for _ in range(iters):
        p = 1 / (1 + np.exp(-(b0 + X @ b)))
        g = sw * (p - y)
        b0 -= lr * g.mean()
        b = np.maximum(0.0, b - lr * (X.T @ g / n + l2 * b))
    return b0, b


def learn_weights(train: pd.DataFrame, comps=COMPS) -> dict[str, float]:
    _, b = fit_nonneg_logistic(train[comps].to_numpy(float), train.label.to_numpy(int))
    if b.sum() == 0:
        return {c: 1 / len(comps) for c in comps}
    return {c: float(v / b.sum()) for c, v in zip(comps, b)}


def risk(df: pd.DataFrame, w: dict[str, float]) -> pd.Series:
    return 100 * sum(w[c] * df[c] for c in w)


def pick_thresholds(val: pd.DataFrame, r: pd.Series) -> dict[str, float]:
    """τ_warn theo FPR trên N8, τ_block theo precision; xét trên mẫu không dính luật cứng (luật cứng luôn cảnh báo)."""
    soft = val.hard.isna()
    cands = np.unique(np.r_[r[soft].to_numpy(), 100.0001])
    n8 = r[soft & (val.grp == "-N8")]
    warn = next((t for t in cands if len(n8) and (n8 >= t).mean() <= FPR_N8), 100.0001)
    block = 100.0001
    y = val.label[soft]
    for t in cands:
        pred = r[soft] >= t
        if pred.sum() and (y[pred] == 1).mean() >= PREC_BLOCK:
            block = t
            break
    return {"warn": float(warn), "block": float(max(block, warn))}


def confusion(y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    p = tp / (tp + fp) if tp + fp else float("nan")
    rc = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * p * rc / (p + rc) if tp else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": rc, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else float("nan")}


def with_ci(y: np.ndarray, pred: np.ndarray, boot: int, rng) -> dict:
    out = confusion(y, pred)
    if boot and len(y):
        stats = {k: [] for k in ("precision", "recall", "f1", "fpr")}
        for _ in range(boot):
            i = rng.integers(0, len(y), len(y))
            c = confusion(y[i], pred[i])
            for k in stats:
                stats[k].append(c[k])
        for k, v in stats.items():
            v = np.array(v, float)
            v = v[~np.isnan(v)]
            out[k + "_ci"] = [float(np.quantile(v, .025)), float(np.quantile(v, .975))] if len(v) else None
    return out


def auc(y: np.ndarray, s: np.ndarray) -> float:
    pos, neg = s[y == 1], s[y == 0]
    if not len(pos) or not len(neg):
        return float("nan")
    r = pd.Series(np.r_[pos, neg]).rank().to_numpy()
    return float((r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def curve(name: str, y: np.ndarray, s: np.ndarray) -> pd.DataFrame:
    """Điểm ROC + PR theo mọi ngưỡng (R giảm dần)."""
    o = np.argsort(-s, kind="stable")
    y, s = y[o], s[o]
    tp, fp = np.cumsum(y == 1), np.cumsum(y == 0)
    last = np.r_[s[1:] != s[:-1], True]                     # chỉ giữ điểm cuối của mỗi nhóm điểm bằng nhau
    P, N = max((y == 1).sum(), 1), max((y == 0).sum(), 1)
    return pd.DataFrame({"set": name, "threshold": s[last], "tpr": tp[last] / P, "fpr": fp[last] / N,
                         "precision": tp[last] / (tp[last] + fp[last])})


def evaluate_set(d: pd.DataFrame, r: pd.Series, tau: dict, boot: int, rng) -> dict:
    y = d.label.to_numpy(int)
    hard = d.hard.notna().to_numpy()
    out = {"n_pos": int(y.sum()), "n_neg": int((y == 0).sum()), "auc_R": auc(y, r.to_numpy()),
           "auc_R_soft": auc(y[~hard], r.to_numpy()[~hard])}
    for level in ("warn", "block"):
        pred = hard | (r.to_numpy() >= tau[level])
        res = {"all": with_ci(y, pred, boot, rng),
               "hard_only": confusion(y, hard),
               "R_only_on_soft": confusion(y[~hard], (r.to_numpy() >= tau[level])[~hard])}
        res["by_chain"] = {ch: confusion(y[m], pred[m]) for ch in sorted(d.chain.unique())
                           for m in [(d.chain == ch).to_numpy()]}
        res["recall_by_group"] = {g: float(pred[m].mean()) for g in sorted(d[d.label == 1].grp.unique())
                                  for m in [(d.grp == g).to_numpy()]}
        res["fpr_by_group"] = {g: float(pred[m].mean()) for g in sorted(d[d.label == 0].grp.unique())
                               for m in [(d.grp == g).to_numpy()]}
        out[level] = res
    return out


def baseline(d: pd.DataFrame) -> np.ndarray:
    """getCode == 0x ∧ có calldata (không lọc văn bản nếu có cột has_call)."""
    if "has_call" in d:
        return ((d.state == "none") & d.has_call.fillna(False)).to_numpy()
    return ((d.state == "none") & d.types.str.contains("T1")).to_numpy()


def run(df: pd.DataFrame, comps=COMPS, boot: int = 1000, seed: int = 0, curves: list | None = None) -> dict:
    rng = np.random.default_rng(seed)
    tr, va = df[df.split == "train"], df[df.split == "val"]
    w = learn_weights(tr, comps)
    tau = pick_thresholds(va, risk(va, w))
    out = {"weights": w, "thresholds": tau, "sets": {}}
    sets = {"test": df[df.split == "test"], "out_of_time": df[df.out_of_time & (df.split != "excluded")]}
    for name, d in sets.items():
        r = risk(d, w)
        out["sets"][name] = evaluate_set(d, r, tau, boot, rng)
        out["sets"][name]["baseline_getcode_calldata"] = confusion(d.label.to_numpy(int), baseline(d))
        if curves is not None:
            for ch in sorted(d.chain.unique()):
                m = d.chain == ch
                curves.append(curve(f"{name}/{ch}", d.label[m].to_numpy(int), r[m].to_numpy()))
    return out


def _fmt(c: dict) -> str:
    ci = lambda k: f" [{c[k + '_ci'][0]:.2f}–{c[k + '_ci'][1]:.2f}]" if c.get(k + "_ci") else ""
    return (f"P {c['precision']:.3f}{ci('precision')}  R {c['recall']:.3f}{ci('recall')}  "
            f"F1 {c['f1']:.3f}{ci('f1')}  FPR {c['fpr']:.3f}{ci('fpr')}  (TP {c['tp']}, FP {c['fp']}, FN {c['fn']})")


def report(res: dict, abl: dict) -> str:
    L = ["Nhãn: luật tác giả + tập âm N1–N8 (TẠM, chưa phải nhãn vàng D5).",
         "Trọng số học trên train: " + ", ".join(f"{k} {v:.3f}" for k, v in res["weights"].items()),
         f"Ngưỡng chọn trên val: τ_warn {res['thresholds']['warn']:.2f} (FPR N8 ≤ 1%), "
         f"τ_block {res['thresholds']['block']:.2f} (precision ≥ 0,95)"]
    for name, s in res["sets"].items():
        L += ["", f"== {name}: dương {s['n_pos']}, âm {s['n_neg']}, AUC(R) {s['auc_R']:.3f}, "
                  f"AUC(R, bỏ mẫu luật cứng) {s['auc_R_soft']:.3f}"]
        for level in ("warn", "block"):
            e = s[level]
            L.append(f"  {level:5s} tổng:          {_fmt(e['all'])}")
            L.append(f"        chỉ luật cứng:  {_fmt(e['hard_only'])}")
            L.append(f"        chỉ R (mẫu không dính luật cứng): {_fmt(e['R_only_on_soft'])}")
            for ch, c in e["by_chain"].items():
                L.append(f"        {ch}: {_fmt(c)}")
            L.append("        recall theo loại: " + ", ".join(f"{g} {v:.2f}" for g, v in e["recall_by_group"].items()))
            L.append("        FPR theo nhóm âm: " + ", ".join(f"{g} {v:.3f}" for g, v in e["fpr_by_group"].items()))
        L.append(f"  baseline getCode==0x ∧ calldata: {_fmt(s['baseline_getcode_calldata'])}")
    L += ["", "Ablation (học lại w, chọn lại ngưỡng; F1 / FPR mức warn trên test):"]
    for k, r in abl.items():
        e = r["sets"]["test"]["warn"]["all"]
        L.append(f"  {k:14s} F1 {e['f1']:.3f}  R {e['recall']:.3f}  FPR {e['fpr']:.3f}  AUC {r['sets']['test']['auc_R']:.3f}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    df = pd.read_parquet(EVAL)
    curves = []
    res = run(df, boot=a.boot, seed=a.seed, curves=curves)
    abl = {"đủ 4": res}
    for c in COMPS:
        abl[f"bỏ {c}"] = run(df, [x for x in COMPS if x != c], boot=0, seed=a.seed)
    abl["chỉ cross"] = run(df, ["cross"], boot=0, seed=a.seed)
    OUT.write_text(json.dumps({"main": res, "ablation": {k: {"weights": v["weights"], "thresholds": v["thresholds"],
                                                             "test_warn": v["sets"]["test"]["warn"]["all"]}
                                                         for k, v in abl.items()}},
                              ensure_ascii=False, indent=1, default=float), encoding="utf-8")
    pd.concat(curves, ignore_index=True).to_csv(ROC, index=False)
    print(report(res, abl))
    print(f"\nghi {OUT}, {ROC}")


if __name__ == "__main__":
    main()
