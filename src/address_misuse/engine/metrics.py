"""Module 3 — học trọng số, chọn ngưỡng, P/R/F1/FPR có CI, ROC/PR, baseline và ablation (PLAN_V2 §4, RISK_SCORE §3).

python -m address_misuse.engine.metrics [--boot 1000] [--seed 0]
    đọc  data/interim/engine_eval.parquet (`engine.evaluate`)
    ghi  data/interim/engine_metrics.json, engine_roc.csv (điểm ROC/PR để vẽ trong paper)

Nhãn hiện là **nhãn theo luật của tác giả** (dương) + tập âm N1–N8, chưa phải nhãn vàng D5: số liệu là tạm, chạy
lại khi có nhãn vàng. Quy trình không đổi:
1. Học `w` trên train: logistic regression hệ số không âm trên 4 thành phần S, `w = β / Σβ` → R ∈ [0, 100].
2. Ngưỡng trên val: `τ_warn` = nhỏ nhất sao cho FPR ≤ 1% trên lưu lượng bình thường (N2 + N3 + N8, ~190 mẫu thay vì
   chỉ 75 mẫu N8); `τ_block` = nhỏ nhất sao cho precision ≥ 0,95 và FPR ≤ 0,1% trên mọi âm val. Độ biến thiên của τ
   báo bằng bootstrap val theo địa chỉ (`threshold_boot`).
3. Trên test và ngoài thời gian: cảnh báo = luật cứng HOẶC R ≥ τ. Báo cáo riêng phần do luật cứng và phần do R.
   P/R/F1/FPR tổng, theo chain, recall theo loại dương (tách phần do luật cứng và phần do R), FPR theo nhóm âm;
   CI 95% bootstrap theo địa chỉ (cluster: mọi dòng cùng địa chỉ được chọn cùng nhau).
4. Baseline: heuristic `getCode == 0x ∧ có calldata` (T1 của S_bytecode, không có bộ lọc văn bản nếu có `has_call`);
   GoPlus Address Security (`engine.goplus`, trạng thái lúc tra chứ không phải tại `at`), chỉ trên mẫu đã tra được.
   Rule gốc của Shao et al. không so được vì chính nó sinh nhãn dương.
5. Ablation: bỏ từng S (học lại `w`, chọn lại ngưỡng).
"""

import argparse
import json

import numpy as np
import pandas as pd

from address_misuse.config import INTERIM_DIR
from address_misuse.engine.goplus import flags_frame

EVAL = INTERIM_DIR / "engine_eval.parquet"
OUT = INTERIM_DIR / "engine_metrics.json"
ROC = INTERIM_DIR / "engine_roc.csv"
COMPS = ["bytecode", "cross", "osint", "history"]
FPR_NORMAL = 0.01
FPR_BLOCK = 0.001
PREC_BLOCK = 0.95
NORMAL_GRPS = ("-N2", "-N3", "-N8")                      # lưu lượng bình thường của ví: gọi contract, tin nhắn, tx ngẫu nhiên


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
    """Chỉ học trên mẫu không dính luật cứng (như `pick_thresholds`): mẫu KEY luôn có S_osint = 1 và luôn bị cảnh báo
    bằng luật cứng, giữ lại thì w_osint bị thổi phồng mà không giúp gì cho phần R."""
    if "hard" in train:
        train = train[train.hard.isna()]
    _, b = fit_nonneg_logistic(train[comps].to_numpy(float), train.label.to_numpy(int))
    if b.sum() == 0:
        return {c: 1 / len(comps) for c in comps}
    return {c: float(v / b.sum()) for c, v in zip(comps, b)}


def risk(df: pd.DataFrame, w: dict[str, float]) -> pd.Series:
    return 100 * sum(w[c] * df[c] for c in w)


def pick_thresholds(val: pd.DataFrame, r: pd.Series) -> dict[str, float]:
    """τ_warn theo FPR trên lưu lượng bình thường, τ_block theo precision và FPR trên mọi âm; xét trên mẫu không dính
    luật cứng (luật cứng luôn cảnh báo)."""
    soft = val.hard.isna()
    cands = np.unique(np.r_[r[soft].to_numpy(), 100.0001])
    normal = r[soft & val.grp.isin(NORMAL_GRPS)]
    warn = next((t for t in cands if len(normal) and (normal >= t).mean() <= FPR_NORMAL), 100.0001)
    neg = r[soft & (val.label == 0)]
    block = 100.0001
    y = val.label[soft]
    for t in cands:
        pred = r[soft] >= t
        if pred.sum() and (y[pred] == 1).mean() >= PREC_BLOCK and (not len(neg) or (neg >= t).mean() <= FPR_BLOCK):
            block = t
            break
    return {"warn": float(warn), "block": float(max(block, warn))}


def cluster_index(d: pd.DataFrame) -> list[np.ndarray]:
    """Chỉ số dòng theo từng địa chỉ (chain, address): đơn vị lấy mẫu lại của bootstrap."""
    codes = pd.factorize(d.chain.astype(str) + ":" + d.address.astype(str))[0]
    order = np.argsort(codes, kind="stable")
    return np.split(order, np.flatnonzero(np.diff(codes[order])) + 1)


def resample(clusters: list[np.ndarray], rng) -> np.ndarray:
    pick = rng.integers(0, len(clusters), len(clusters))
    return np.concatenate([clusters[i] for i in pick])


def threshold_boot(val: pd.DataFrame, r: pd.Series, n: int, rng) -> dict:
    """Độ biến thiên của τ khi lấy mẫu lại val theo địa chỉ: τ dựa trên ít mẫu âm thì dao động mạnh."""
    if not n:
        return {}
    cl = cluster_index(val)
    taus = [pick_thresholds(val.iloc[i], r.iloc[i]) for i in (resample(cl, rng) for _ in range(n))]
    return {k: {"p05": float(np.quantile([t[k] for t in taus], .05)), "p50": float(np.quantile([t[k] for t in taus], .5)),
                "p95": float(np.quantile([t[k] for t in taus], .95))} for k in ("warn", "block")}


def confusion(y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    p = tp / (tp + fp) if tp + fp else float("nan")
    rc = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * p * rc / (p + rc) if tp else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": rc, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else float("nan")}


def with_ci(y: np.ndarray, pred: np.ndarray, boot: int, rng, clusters: list[np.ndarray] | None = None) -> dict:
    out = confusion(y, pred)
    if boot and len(y):
        clusters = clusters or [np.array([i]) for i in range(len(y))]
        stats = {k: [] for k in ("precision", "recall", "f1", "fpr")}
        for _ in range(boot):
            i = resample(clusters, rng)
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
        res = {"all": with_ci(y, pred, boot, rng, cluster_index(d)),
               "hard_only": confusion(y, hard),
               "R_only_on_soft": confusion(y[~hard], (r.to_numpy() >= tau[level])[~hard])}
        res["by_chain"] = {ch: confusion(y[m], pred[m]) for ch in sorted(d.chain.unique())
                           for m in [(d.chain == ch).to_numpy()]}
        res["recall_by_group"] = {g: float(pred[m].mean()) for g in sorted(d[d.label == 1].grp.unique())
                                  for m in [(d.grp == g).to_numpy()]}
        # recall theo loại tách theo nguồn: KEY / ADDR bị luật cứng chi phối (≈ định nghĩa nhãn), nên cần "chỉ R"
        res["recall_by_group_hard"] = {g: float(hard[m].mean()) for g in sorted(d[d.label == 1].grp.unique())
                                       for m in [(d.grp == g).to_numpy()]}
        res["recall_by_group_R_only_on_soft"] = {
            g: float((r.to_numpy() >= tau[level])[m & ~hard].mean()) if (m & ~hard).any() else None
            for g in sorted(d[d.label == 1].grp.unique()) for m in [(d.grp == g).to_numpy()]}
        res["n_soft_by_group"] = {g: int((m & ~hard).sum()) for g in sorted(d[d.label == 1].grp.unique())
                                  for m in [(d.grp == g).to_numpy()]}
        res["fp_by_hard_rule"] = d[(d.label == 0) & hard].hard.value_counts().to_dict()
        if "delegate_src" in d:    # nguồn delegate: "recorded" (snapshot tác giả, chỉ có ở dương) vs "current" (getCode hôm nay)
            m7 = (d.state == "7702").to_numpy()
            res["by_delegate_src"] = {f"{int(l)}/{src}": {"n": int(k.sum()), "flagged": float(pred[k].mean())}
                                      for l in (1, 0) for src in ("recorded", "current")
                                      for k in [m7 & (y == l) & (d.delegate_src == src).to_numpy()] if k.any()}
        res["fpr_by_group"] = {g: float(pred[m].mean()) for g in sorted(d[d.label == 0].grp.unique())
                               for m in [(d.grp == g).to_numpy()]}
        out[level] = res
    return out


def baseline(d: pd.DataFrame) -> np.ndarray:
    """getCode == 0x ∧ có calldata (không lọc văn bản nếu có cột has_call)."""
    if "has_call" in d:
        return ((d.state == "none") & d.has_call.fillna(False)).to_numpy()
    return ((d.state == "none") & d.types.str.contains("T1")).to_numpy()


def goplus_baseline(d: pd.DataFrame, r: pd.Series, tau: dict) -> dict:
    """GoPlus (cờ độc hại bất kỳ) so với engine mức warn trên cùng các mẫu GoPlus tra được."""
    m = d.goplus_flag.notna()
    d, r = d[m], r[m]
    y, pred = d.label.to_numpy(int), d.goplus_flag.astype(bool).to_numpy()
    eng = d.hard.notna().to_numpy() | (r.to_numpy() >= tau["warn"])
    return {"coverage": float(m.mean()), "goplus": confusion(y, pred), "engine_same_samples": confusion(y, eng),
            "goplus_or_engine": confusion(y, pred | eng),
            "recall_by_group": {g: float(pred[(d.grp == g).to_numpy()].mean()) for g in sorted(d[d.label == 1].grp.unique())},
            "fpr_by_group": {g: float(pred[(d.grp == g).to_numpy()].mean()) for g in sorted(d[d.label == 0].grp.unique())}}


def run(df: pd.DataFrame, comps=COMPS, boot: int = 1000, seed: int = 0, curves: list | None = None) -> dict:
    rng = np.random.default_rng(seed)
    tr, va = df[df.split == "train"], df[df.split == "val"]
    w = learn_weights(tr, comps)
    tau = pick_thresholds(va, risk(va, w))
    out = {"weights": w, "thresholds": tau, "threshold_boot": threshold_boot(va, risk(va, w), boot // 5, rng),
           "n_val_normal": int((va.hard.isna() & va.grp.isin(NORMAL_GRPS)).sum()), "sets": {}}
    # Mọi mẫu dương đều lấy từ danh sách OSINT của tác giả (S_osint > 0), âm thì không: S_osint tách được dương/âm
    # chỉ vì cách lấy mẫu. `test_osint` chỉ giữ mẫu có trong danh sách OSINT để đo phần còn lại của engine công bằng.
    sets = {"test": df[df.split == "test"], "out_of_time": df[df.out_of_time & (df.split != "excluded")],
            "test_osint": df[(df.split == "test") & (df.osint > 0)],
            # `test` gồm cả mẫu ≥ 2025-09 (cũng nằm trong out_of_time, gồm toàn bộ dương D6): test_in_time không trùng
            "test_in_time": df[(df.split == "test") & ~df.out_of_time]}
    ex = df[(df.split == "excluded") & (df.label == 0)]
    kept = df[(df.split == "test") & (df.label == 0)]
    fpr = lambda d, level: float((d.hard.notna() | (risk(d, w) >= tau[level])).mean()) if len(d) else float("nan")
    out["excluded_neg"] = {"n": len(ex), "fpr_warn": fpr(ex, "warn"), "fpr_block": fpr(ex, "block"),
                           "kept_fpr_warn": fpr(kept, "warn"), "kept_fpr_block": fpr(kept, "block")}
    for name, d in sets.items():
        r = risk(d, w)
        out["sets"][name] = evaluate_set(d, r, tau, boot, rng)
        out["sets"][name]["baseline_getcode_calldata"] = confusion(d.label.to_numpy(int), baseline(d))
        if "goplus_flag" in d:
            out["sets"][name]["baseline_goplus"] = goplus_baseline(d, risk(d, w), tau)
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
         f"Ngưỡng chọn trên val: τ_warn {res['thresholds']['warn']:.2f} (FPR ≤ 1% trên {res['n_val_normal']} mẫu "
         f"N2+N3+N8), τ_block {res['thresholds']['block']:.2f} (precision ≥ 0,95 và FPR ≤ 0,1% trên mọi âm val)"]
    for k, v in res.get("threshold_boot", {}).items():
        L.append(f"  τ_{k} bootstrap val theo địa chỉ: p5 {v['p05']:.1f} · p50 {v['p50']:.1f} · p95 {v['p95']:.1f}")
    x = res.get("excluded_neg")
    if x:
        L.append(f"Âm bị `excluded` (contract phổ biến, {x['n']} mẫu): FPR warn {x['fpr_warn']:.3f}, block {x['fpr_block']:.3f}"
                 f" (âm giữ lại ở test: warn {x['kept_fpr_warn']:.3f}, block {x['kept_fpr_block']:.3f})")
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
            L.append("          trong đó do luật cứng: " + ", ".join(f"{g} {v:.2f}" for g, v in e["recall_by_group_hard"].items()))
            L.append("          chỉ R trên mẫu mềm:    " + ", ".join(
                f"{g} {'–' if v is None else format(v, '.2f')} (n={e['n_soft_by_group'][g]})"
                for g, v in e["recall_by_group_R_only_on_soft"].items()))
            if e.get("by_delegate_src"):
                L.append("        EOA 7702 theo nhãn/nguồn delegate: " + ", ".join(
                    f"{k} n={v['n']} cảnh báo {v['flagged']:.2f}" for k, v in e["by_delegate_src"].items()))
            if e["fp_by_hard_rule"]:
                L.append(f"        báo nhầm do luật cứng: {e['fp_by_hard_rule']}")
            L.append("        FPR theo nhóm âm: " + ", ".join(f"{g} {v:.3f}" for g, v in e["fpr_by_group"].items()))
        L.append(f"  baseline getCode==0x ∧ calldata: {_fmt(s['baseline_getcode_calldata'])}")
        if "baseline_goplus" in s:
            g = s["baseline_goplus"]
            L.append(f"  baseline GoPlus (tra được {g['coverage']:.0%} mẫu): {_fmt(g['goplus'])}")
            L.append(f"        engine trên cùng mẫu:   {_fmt(g['engine_same_samples'])}")
            L.append(f"        GoPlus HOẶC engine:     {_fmt(g['goplus_or_engine'])}")
            L.append("        GoPlus recall theo loại: " + ", ".join(f"{k} {v:.2f}" for k, v in g["recall_by_group"].items()))
            L.append("        GoPlus FPR theo nhóm âm: " + ", ".join(f"{k} {v:.3f}" for k, v in g["fpr_by_group"].items()))
    L += ["", "Ablation (học lại w, chọn lại ngưỡng; F1 / FPR mức warn trên test):"]
    for k, r in abl.items():
        e = r["sets"]["test"]["warn"]["all"]
        o = r["sets"]["test_osint"]
        L.append(f"  {k:14s} F1 {e['f1']:.3f}  R {e['recall']:.3f}  FPR {e['fpr']:.3f}  AUC {r['sets']['test']['auc_R']:.3f}"
                 f"  | test_osint F1 {o['warn']['all']['f1']:.3f}  AUC {o['auc_R']:.3f}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    df = pd.read_parquet(EVAL)
    gp = flags_frame()
    if len(gp):
        df = df.merge(gp[["chain", "address", "goplus_flag"]], on=["chain", "address"], how="left")
    curves = []
    res = run(df, boot=a.boot, seed=a.seed, curves=curves)
    abl = {"đủ 4": res}
    for c in COMPS:
        abl[f"bỏ {c}"] = run(df, [x for x in COMPS if x != c], boot=0, seed=a.seed)
    abl["chỉ cross"] = run(df, ["cross"], boot=0, seed=a.seed)
    OUT.write_text(json.dumps({"main": res, "ablation": {k: {"weights": v["weights"], "thresholds": v["thresholds"],
                                                             "test_warn": v["sets"]["test"]["warn"]["all"],
                                                             "test_osint_warn": v["sets"]["test_osint"]["warn"]["all"]}
                                                         for k, v in abl.items()}},
                              ensure_ascii=False, indent=1, default=float), encoding="utf-8")
    pd.concat(curves, ignore_index=True).to_csv(ROC, index=False)
    print(report(res, abl))
    print(f"\nghi {OUT}, {ROC}")


if __name__ == "__main__":
    main()
