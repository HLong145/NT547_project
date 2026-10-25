"""D5 — đo engine bằng nhãn vàng từ mẫu phân tầng (CODEBOOK §7.6): ước lượng có trọng số, CI bootstrap phân tầng, cận cho ô 0 sự kiện.

Bảng đầu vào (mỗi dòng một địa chỉ đã gán), cột bắt buộc:
    cell      ô lấy mẫu (tầng|chain|F/u, xem `sample_gold._units`)
    stratum   tầng ("+…" dương theo tác giả, "-…" âm)
    flag      engine cảnh báo (luật cứng hoặc R ≥ τ_warn)
    gold      nhãn vàng cuối (0/1)
    n_rows    số dòng dataset_v2 mà địa chỉ đại diện (đơn vị của các chỉ số engine)
    cell_n    số địa chỉ trong ô (khung), cell_rows  số dòng trong ô
Trọng số tính LẠI từ số mẫu đã gán trong từng ô (`gold_weights`), vì lô 2 có thể dừng ở bất kỳ ranh giới lô nào.

Vì sao không dùng `engine.metrics.with_ci`: nó chấm trên toàn tập (không có lấy mẫu con) nên không cần trọng số. Với nhãn vàng:
- Ước lượng Horvitz–Thompson theo dòng: w_row = (cell_n / số đã gán trong ô) × n_rows.
- Bootstrap phải lấy lại mẫu TRONG từng ô (giữ nguyên số mẫu mỗi ô), không lấy lại cả bảng.
- Ô có 0 dương ẩn trong n mẫu: bootstrap cho CI bằng 0, sai. Dùng cận Clopper–Pearson (`cp_upper`) rồi cộng các ô.
"""

import math

import numpy as np
import pandas as pd


def gold_weights(df: pd.DataFrame) -> pd.DataFrame:
    """Gắn `w_addr`, `w_row` theo số địa chỉ ĐÃ GÁN trong từng ô (cell_n / n_đã_gán)."""
    n_lab = df.groupby("cell").cell.transform("size")
    out = df.copy()
    out["w_addr"] = out.cell_n / n_lab
    out["w_row"] = out.w_addr * out.n_rows
    return out


def confusion_w(gold, flag, w) -> dict:
    """Tổng có trọng số (số dòng ước lượng) và P/R/F1/FPR."""
    gold, flag, w = np.asarray(gold, bool), np.asarray(flag, bool), np.asarray(w, float)
    tp, fp = w[flag & gold].sum(), w[flag & ~gold].sum()
    fn, tn = w[~flag & gold].sum(), w[~flag & ~gold].sum()
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * p * r / (p + r) if tp else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else float("nan")}


def stratified_boot(df: pd.DataFrame, boot: int = 1000, seed: int = 0) -> dict:
    """CI 95% (percentile) của P/R/F1/FPR: lấy lại mẫu có hoàn lại trong từng ô, giữ nguyên số mẫu mỗi ô (nên trọng số không đổi)."""
    df = gold_weights(df)
    rng = np.random.default_rng(seed)
    idx = [np.flatnonzero(df.cell.to_numpy() == c) for c in df.cell.unique()]
    gold, flag, w = df.gold.to_numpy(bool), df.flag.to_numpy(bool), df.w_row.to_numpy(float)
    est = confusion_w(gold, flag, w)
    draws = {k: [] for k in ("precision", "recall", "f1", "fpr")}
    for _ in range(boot):
        i = np.concatenate([rng.choice(ix, len(ix)) for ix in idx])
        c = confusion_w(gold[i], flag[i], w[i])
        for k in draws:
            draws[k].append(c[k])
    for k, v in draws.items():
        v = np.array(v, float)
        v = v[~np.isnan(v)]
        est[k + "_ci"] = [float(np.quantile(v, .025)), float(np.quantile(v, .975))] if len(v) else None
    return est


def cp_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """Cận trên Clopper–Pearson một phía (độ tin cậy 1 − alpha) của tỉ lệ khi thấy k sự kiện trong n mẫu. k = 0: 1 − alpha^(1/n)."""
    if n <= 0:
        return 1.0
    if k >= n:
        return 1.0
    if k == 0:
        return 1 - alpha ** (1 / n)
    lo, hi = k / n, 1.0
    for _ in range(80):                                      # P(X ≤ k | n, p) giảm theo p; tìm p để bằng alpha
        mid = (lo + hi) / 2
        cdf = sum(math.comb(n, j) * mid ** j * (1 - mid) ** (n - j) for j in range(k + 1))
        lo, hi = (mid, hi) if cdf > alpha else (lo, mid)
    return hi


def hidden_positive_bound(df: pd.DataFrame, alpha: float = 0.05) -> dict:
    """Dương ẩn = nhãn vàng 1 ở tầng âm theo tác giả mà engine KHÔNG cảnh báo (làm recall thật thấp hơn recall đo được).
    Trả về điểm ước lượng và cận trên (bảo thủ: cộng cận Clopper–Pearson từng ô, mỗi ô độ tin cậy 1 − alpha) của số dòng
    dương ẩn, và cận dưới của recall = TP / (TP + FN đã biết + cận trên dương ẩn). Ô gán hết thì đóng góp số thật, không bất định."""
    d = gold_weights(df)
    neg = d[(d.stratum.str[0] == "-") & ~d.flag.astype(bool)]
    upper = point = 0.0
    for _, g in neg.groupby("cell"):
        n, found_rows = len(g), float((g.gold.astype(float) * g.n_rows).sum())
        if n >= g.cell_n.iloc[0]:
            upper += found_rows
            point += found_rows
        else:
            upper += g.cell_rows.iloc[0] * cp_upper(int(g.gold.sum()), n, alpha)
            point += float((g.gold.astype(float) * g.w_row).sum())
    g1, fl = d.gold.astype(bool), d.flag.astype(bool)
    tp = float(d.w_row[g1 & fl].sum())
    fn_known = float(d.w_row[g1 & ~fl & (d.stratum.str[0] == "+")].sum())
    return {"hidden_positive_rows_point": point, "hidden_positive_rows_upper": upper,
            "recall_lower_bound": tp / (tp + fn_known + upper) if tp else 0.0}


def evaluate(df: pd.DataFrame, boot: int = 1000, seed: int = 0, unknown: str = "zero") -> dict:
    """Báo cáo gộp. `df.gold` có thể là 0/1/'?': `unknown` = 'zero' (tính '?' là 0) hoặc 'one' (tính là 1), báo cả hai kịch bản."""
    d = df.copy()
    d["gold"] = d.gold.map({0: 0, 1: 1, "0": 0, "1": 1, "?": 0 if unknown == "zero" else 1}).astype(int)
    d = gold_weights(d)
    out = stratified_boot(d, boot, seed)
    out.update(hidden_positive_bound(d))
    return out
