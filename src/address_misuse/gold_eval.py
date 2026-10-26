"""D5 — đo engine bằng nhãn vàng từ mẫu phân tầng (GOLD_PROTOCOL §1, §4): ước lượng có trọng số, CI bootstrap phân tầng, cận cho ô 0 sự kiện.

Bảng đầu vào (mỗi dòng một địa chỉ đã gán), cột bắt buộc:
    cell      ô lấy mẫu (tầng|chain|F/u, xem `sample_gold._units`)
    stratum   tầng ("+…" dương theo tác giả, "-…" âm)
    flag      engine cảnh báo (luật cứng hoặc R ≥ τ_warn); chấp nhận bool / 0,1 / "True","False"
    gold      nhãn vàng cuối (0/1, hoặc '?' xem `unknown`)
    n_rows    số dòng dataset_v2 mà địa chỉ đại diện (đơn vị của các chỉ số engine theo dòng)
    cell_n    số địa chỉ trong ô (khung), cell_rows  số dòng trong ô
Trọng số tính LẠI từ số mẫu đã gán trong từng ô (`gold_weights`), vì lô 2 có thể dừng ở bất kỳ ranh giới lô nào.

Đơn vị đo (`unit`): CHÍNH là `addr` (mỗi địa chỉ đếm 1; nhãn gán cho địa chỉ, và một địa chỉ có nhiều dòng thì các dòng không độc lập —
cỡ mẫu hiệu dụng theo dòng chỉ cỡ vài chục). `row` (đơn vị của `engine.metrics`) báo kèm để so với các con số đã có.

Vì sao không dùng `engine.metrics.with_ci`: nó chấm trên toàn tập (không có lấy mẫu con) nên không cần trọng số. Với nhãn vàng:
- Ước lượng Horvitz–Thompson: w_addr = cell_n / số đã gán trong ô; w_row = w_addr × n_rows.
- Bootstrap lấy lại mẫu TRONG từng ô được lấy mẫu (giữ nguyên số mẫu mỗi ô). Ô đã gán hết (điều tra toàn bộ) KHÔNG lấy lại mẫu.
- Ô có 0 dương ẩn trong n mẫu: bootstrap cho CI bằng 0, sai. Dùng cận Jeffreys (mô phỏng Beta) hoặc Clopper–Pearson (`cp_upper`, bảo thủ).
"""

import math
import re

import numpy as np
import pandas as pd

_BOOL = {True: True, False: False, 1: True, 0: False, "1": True, "0": False, "true": True, "false": False}
_LAB = {0: 0, 1: 1, "0": 0, "1": 1}


def _to_bool(s: pd.Series, name: str) -> pd.Series:
    """Chuỗi "True"/"False" từ CSV KHÔNG được coi là True mặc định (astype(bool) sẽ biến "False" thành True)."""
    def f(x):
        k = x.strip().lower() if isinstance(x, str) else x
        if k not in _BOOL:
            raise ValueError(f"cột {name}: giá trị không hợp lệ {x!r}")
        return _BOOL[k]
    return s.map(f).astype(bool)


def prepare(df: pd.DataFrame, unknown: str = "zero") -> pd.DataFrame:
    """Chuẩn hóa kiểu, kiểm tra cột và nhãn. `gold` '?' tính là 0 (`unknown='zero'`) hoặc 1 (`'one'`); `'drop'` bỏ mẫu đó."""
    need = {"cell", "stratum", "flag", "gold", "n_rows", "cell_n", "cell_rows"}
    if need - set(df.columns):
        raise ValueError(f"thiếu cột: {sorted(need - set(df.columns))}")
    d = df.copy()
    d["flag"] = _to_bool(d.flag, "flag")
    g = d.gold.map(lambda x: x.strip() if isinstance(x, str) else x)
    q = g == "?"
    if unknown == "drop":
        d, g = d[~q].copy(), g[~q]
    else:
        g = g.where(~q, 0 if unknown == "zero" else 1)
    bad = ~g.isin(list(_LAB))
    if bad.any():
        raise ValueError(f"cột gold: giá trị không hợp lệ {sorted(set(g[bad].astype(str)))}")
    d["gold"] = g.map(_LAB).astype(int)
    for c in ("n_rows", "cell_n", "cell_rows"):
        d[c] = pd.to_numeric(d[c])
    return d


def final_gold(df: pd.DataFrame) -> pd.Series:
    """Nhãn vàng cuối: mẫu gán đôi → nhãn đã thống nhất (`gold_adj`; thiếu thì lỗi, không tự chọn); mẫu đơn → nhãn của B (`gold_B`).
    Cột nguồn ghi vào `gold_source` ('adjudicated' / 'single')."""
    if "gold_adj" in df and df.gold_adj.notna().any():
        adj = df.gold_adj.replace("", np.nan)
    else:
        adj = pd.Series(np.nan, index=df.index)
    dbl = df.double.astype(str).str.lower().isin(["true", "1"])
    if (dbl & adj.isna()).any():
        raise ValueError(f"{int((dbl & adj.isna()).sum())} mẫu gán đôi chưa có nhãn thống nhất (gold_adj)")
    out = adj.where(dbl, df.gold_B)
    return out


def gold_weights(df: pd.DataFrame) -> pd.DataFrame:
    """Gắn `w_addr`, `w_row` theo số địa chỉ ĐÃ GÁN trong từng ô (cell_n / n_đã_gán)."""
    n_lab = df.groupby("cell").cell.transform("size")
    out = df.copy()
    out["w_addr"] = out.cell_n / n_lab
    out["w_row"] = out.w_addr * out.n_rows
    out["census"] = n_lab >= out.cell_n                       # ô đã gán hết khung: không còn sai số lấy mẫu
    return out


def _w(d: pd.DataFrame, unit: str) -> np.ndarray:
    return d["w_addr" if unit == "addr" else "w_row"].to_numpy(float)


def confusion_w(gold, flag, w) -> dict:
    """Tổng có trọng số và P/R/F1/FPR."""
    gold, flag, w = np.asarray(gold, bool), np.asarray(flag, bool), np.asarray(w, float)
    tp, fp = w[flag & gold].sum(), w[flag & ~gold].sum()
    fn, tn = w[~flag & gold].sum(), w[~flag & ~gold].sum()
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * p * r / (p + r) if tp else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else float("nan")}


def stratified_boot(df: pd.DataFrame, boot: int = 1000, seed: int = 0, unit: str = "addr") -> dict:
    """CI 95% (percentile) của P/R/F1/FPR. Chỉ lấy lại mẫu có hoàn lại trong các ô được lấy mẫu (giữ nguyên số mẫu mỗi ô nên
    trọng số không đổi); ô điều tra toàn bộ giữ nguyên."""
    df = gold_weights(df)
    rng = np.random.default_rng(seed)
    cells = df.cell.to_numpy()
    fixed = np.flatnonzero(df.census.to_numpy())
    idx = [np.flatnonzero(cells == c) for c in df.cell[~df.census].unique()]
    gold, flag, w = df.gold.to_numpy(bool), df.flag.to_numpy(bool), _w(df, unit)
    est = confusion_w(gold, flag, w)
    draws = {k: [] for k in ("precision", "recall", "f1", "fpr")}
    for _ in range(boot):
        i = np.concatenate([fixed] + [rng.choice(ix, len(ix)) for ix in idx])
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


def hidden_positive_bound(df: pd.DataFrame, alpha: float = 0.05, unit: str = "addr", sims: int = 4000, seed: int = 0) -> dict:
    """Dương ẩn = nhãn vàng 1 ở tầng âm theo tác giả mà engine KHÔNG cảnh báo (làm recall thật thấp hơn recall đo được).
    Với mỗi ô âm không cờ chưa gán hết: tỉ lệ dương ~ Beta(k + 1/2, n − k + 1/2) (Jeffreys); số dương ẩn trong phần CHƯA gán
    (cỡ ô − n, tính theo `unit`) ~ nhị thức; cộng số đã thấy. `upper` = phân vị 1 − alpha của tổng qua các ô (độc lập),
    `upper_cp` = cộng cận Clopper–Pearson từng ô (rất bảo thủ). `recall_lower_bound` = TP / (TP + FN đã biết + upper).
    Ô gán hết đóng góp số thật, không bất định."""
    d = gold_weights(df)
    rng = np.random.default_rng(seed)
    neg = d[(d.stratum.str[0] == "-") & ~d.flag]
    size = "cell_n" if unit == "addr" else "cell_rows"
    unitcol = (lambda g: g.gold.astype(float)) if unit == "addr" else (lambda g: g.gold.astype(float) * g.n_rows)
    seen_total, sim, upper_cp = 0.0, np.zeros(sims), 0.0
    for _, g in neg.groupby("cell"):
        n, k = len(g), int(g.gold.sum())
        found = float(unitcol(g).sum())
        seen_total += found
        if g.census.iloc[0]:
            continue
        rest = float(g[size].iloc[0]) - (n if unit == "addr" else float(g.n_rows.sum()))
        p = rng.beta(k + .5, n - k + .5, sims)
        sim += rng.binomial(max(int(round(rest)), 0), p)
        upper_cp += max(rest, 0) * cp_upper(k, n, alpha)
        # `found` đã cộng ở seen_total; phần chưa gán cộng vào sim
    upper = seen_total + float(np.quantile(sim, 1 - alpha))
    point = seen_total + float(sim.mean())
    g1, fl = d.gold.astype(bool), d.flag.astype(bool)
    w = _w(d, unit)
    tp = float(w[g1 & fl].sum())
    fn_known = float(w[g1 & ~fl & (d.stratum.str[0] == "+")].sum())
    return {"hidden_positive_point": point, "hidden_positive_upper": upper, "hidden_positive_upper_cp": seen_total + upper_cp,
            "recall_lower_bound": tp / (tp + fn_known + upper) if tp else 0.0,
            "recall_lower_bound_cp": tp / (tp + fn_known + seen_total + upper_cp) if tp else 0.0}


def delegate_decided(items: pd.DataFrame) -> list[str]:
    """item_id của các mẫu mà nhãn do phân loại delegate quyết định (CODEBOOK ca 13): `code_at_event = 7702` trong
    main_items.csv, tức hôm nay là 7702, tx sau ngày kích hoạt và contract delegate đã có trước tx (v0.6.2). Thời điểm ủy quyền
    không được tra, nên tập này có thể còn mẫu ủy quyền sau tx (người gán khi đó theo bước D2). Phân loại do người điều phối
    điền sẵn và trùng một phần danh sách đen của engine (GOLD_PROTOCOL §2.3, §4 j)."""
    return items.loc[items.code_at_event.astype(str) == "7702", "item_id"].astype(str).tolist()


_HEX40 = r"0x[0-9a-fA-F]{40}"


def delegate_named(labels: pd.DataFrame, items: pd.DataFrame, lookup: pd.DataFrame) -> list[str]:
    """(j′, GOLD_PROTOCOL §4 j′) item_id có `code_at_event = unknown` mà `note` của người gán ghi địa chỉ đầy đủ (0x + 40 hex) của
    một delegate có trong bảng delegate cùng chain (CODEBOOK bước A: tab Authorizations cho thấy lúc tx đã ủy quyền tới delegate X
    → ghi X vào note → nhãn do bảng quyết định). So không phân biệt hoa thường; địa chỉ viết tắt không được tính."""
    if "note" not in labels or not len(lookup) or not {"chain", "code_at_event"} <= set(items.columns):
        return []
    table = {(str(c).lower(), str(d).lower()) for c, d in zip(lookup.chain, lookup.delegate)}
    it = items.assign(item_id=items.item_id.astype(str)).set_index("item_id")
    out = []
    for i, note in zip(labels.item_id.astype(str), labels.note.fillna("").astype(str)):
        if i not in it.index or str(it.at[i, "code_at_event"]) != "unknown":
            continue
        chain = str(it.at[i, "chain"]).lower()
        if any((chain, a.lower()) in table for a in re.findall(_HEX40, note)):
            out.append(i)
    return out


_CA7_UNLABELLED = r"ca\s*7\s*[bcd]\b"


def ca7_unlabelled(labels: pd.DataFrame) -> list[str]:
    """item_id có `note` nhắc "ca 7b", "ca 7c" hoặc "ca 7d" (CODEBOOK ca 7: lần rút nhanh về ví KHÔNG có nhãn sàn / custodian,
    kể cả ví có nhãn router / bridge, vẫn được tính, `confidence = low`). Dùng cho phân tích độ nhạy đăng ký trước
    (GOLD_PROTOCOL §4 k)."""
    if "note" not in labels:
        return []
    m = labels.note.fillna("").astype(str).str.contains(_CA7_UNLABELLED, case=False, regex=True)
    return labels.loc[m, "item_id"].astype(str).tolist()


def restrict_domain(d: pd.DataFrame, drop: pd.Series) -> pd.DataFrame:
    """Bỏ các mẫu `drop` khỏi miền đánh giá (ước lượng theo miền con): cỡ ô (`cell_n`, `cell_rows`) giảm theo tỉ lệ phần đã gán
    bị bỏ, nên trọng số của mẫu còn lại KHÔNG đổi; ô điều tra toàn bộ giảm đúng số mẫu bị bỏ."""
    drop = drop.astype(bool)
    g = d.groupby("cell")
    n_lab, n_ex = g.cell.transform("size"), drop.groupby(d.cell).transform("sum")
    r_lab, r_ex = g.n_rows.transform("sum"), (d.n_rows * drop).groupby(d.cell).transform("sum")
    out = d.copy()
    census = n_lab >= out.cell_n
    out["cell_n"] = np.where(census, out.cell_n - n_ex, out.cell_n * (n_lab - n_ex) / n_lab)
    out["cell_rows"] = np.where(census, out.cell_rows - r_ex, out.cell_rows * (r_lab - r_ex) / r_lab)
    return out[~drop.to_numpy()]


def evaluate(df: pd.DataFrame, boot: int = 1000, seed: int = 0, unknown: str = "zero", unit: str = "addr",
             exclude_strata: tuple[str, ...] = (), exclude_items=(), flip_to_negative=()) -> dict:
    """Báo cáo gộp theo `unit` ('addr' chính; 'row' phụ). `unknown`: '?' tính 0 / 1 / bỏ ('drop'); báo cả ba kịch bản.
    `exclude_strata`: bỏ các tầng (ví dụ ('+KEY', '+ADDR') vì nhãn KEY/ADDR là cận dưới, GOLD_PROTOCOL §6); ô còn lại tự tính lại trọng số.
    `exclude_items`: bỏ các item_id (ví dụ `delegate_decided(items)`) theo miền con, trọng số mẫu còn lại giữ nguyên.
    `flip_to_negative`: đặt nhãn vàng = 0 cho các item_id này (độ nhạy ca 7b/7c/7d: `ca7_unlabelled`), trước khi tính.
    Tiền đăng ký: báo cả đầy đủ và bỏ mẫu do delegate quyết định (GOLD_PROTOCOL §4 j, j′: thêm `delegate_named`); ca 7b/7c/7d:
    đầy đủ, lật về 0, và bỏ (§4 k)."""
    d = prepare(df, unknown)
    fl = set(map(str, flip_to_negative))
    if fl:
        if "item_id" not in d:
            raise ValueError("flip_to_negative cần cột item_id")
        d.loc[d.item_id.astype(str).isin(fl), "gold"] = 0
    if exclude_strata:
        d = d[~d.stratum.isin(exclude_strata)]
    ex = set(map(str, exclude_items))
    if ex:
        if "item_id" not in d:
            raise ValueError("exclude_items cần cột item_id")
        d = restrict_domain(d, d.item_id.astype(str).isin(ex))
    d = gold_weights(d)
    out = stratified_boot(d, boot, seed, unit)
    out.update(hidden_positive_bound(d, unit=unit, seed=seed))
    out["unit"] = unit
    out["n_labelled"] = len(d)
    return out
