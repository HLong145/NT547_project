"""Kiểm tra độc lập số liệu chính của `engine.metrics`: học lại w bằng Newton–Raphson (có loại dần hệ số âm), chọn lại
τ_warn trên val, tính P/R/F1/FPR trên test. Không dùng code của metrics.py, chỉ đọc engine_eval.parquet.

python -X utf8 -m address_misuse.engine.verify_independent [--l2 1e-3 1e-4 1e-2 1e-1]
Với cùng l2 (1e-3) phải ra gần như đúng w và τ của metrics.py; đổi l2 cho thấy w không xác định (dữ liệu gần tách được)
nhưng kết quả test hầu như không đổi.
"""

import argparse

import numpy as np
import pandas as pd

from address_misuse.config import INTERIM_DIR

C = ["bytecode", "cross", "osint", "history"]
NORMAL = ["-N2", "-N3", "-N8"]


def fit(X: np.ndarray, y: np.ndarray, l2: float) -> np.ndarray:
    sw = np.where(y == 1, (len(y) - y.sum()) / y.sum(), 1.0)
    sw /= sw.mean()
    cols = list(range(X.shape[1]))
    while True:
        Z = np.c_[np.ones(len(y)), X[:, cols]]
        reg = l2 * np.r_[0, np.ones(len(cols))]
        p = np.zeros(Z.shape[1])
        for _ in range(100):
            pr = 1 / (1 + np.exp(-Z @ p))
            g = Z.T @ (sw * (pr - y)) / len(y) + reg * p
            H = (Z * (sw * pr * (1 - pr))[:, None]).T @ Z / len(y) + np.diag(reg)
            p = p - np.linalg.solve(H, g)
        if (p[1:] >= 0).all():
            break
        cols.pop(int(np.argmin(p[1:])))
    b = np.zeros(X.shape[1])
    b[cols] = p[1:]
    return b / b.sum()


def run(df: pd.DataFrame, l2: float) -> dict:
    tr = df[(df.split == "train") & df.hard.isna()]
    w = fit(tr[C].to_numpy(float), tr.label.to_numpy(float), l2)
    R = lambda d: 100 * (d[C].to_numpy(float) @ w)
    va = df[df.split == "val"]
    soft, r = va.hard.isna().to_numpy(), R(va)
    normal = va.grp.isin(NORMAL).to_numpy() & soft
    tau = next(t for t in np.unique(np.r_[r[soft], 100.0001]) if (r[normal] >= t).mean() <= 0.01)
    te = df[df.split == "test"]
    pred, y = te.hard.notna().to_numpy() | (R(te) >= tau), te.label.to_numpy()
    tp, fp, fn, tn = (pred & (y == 1)).sum(), (pred & (y == 0)).sum(), (~pred & (y == 1)).sum(), (~pred & (y == 0)).sum()
    p, rc = tp / (tp + fp), tp / (tp + fn)
    return {"w": dict(zip(C, map(float, w))), "tau_warn": float(tau), "precision": float(p), "recall": float(rc),
            "f1": float(2 * p * rc / (p + rc)), "fpr": float(fp / (fp + tn))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--l2", type=float, nargs="+", default=[1e-3, 1e-4, 1e-2, 1e-1])
    df = pd.read_parquet(INTERIM_DIR / "engine_eval.parquet")
    for l2 in ap.parse_args().l2:
        r = run(df, l2)
        print(f"l2={l2:g}  w=" + "/".join(f"{v:.3f}" for v in r["w"].values()) + f"  τ_warn={r['tau_warn']:.1f}  "
              f"test P={r['precision']:.3f} R={r['recall']:.3f} F1={r['f1']:.3f} FPR={r['fpr']:.4f}")


if __name__ == "__main__":
    main()
