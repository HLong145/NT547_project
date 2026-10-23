import numpy as np
import pandas as pd
import pytest

from address_misuse.engine.metrics import auc, confusion, curve, fit_nonneg_logistic, pick_thresholds


def test_nonneg_logistic_ignores_negative_signal():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 400)
    X = np.c_[y + rng.normal(0, .3, 400), 1 - y + rng.normal(0, .3, 400)]   # cột 2 tương quan âm với nhãn
    _, b = fit_nonneg_logistic(X, y)
    assert b[0] > 0 and b[1] == 0


def test_confusion_and_auc():
    y = np.array([1, 1, 0, 0])
    c = confusion(y, np.array([True, False, True, False]))
    assert (c["tp"], c["fp"], c["fn"], c["tn"]) == (1, 1, 1, 1)
    assert c["precision"] == c["recall"] == c["fpr"] == 0.5
    assert auc(y, np.array([.9, .8, .1, .2])) == 1.0
    assert auc(y, np.array([.5, .5, .5, .5])) == 0.5


def test_thresholds_respect_n8_fpr():
    val = pd.DataFrame({"label": [1, 1, 0, 0, 0], "grp": ["+NCD", "+NCD", "-N8", "-N8", "-N1"], "hard": None})
    r = pd.Series([90.0, 60.0, 70.0, 10.0, 5.0])
    t = pick_thresholds(val, r)
    assert t["warn"] == pytest.approx(90.0)           # 70 trên N8 phải nằm dưới ngưỡng
    assert t["block"] >= t["warn"]


def test_curve_ends_at_full_recall():
    c = curve("x", np.array([1, 0, 1, 0]), np.array([.9, .8, .7, .1]))
    assert c.tpr.iloc[-1] == 1.0 and c.fpr.iloc[-1] == 1.0
    assert c.threshold.is_monotonic_decreasing
