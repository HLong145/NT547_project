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


def test_learn_weights_ignores_hard_rule_samples():
    from address_misuse.engine.metrics import learn_weights
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 300)
    soft = pd.DataFrame({"a": y + rng.normal(0, .3, 300), "b": rng.normal(0, .3, 300), "label": y, "hard": None})
    key = pd.DataFrame({"a": 0.0, "b": 1.0, "label": 1, "hard": "leaked_key"}, index=range(300, 600))
    w = learn_weights(pd.concat([soft, key]), ["a", "b"])
    assert w["a"] > 0.9                                            # mẫu KEY (b = 1) không kéo trọng số về b


def test_goplus_flag_and_baseline_only_on_looked_up_samples():
    from address_misuse.engine.goplus import flagged
    from address_misuse.engine.metrics import goplus_baseline
    assert flagged({"stealing_attack": "1", "contract_address": "0"}) is True
    assert flagged({"contract_address": "1", "number_of_malicious_contracts_created": "0"}) is False
    assert flagged({"number_of_malicious_contracts_created": "2"}) is True
    assert flagged(None) is None
    d = pd.DataFrame({"label": [1, 1, 0, 0], "grp": ["+ADDR", "+NCD", "-N1", "-N8"], "hard": None,
                      "goplus_flag": [True, None, False, True]})
    g = goplus_baseline(d, pd.Series([0.0, 99.0, 0.0, 0.0]), {"warn": 50.0})
    assert g["coverage"] == 0.75
    assert (g["goplus"]["tp"], g["goplus"]["fp"], g["goplus"]["fn"]) == (1, 1, 0)   # mẫu chưa tra (+NCD) bị bỏ
    assert g["engine_same_samples"]["tp"] == 0
