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


def test_threshold_pools_normal_traffic_and_block_is_stricter():
    from address_misuse.engine.metrics import NORMAL_GRPS
    assert set(NORMAL_GRPS) == {"-N2", "-N3", "-N8"}
    val = pd.DataFrame({"label": [1] * 5 + [0] * 4, "grp": ["+NCD"] * 5 + ["-N2", "-N3", "-N8", "-N1"], "hard": None})
    r = pd.Series([95.0, 90.0, 85.0, 80.0, 75.0, 60.0, 40.0, 20.0, 99.0])    # N1 không thuộc lưu lượng bình thường
    t = pick_thresholds(val, r)
    assert t["warn"] == pytest.approx(75.0)        # FPR ≤ 1% trên N2+N3+N8: cao hơn 60 nhỏ nhất
    assert t["block"] >= t["warn"]
    assert t["block"] > 99.0                       # block phải loại cả âm N1 (R = 99): FPR ≤ 0,1% trên mọi âm


def test_cluster_bootstrap_resamples_whole_addresses():
    from address_misuse.engine.metrics import cluster_index, resample
    d = pd.DataFrame({"chain": "eth", "address": ["0xa", "0xb", "0xa", "0xc", "0xb"]})
    cl = cluster_index(d)
    assert sorted(len(c) for c in cl) == [1, 2, 2]
    i = resample(cl, np.random.default_rng(0))
    for a in set(d.address.iloc[i]):               # địa chỉ nào được chọn thì mọi dòng của nó đều có mặt
        assert (d.address.iloc[i] == a).sum() % (d.address == a).sum() == 0


def test_recall_split_between_hard_rule_and_R():
    from address_misuse.engine.metrics import evaluate_set
    d = pd.DataFrame({"label": [1, 1, 1, 0], "grp": ["+KEY", "+ADDR", "+ADDR", "-N8"], "chain": "eth",
                      "address": ["0x1", "0x2", "0x3", "0x4"], "hard": ["leaked_key", None, None, "sweeper"]})
    e = evaluate_set(d, pd.Series([0.0, 80.0, 10.0, 5.0]), {"warn": 50.0, "block": 50.0}, 0, np.random.default_rng(0))["warn"]
    assert e["recall_by_group_hard"] == {"+ADDR": 0.0, "+KEY": 1.0}
    assert e["recall_by_group_R_only_on_soft"]["+ADDR"] == 0.5 and e["recall_by_group_R_only_on_soft"]["+KEY"] is None
    assert e["fp_by_hard_rule"] == {"sweeper": 1}


def test_block_threshold_requires_no_false_positive_even_when_precision_is_high():
    val = pd.DataFrame({"label": [1] * 30 + [0], "grp": ["+NCD"] * 30 + ["-N8"], "hard": None})
    r = pd.Series([90.0] * 30 + [95.0])               # precision tại t ≤ 95 là 30/31 ≥ 0,95, nhưng có 1 âm ở 95
    t = pick_thresholds(val, r)
    assert t["block"] > 95.0                          # chỉ precision thì block = 90; FPR_BLOCK đẩy lên trên âm


def test_ablation_without_history_drops_sweeper_rule():
    from address_misuse.engine.metrics import run
    df = pd.DataFrame({"label": [1, 1, 0, 0] * 4, "grp": ["+ADDR", "+ADDR", "-N8", "-N8"] * 4,
                       "split": ["train"] * 4 + ["val"] * 4 + ["test"] * 4 + ["test"] * 4, "out_of_time": False,
                       "chain": "eth", "address": [f"0x{i}" for i in range(16)], "state": "none", "types": "",
                       "bytecode": [1.0, 1.0, 0.0, 0.0] * 4, "cross": 0.0, "osint": 0.0, "history": 0.0,
                       "hard": ["sweeper", None, None, None] * 4})
    full = run(df, ["bytecode", "cross", "osint", "history"], boot=0)
    no_hist = run(df, ["bytecode", "cross", "osint"], boot=0)
    assert full["sets"]["test"]["warn"]["hard_only"]["tp"] == 2
    assert no_hist["sets"]["test"]["warn"]["hard_only"]["tp"] == 0


def test_draw_main_uses_eval_split_weights_and_unique_addresses():
    from address_misuse import sample_gold as sg
    rows = []
    for i in range(300):
        rows.append({"chain": "eth" if i % 2 else "bsc", "address": f"0x{i % 150:03d}", "grp": "+NCD",
                     "label_source": "author", "split": "test" if i < 250 else "train", "out_of_time": False})
    rows += [{"chain": "eth", "address": "0xex", "grp": "+NCD", "label_source": "author", "split": "excluded",
              "out_of_time": False}]
    rows += [{"chain": "eth", "address": f"0xd{i}", "grp": "+KEY", "label_source": "d6_rule", "split": "test",
              "out_of_time": True} for i in range(5)]
    ds = pd.DataFrame(rows)
    out = sg.draw_main(ds, seed=1, n_double=10)
    assert not out.duplicated(["chain", "address"]).any()
    assert "0xex" not in set(out.address) and (out.split != "train").all()
    assert set(out.loc[out.stratum == "+D6", "address"]) == {f"0xd{i}" for i in range(5)}   # d6_rule thành tầng riêng
    assert out.double.sum() == 10 and out.item_id.is_unique
    ncd = out[out.stratum == "+NCD"]
    assert abs(ncd.weight.iloc[0] * len(ncd) - 150) < 1e-9          # 150 địa chỉ test duy nhất ở tầng +NCD (không tính excluded)
