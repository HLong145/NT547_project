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


def _gold_ds():
    rows = []
    for i in range(300):                                    # +NCD: 150 địa chỉ, 100 địa chỉ có 2 dòng test, 50 có 1
        rows.append({"chain": "eth" if i % 2 else "bsc", "address": f"0x{i % 150:03d}", "grp": "+NCD",
                     "label_source": "author", "split": "test" if i < 250 else "train", "out_of_time": False, "flag": False})
    rows += [{"chain": "eth", "address": "0xex", "grp": "+NCD", "label_source": "author", "split": "excluded",
              "out_of_time": False, "flag": False}]
    rows += [{"chain": "eth", "address": f"0xd{i}", "grp": "+KEY", "label_source": "d6_rule", "split": "test",
              "out_of_time": True, "flag": False} for i in range(5)]
    for i in range(200):                                    # -N3: 100 eth + 100 bsc, 2 địa chỉ eth bị engine gắn cờ
        rows.append({"chain": "eth" if i < 100 else "bsc", "address": f"0xn{i:03d}", "grp": "-N3", "label_source": "scan",
                     "split": "test", "out_of_time": False, "flag": i in (3, 4)})
    return pd.DataFrame(rows)


def test_draw_main_census_for_positives_and_flagged_negatives_with_chain_weights():
    from address_misuse import sample_gold as sg
    ds = _gold_ds()
    out = sg.draw_main(ds, seed=1, n_double=10)
    assert not out.duplicated(["chain", "address"]).any()
    assert "0xex" not in set(out.address) and (out.split != "train").all()
    assert set(out.loc[out.stratum == "+D6", "address"]) == {f"0xd{i}" for i in range(5)}   # d6_rule thành tầng riêng
    assert out.double.sum() == 10 and out.item_id.is_unique
    ncd = out[out.stratum == "+NCD"]
    assert len(ncd) == 150 and (ncd.w_addr == 1).all()                  # dương: lấy hết, trọng số 1
    assert ncd.w_row.sum() == 250                                        # tổng dòng khung: 100 địa chỉ × 2 dòng + 50 × 1
    n3 = out[out.stratum == "-N3"]
    flagged = n3[n3.flag]
    assert set(flagged.address) == {"0xn003", "0xn004"} and (flagged.w_addr == 1).all()   # âm có cờ: lấy hết
    # âm không cờ: 40 địa chỉ chia đều eth/bsc, trọng số theo từng chain (eth còn 98 địa chỉ không cờ, bsc 100)
    un = n3[~n3.flag]
    assert len(un) == 40 and un.groupby("chain").size().to_dict() == {"bsc": 20, "eth": 20}
    for chain, size in (("eth", 98), ("bsc", 100)):
        w = un[un.chain == chain].w_addr
        assert abs(w.iloc[0] - size / 20) < 1e-9
        assert abs(w.sum() - size) < 1e-9                                # Σ w_addr = cỡ ô


def test_draw_reserve_continues_cell_order_and_is_disjoint_from_core():
    from address_misuse import sample_gold as sg
    ds = _gold_ds()
    core, res = sg.draw_main(ds, seed=1), sg.draw_reserve(ds, seed=1)
    assert not (set(zip(core.chain, core.address)) & set(zip(res.chain, res.address)))
    assert (res.stratum == "-N3").all() and (~res.flag).all()
    assert len(res) == 98 + 100 - 40
    assert res.item_id.is_unique and res.batch.max() == -(-len(res) // sg.RESERVE_BATCH)
    first = res.head(sg.RESERVE_BATCH)                                   # tiền tố ≈ tỉ lệ cỡ ô (eth 78 : bsc 80)
    assert abs((first.chain == "eth").sum() - 25) <= 2
    assert sg.draw_reserve(ds, seed=1).equals(res)                       # thứ tự cố định theo seed


def test_gold_eval_weights_ci_and_hidden_positive_bound():
    from address_misuse import gold_eval as ge
    # 1) census (w = 1) thì khớp công thức đếm
    c = ge.confusion_w([1, 1, 0, 0], [1, 0, 1, 0], [1, 1, 1, 1])
    assert c["tp"] == 1 and c["fp"] == 1 and c["fn"] == 1 and c["tn"] == 1 and abs(c["precision"] - .5) < 1e-12
    # 2) cận Clopper–Pearson: k = 0 có công thức đóng; k > 0 lớn hơn tỉ lệ mẫu
    assert abs(ge.cp_upper(0, 59) - (1 - 0.05 ** (1 / 59))) < 1e-12 and ge.cp_upper(2, 50) > 2 / 50
    # 3) bảng nhỏ: ô dương gán hết (cell_n = n), ô âm 4 trong 40 địa chỉ, không dương ẩn
    rows = [{"cell": "+A|eth|u", "stratum": "+A", "flag": f, "gold": g, "n_rows": 1, "cell_n": 4, "cell_rows": 4}
            for f, g in ((1, 1), (1, 1), (1, 0), (0, 1))]
    rows += [{"cell": "-N|eth|u", "stratum": "-N", "flag": 0, "gold": 0, "n_rows": 2, "cell_n": 40, "cell_rows": 80}] * 4
    df = pd.DataFrame(rows)
    w = ge.gold_weights(df)
    assert (w.w_row[w.stratum == "+A"] == 1).all() and (w.w_row[w.stratum == "-N"] == 20).all()
    r = ge.evaluate(df, boot=50, seed=0)
    assert abs(r["precision"] - 2 / 3) < 1e-9 and abs(r["recall"] - 2 / 3) < 1e-9
    assert abs(r["fpr"] - 1 / (1 + 40)) < 1e-9 and abs(ge.evaluate(df, boot=5, unit="row")["fpr"] - 1 / (1 + 80)) < 1e-9 and r["precision_ci"][0] <= r["precision"] <= r["precision_ci"][1]
    assert r["hidden_positive_point"] >= 0 and r["hidden_positive_upper"] > 0              # 0/4 vẫn có cận trên > 0
    assert r["hidden_positive_upper_cp"] >= r["hidden_positive_upper"] * 0.8               # CP không nhỏ hơn Jeffreys nhiều
    assert 0 < r["recall_lower_bound"] < r["recall"]


def test_gold_eval_string_flags_census_cells_and_row_unit():
    from address_misuse import gold_eval as ge
    base = [{"cell": "+A|eth|u", "stratum": "+A", "flag": f, "gold": g, "n_rows": 3 if i == 0 else 1, "cell_n": 4, "cell_rows": 6}
            for i, (f, g) in enumerate(((1, 1), (1, 1), (1, 0), (0, 1)))]
    num, txt = pd.DataFrame(base), pd.DataFrame(base).astype({"flag": str, "gold": str})   # CSV đọc ra "1"/"True"…
    txt["flag"] = txt.flag.map({"1": "True", "0": "False"})
    a, b = ge.evaluate(num, boot=20), ge.evaluate(txt, boot=20)
    assert abs(a["precision"] - 2 / 3) < 1e-9 and a["precision"] == b["precision"] and a["recall"] == b["recall"]
    assert a["precision_ci"] == [a["precision"]] * 2                                   # ô điều tra toàn bộ: không có sai số lấy mẫu
    row = ge.evaluate(num, boot=20, unit="row")
    assert abs(row["precision"] - 4 / 5) < 1e-9                                         # tp = 3 + 1 dòng, fp = 1
    bad = txt.copy()
    bad.loc[0, "flag"] = "maybe"
    try:
        ge.evaluate(bad, boot=5)
        raise AssertionError("phải báo lỗi cờ không hợp lệ")
    except ValueError:
        pass
    q = txt.copy()
    q.loc[3, "gold"] = "?"
    assert ge.evaluate(q, boot=5, unknown="zero")["recall"] > ge.evaluate(q, boot=5, unknown="one")["recall"]   # ? chưa cờ: tính 1 làm recall giảm
    assert ge.evaluate(q, boot=5, unknown="drop")["n_labelled"] == 3


def test_final_gold_requires_adjudication_for_double_items():
    from address_misuse import gold_eval as ge
    df = pd.DataFrame({"double": [True, False, True], "gold_B": [1, 0, 1], "gold_adj": [0, None, None]})
    try:
        ge.final_gold(df)
        raise AssertionError("mẫu gán đôi thiếu nhãn thống nhất phải báo lỗi")
    except ValueError:
        pass
    df.loc[2, "gold_adj"] = 1
    assert ge.final_gold(df).tolist() == [0, 0, 1]


def test_n_rows_counts_whole_frame_and_extra_double_rank():
    from address_misuse import sample_gold as sg
    ds = _gold_ds()
    u = sg._units(ds, seed=1)
    pool = ds[((ds.split == "test") | ds.out_of_time) & (ds.split != "excluded")]
    assert u.n_rows.sum() == len(pool)                                                  # Σ n_rows = cỡ khung (không mất dòng)
    out = sg.draw_main(ds, seed=1, n_double=10)
    ex = out.loc[~out.double, "double_extra_rank"]
    assert sorted(ex) == list(range(len(ex))) and (out.loc[out.double, "double_extra_rank"] == -1).all()
