import numpy as np
import pandas as pd
import pytest

from address_misuse.sample_gold import _pick, _state, cohen_kappa


def test_cohen_kappa_known_values():
    assert cohen_kappa(list("aabb"), list("aabb")) == 1.0
    assert cohen_kappa(["1", "1", "0", "0"], ["1", "0", "1", "0"]) == pytest.approx(0.0)
    # ví dụ kinh điển: po = 0,7, pe = 0,5 → κ = 0,4
    a = ["y"] * 25 + ["n"] * 25
    b = ["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15
    assert cohen_kappa(a, b) == pytest.approx(0.4)
    assert cohen_kappa(["x"] * 3, ["x"] * 3) == 1.0
    with pytest.raises(ValueError):
        cohen_kappa(["a"], [])


def test_pick_mixes_high_and_low_loss_and_is_deterministic():
    df = pd.DataFrame({"address": [f"a{i}" for i in range(100)], "cost_native": np.arange(100.0)})
    p1 = _pick(df, 10, np.random.default_rng(0))
    p2 = _pick(df, 10, np.random.default_rng(0))
    assert list(p1.address) == list(p2.address) and p1.address.is_unique and len(p1) == 10
    assert (p1.cost_native >= 74.25).sum() == 5                   # một nửa từ top 25%
    assert len(_pick(df.head(3), 10, np.random.default_rng(0))) == 3


def test_state_from_code_record():
    assert _state({"a": "x", "err": 1}) is None
    assert _state({"a": "x", "s": 0}) == "none"
    assert _state({"a": "x", "d": "0xcd"}) == "7702"
    assert _state({"a": "x", "s": 5, "h": "ab"}) == "code"


def test_delegations_uses_symexec_and_known_wallets():
    from address_misuse.sample_gold import delegations
    s = {"eip7702_delegations": pd.DataFrame({"chain": ["bsc"] * 4, "eoa_list": ["KEY"] * 4,
                                              "eoa": ["e1", "e2", "e3", "e1"], "delegate": ["dA", "dB", "dC", "dA"]}),
         "symexec_results": pd.DataFrame({"chain": ["bsc", "bsc"], "kind": ["eip7702_delegate"] * 2,
                                          "address": ["dA", "dB"], "transfer_all_eth": [True, False],
                                          "transfer_msg_value": [False, False], "transfer_input_amount": [False, False]}),
         "n6": pd.DataFrame({"address": ["dA"], "wallet": ["Ví X"], "kept": [True]})}
    d = delegations(s).set_index("address")
    assert len(d) == 3                                          # bỏ trùng (chain, EOA)
    assert d.loc["e1", "delegate_symexec_transfer"] is True and d.loc["e1", "delegate_known_wallet"] == "Ví X"
    assert d.loc["e2", "delegate_symexec_transfer"] is False and pd.isna(d.loc["e2", "delegate_known_wallet"])
    assert pd.isna(d.loc["e3", "delegate_symexec_transfer"])  # delegate chưa được phân tích


def test_live_evidence_is_uniform():
    from address_misuse.config import NETWORKS
    from address_misuse.crosschain_matrix import _code_record
    from address_misuse.sample_gold import live_evidence
    a = "0x" + "aa" * 20
    none = {n: _code_record(a, "0x") for n in NETWORKS}
    ev = live_evidence("eth", none)
    assert ev["xc_nets"] == "" and ev["same_code_elsewhere"] is False and ev["delegate_7702"] is None
    recs = {**none, "eth": _code_record(a, "0x6080"), "bsc": _code_record(a, "0x6080"), "arb": _code_record(a, "0x60")}
    ev = live_evidence("eth", recs)
    assert ev["xc_nets"] == "bsc,arb" and ev["same_code_elsewhere"] is True
    ev = live_evidence("bsc", {**none, "bsc": _code_record(a, "0xef0100" + "cd" * 20), "eth": _code_record(a, None)})
    assert ev["code_bsc"] == "7702" and ev["delegate_7702"] == "0x" + "cd" * 20 and ev["code_eth"] is None
    assert ev["same_code_elsewhere"] is False


def test_event_tx_recovers_incoming_tx_at_event_time(tmp_path, monkeypatch):
    import gzip
    import json
    import address_misuse.engine.features as F
    from address_misuse.sample_gold import event_tx
    a = "0x" + "aa" * 20
    txs = [
        {"hash": "0x1", "to": a, "timeStamp": "100", "gasUsed": "21000", "transactionIndex": "0", "input": "0x", "value": "5"},
        {"hash": "0x2", "to": a, "timeStamp": "100", "gasUsed": "90000", "transactionIndex": "3", "input": "0xa9059cbb00", "value": "0"},
        {"hash": "0x3", "to": "0x" + "bb" * 20, "timeStamp": "100", "gasUsed": "90000", "transactionIndex": "1", "input": "0x", "value": "0"},
        {"hash": "0x4", "to": a, "timeStamp": "101", "gasUsed": "90000", "transactionIndex": "0", "input": "0x", "value": "0"},
    ]
    p = tmp_path / "tx.json.gz"
    with gzip.open(p, "wt", encoding="utf-8") as f:
        json.dump({"result": txs}, f)
    monkeypatch.setattr(F, "txlist_path", lambda chain, address: p)
    assert event_tx("eth", a, 100)["hash"] == "0x2"            # ưu tiên tx có calldata, bỏ tx đi tới địa chỉ khác
    assert event_tx("eth", a, 999) is None
    assert event_tx("eth", a, None) is None
    monkeypatch.setattr(F, "txlist_path", lambda chain, address: tmp_path / "none.gz")
    assert event_tx("eth", a, 100) is None


def test_key_sweep_measures_time_to_drain_and_classifies_recipient():
    from address_misuse.key_sweep import analyze, classify, summarize
    k1, k2, w, s1, s2, thief = ("0x" + c * 40 for c in "abcdef")

    def tx(b, i, ts, frm, to, val, status=1, fee=1e12):
        return {"block_number": b, "transaction_index": i, "block_ts": ts, "from_address": frm, "to_address": to,
                "value_wei": val, "receipt_status": status, "fee_wei": fee, "order": b * 100_000 + i}
    df = pd.DataFrame([
        tx(100, 0, 1000, s1, k1, 1e18), tx(101, 0, 1012, k1, thief, 0.999e18),        # rút sau 1 block
        tx(200, 0, 2000, s2, k1, 1e18), tx(300, 0, 5000, k1, thief, 0.99e18),         # rút sau 3000 s (<=1 giờ)
        tx(400, 0, 9000, s1, k1, 1e18, status=0),                                     # nạp lỗi: bỏ
        tx(500, 0, 9500, s1, k2, 2e18), tx(501, 0, 9512, k2, s1, 1.99e18),             # trả về người gửi
        tx(600, 0, 9900, s1, k2, 1e18),                                               # không thấy rút
        tx(700, 0, 20000, s1, k1, 1e18), tx(701, 0, 20012, k1, w, 0.2e18)])            # rút ít hơn 95%: không tính
    d = analyze(df, {k1, k2})
    assert len(d) == 5
    d = d.set_index(["addr", "in_block"])
    assert d.loc[(k1, 100), "dt_block"] == 1 and d.loc[(k1, 200), "dt_sec"] == 3000
    assert not d.loc[(k1, 700), "drained"] and not d.loc[(k2, 600), "drained"]
    d = classify(d.reset_index(), {k1, k2})
    kinds = d.set_index(["addr", "in_block"]).recipient_kind
    assert kinds[(k2, 500)] == "trả về người gửi" and kinds[(k1, 100)] == "ví khác" and kinds[(k1, 700)] == "không thấy rút"
    s = summarize(d).set_index("tập").loc["tất cả"]
    assert s["tx <=2 block"] == 2 and s["tx <=1 giờ"] == 1 and s["số khoản nạp"] == 5
