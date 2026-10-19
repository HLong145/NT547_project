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
