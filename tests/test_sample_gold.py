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
