from decimal import Decimal

import pandas as pd

from address_misuse.engine.features import Features, history_features
from address_misuse.engine.score import TxContext, s_bytecode, s_cross, s_history, s_osint, score_features

A = "0x" + "a" * 40


def feat(**kw) -> Features:
    base = {"address": A, "chain": "bsc", "code": {"bsc": "none", "eth": "none"}, "code_hash": {}}
    base.update(kw)
    return Features(**base)


def test_bytecode_none_depends_on_calldata():
    f = feat()
    assert s_bytecode(f, TxContext(calldata="0x7ff36ab5"))[:2] == (1.0, ["T1"])
    assert s_bytecode(f, TxContext(value_wei=10))[0] == 0.0


def test_bytecode_code_black_hole_vs_withdrawable():
    hole = {"transfer": False, "delegatecall": False, "selfdestruct": False}
    assert s_bytecode(feat(code={"bsc": "code"}, symexec=hole))[:2] == (1.0, ["T2"])
    assert s_bytecode(feat(code={"bsc": "code"}, symexec={**hole, "transfer": True}))[0] == 0.0


def test_bytecode_token_transfer_to_itself():
    data = "0xa9059cbb" + "0" * 24 + A[2:] + "0" * 64
    assert s_bytecode(feat(code={"bsc": "code"}), TxContext(calldata=data))[:2] == (1.0, ["T3"])


def test_bytecode_7702_benign_vs_malicious():
    f = feat(code={"bsc": "7702"}, delegate="0xd", delegate_benign=True)
    assert s_bytecode(f)[0] == 0.0
    f = feat(code={"bsc": "7702"}, delegate="0xd", delegate_malicious=True)
    assert s_bytecode(f)[:2] == (1.0, ["T5"])
    assert score_features(f).hard_rule == "malicious_delegate"


def test_cross_is_time_aware():
    f = feat(code={"bsc": "none", "eth": "code"}, at=1_000, first_create_ts=500)
    assert s_cross(f)[:2] == (1.0, ["T4"])
    f.first_create_ts = 2_000                       # deploy ở ETH sau thời điểm xét → không được biết trước
    assert s_cross(f)[0] == 0.0
    f.first_create_ts = None
    assert 0 < s_cross(f)[0] < 1


def test_cross_same_code_is_multichain_infra():
    f = feat(code={"bsc": "code", "eth": "code"}, code_hash={"bsc": "h1", "eth": "h1"})
    assert s_cross(f)[0] == 0.0
    f.code_hash["eth"] = "h2"
    assert s_cross(f)[1] == ["PCD-XC"]


def test_own_contract_created_after_at_counts_as_none():
    f = feat(code={"bsc": "code", "eth": "code"}, own_create_ts=2_000, at=1_000)
    assert f.state() == "none"


def test_osint_leaked_key_is_hard_rule():
    f = feat(leaked_key=True)
    assert s_osint(f)[0] == 1.0
    assert score_features(f).hard_rule == "leaked_key"


def _tx(block, frm, to, value, gas_used=21_000, gas_price=10, status=1, ts=None):
    return {"block_number": block, "transaction_index": 0, "block_ts": ts if ts is not None else block,
            "from_address": frm, "to_address": to, "value": Decimal(value), "gas_price": gas_price,
            "receipt_gas_used": gas_used, "receipt_status": status, "receipt_contract_address": None}


def test_history_detects_sweep_and_respects_at():
    victim, sweeper = "0x" + "1" * 40, A
    txs = pd.DataFrame([_tx(100, victim, A, 10**18, gas_price=10),
                        _tx(101, A, sweeper[:-1] + "b", 10**18 - 21_000 * 50, gas_price=50)])
    h = history_features(A, txs)
    assert (h["n_plain_in"], h["n_sweep"]) == (1, 1)
    assert s_history(Features(A, "eth", history=h))[0] == 1.0
    assert history_features(A, txs, at=100)["n_tx"] == 0          # chỉ dùng tx trước `at`


def test_history_calls_from_many_senders_to_codeless_address():
    txs = pd.DataFrame([_tx(1, "0x" + "1" * 40, A, 0, gas_used=25_000),
                        _tx(2, "0x" + "2" * 40, A, 0, gas_used=25_000)])
    f = Features(A, "eth", code={"eth": "none"}, history=history_features(A, txs))
    assert s_history(f)[0] == 1.0
    assert s_bytecode(f)[0] == 1.0                                 # không ctx: theo tỉ lệ tx có calldata


def test_score_range_and_weights():
    f = feat(code={"bsc": "none", "eth": "code"})                 # at=None: hôm nay đã là contract ở ETH
    r = score_features(f, TxContext(calldata="0x12345678"))
    assert r.components["bytecode"] == r.components["cross"] == 1.0
    assert r.score == 50.0 and r.types == ["T1", "T4"]
    r = score_features(f, TxContext(calldata="0x12345678"), weights={"bytecode": 0, "cross": 1, "osint": 0,
                                                                     "history": 0})
    assert r.score == 100.0
