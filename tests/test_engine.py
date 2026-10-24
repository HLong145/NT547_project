from decimal import Decimal

import pandas as pd

from address_misuse.engine.features import Features, history_features, txlist_frame
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
    assert s_bytecode(f, TxContext(calldata="0x" + "gm, hello there".encode().hex()))[0] == 0.0   # IDM


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
    f.at = 1_700_000_000                                            # trước khi EIP-7702 kích hoạt: EOA thường
    assert f.state() == "none" and score_features(f).hard_rule is None


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


def test_cross_same_selectors_despite_different_hash():
    sels = frozenset(f"0x{i:08x}" for i in range(10))
    f = feat(code={"bsc": "code", "eth": "code"}, code_hash={"bsc": "h1", "eth": "h2"},
             selectors={"bsc": sels, "eth": sels | {"0xdeadbeef"}})            # vd. immutable WETH khác nhau
    assert s_cross(f)[0] == 0.0
    f.selectors["eth"] = frozenset({"0x11111111", "0x22222222"})
    assert s_cross(f)[1] == ["PCD-XC"]


def test_txlist_frame_matches_bq_columns():
    t = [{"blockNumber": "5", "transactionIndex": "1", "timeStamp": "100", "from": "0xAb", "to": "", "value": "7",
          "gasPrice": "2", "gasUsed": "50000", "isError": "0", "txreceipt_status": "1", "contractAddress": "0xC"},
         {"blockNumber": "0", "transactionIndex": "0", "timeStamp": "1", "from": "GENESIS", "to": "0xab", "value": "1",
          "gasPrice": "0", "gasUsed": "0", "isError": "0", "contractAddress": ""}]
    df = txlist_frame(t)
    assert len(df) == 1                                                       # bỏ bản ghi GENESIS
    r = df.iloc[0]
    assert (r.from_address, r.to_address, r.receipt_contract_address, r.receipt_status) == ("0xab", None, "0xc", 1)


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


def test_nodereal_record_converts_to_txlist_format():
    from address_misuse.engine.prepare import _nodereal_record
    zero = "0x" + "0" * 40
    base = {"blockNum": hex(20_000_000), "blockTimeStamp": 100, "hash": "0x1", "from": "0xAB", "value": "0x0a", "gas": 30000,
            "gasPrice": 5, "gasUsed": 21000, "receiptsStatus": 1, "input": "0x"}
    t = [_nodereal_record({**base, "to": A, "contractAddress": zero}, 0),
         _nodereal_record({**base, "to": zero, "contractAddress": "0xCC", "receiptsStatus": 0}, 1)]
    df = txlist_frame(t)
    assert (df.block_number.tolist(), df.value.tolist(), df.to_address[0]) == ([20_000_000] * 2, [10, 10], A)
    assert pd.isna(df.to_address[1])
    assert pd.isna(df.receipt_contract_address[0]) and df.receipt_contract_address[1] == "0xcc"
    assert df.receipt_status.tolist() == [1, 0]
    old = {**base, "blockNum": hex(1_000_000), "to": A, "contractAddress": zero, "receiptsStatus": 0}
    assert _nodereal_record(old, 0)["isError"] == "0"                          # trước Byzantium: theo gas
    assert _nodereal_record({**old, "gasUsed": 30000}, 0)["isError"] == "1"
    assert _nodereal_record(old, 0, chain="bsc")["isError"] == "1"


def test_pick_event_uses_misuse_txs_only():
    from address_misuse.engine.evaluate import CALL_PLACEHOLDER, pick_event
    txs = pd.DataFrame([_tx(1, "0x" + "1" * 40, A, 5), _tx(2, "0x" + "2" * 40, A, 0, gas_used=40_000),
                        _tx(3, A, "0x" + "3" * 40, 1)])
    at, ctx = pick_event(txs, A, "+NCD", None, seed=0)
    assert (at, ctx.calldata) == (2, CALL_PLACEHOLDER)                 # NCD: chỉ tx gọi hàm
    assert pick_event(txs, A, "+PCD", 5, seed=0) is None                # PCD: chỉ tx sau khi contract được tạo
    assert pick_event(txs, A, "-N1", None, seed=0)[0] in (1, 2)
    assert pick_event(None, A, "-N1", None, seed=0) is None


def test_assign_split_by_time_without_address_overlap():
    from address_misuse.config import SPLIT_TEST_TS, SPLIT_VAL_TS
    from address_misuse.engine.evaluate import assign_split
    df = pd.DataFrame({"chain": "eth", "address": ["0xa", "0xb", "0xb", "0xc"], "label": [1, 0, 0, 0],
                       "at": [SPLIT_VAL_TS - 1, SPLIT_VAL_TS, SPLIT_TEST_TS + 5, None]})
    assert assign_split(df).split.tolist() == ["train", "val", "excluded", "no_time"]


def test_history_uses_only_last_window_before_at():
    txs = pd.DataFrame([_tx(b, "0x" + "1" * 40, A, 0, gas_used=25_000) for b in range(1, 11)])
    h = history_features(A, txs, at=9, window=3)                  # tx block 6, 7, 8
    assert h["n_tx"] == 3 and h["n_in_call"] == 3
    assert history_features(A, txs, window=None)["n_tx"] == 10


def test_pick_event_uses_real_input_when_available():
    from address_misuse.engine.evaluate import CALL_PLACEHOLDER, pick_event
    t = dict(_tx(5, "0x" + "1" * 40, A, 0, gas_used=25_000), input="0x48656c6c6f")
    at, ctx = pick_event(pd.DataFrame([t]), A, "+NCD", None, 0)
    assert at == 5 and ctx.calldata == "0x48656c6c6f"
    _, ctx = pick_event(pd.DataFrame([_tx(5, "0x" + "1" * 40, A, 0, gas_used=25_000)]), A, "+NCD", None, 0)
    assert ctx.calldata == CALL_PLACEHOLDER                        # BigQuery: không có input


def test_sweeper_hard_rule():
    h = {"n_tx": 60, "n_in": 50, "n_in_fail": 0, "n_in_call": 0, "call_senders": 0, "n_out": 10,
         "n_plain_in": 50, "n_sweep": 1}
    assert score_features(Features(A, "eth", code={"eth": "none"}, history=h)).hard_rule == "sweeper"   # 1/50 = 0,02
    h = dict(h, n_plain_in=100)
    assert score_features(Features(A, "eth", code={"eth": "none"}, history=h)).hard_rule is None        # 0,01


def test_pick_event_min_ts_for_new_positives():
    from address_misuse.engine.evaluate import pick_event
    txs = pd.DataFrame([_tx(b, "0x" + "1" * 40, A, 0, gas_used=25_000) for b in (5, 50)])
    assert pick_event(txs, A, "+NCD", None, 0, min_ts=10)[0] == 50
    assert pick_event(txs, A, "+NCD", None, 0, min_ts=100) is None
