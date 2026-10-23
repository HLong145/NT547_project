from address_misuse.d6_new import _ts, code_state


def test_code_state():
    assert code_state("0x") == ("none", None)
    assert code_state("0x6080604052") == ("code", None)
    assert code_state("0xef0100" + "ab" * 20) == ("7702", "0x" + "ab" * 20)
    assert code_state(None) == ("error", None)


def test_flagged_timestamp():
    txs = [{"hash": "0x1", "timeStamp": "100"}, {"hash": "0x2", "timeStamp": "200"}]
    assert _ts(txs, {"hash": "0x2"}) == 200
    assert _ts(txs, {"hash": "0x9"}) == 0
