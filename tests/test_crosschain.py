from address_misuse import crosschain
from address_misuse.crosschain import CodeInfo, assess_call, dispatcher_selectors

# Dispatcher tối giản: PUSH1 0xe0 SHR; DUP1 PUSH4 0x7ff36ab5 EQ; ... ; PUSH32 chứa "63 a9059cbb 14" như DỮ LIỆU
DISPATCH = "0x60e01c" + "80637ff36ab514" + "61" + "0042" + "57" + "7f" + ("63a9059cbb14" + "00" * 26)
TO = "0x" + "ab" * 20
SWAP = "0x7ff36ab5" + "00" * 64


def test_dispatcher_selectors_skips_push_data():
    assert dispatcher_selectors(DISPATCH) == {"0x7ff36ab5"}


def _fake_probe(states):
    def fake(address, networks=None, timeout=8.0):
        out = {}
        for n in states:
            st = states[n]
            info = CodeInfo(n, 0)
            if st == "code":
                info.has_code, info.code_size, info.selectors = True, 100, sorted(dispatcher_selectors(DISPATCH))
            elif st == "7702":
                info.is_eip7702, info.delegate = True, "0x" + "cd" * 20
            elif st == "error":
                info.error = "timeout"
            out[n] = info
        return out
    return fake


def test_cross_chain_misalignment_is_critical(monkeypatch):
    monkeypatch.setattr(crosschain, "probe", _fake_probe({"bsc": "none", "eth": "code", "arb": "none"}))
    r = assess_call("bsc", TO, SWAP)
    assert r.verdict == "NCD_CROSS_CHAIN" and r.risk == "critical"
    assert r.other_chains_with_code == [{"network": "eth", "code_size": 100, "selector_match": True}]


def test_selector_not_in_other_contract_is_high(monkeypatch):
    monkeypatch.setattr(crosschain, "probe", _fake_probe({"bsc": "none", "eth": "code"}))
    r = assess_call("bsc", TO, "0xdeadbeef" + "00" * 32)
    assert r.verdict == "NCD_CROSS_CHAIN" and r.risk == "high"


def test_other_verdicts(monkeypatch):
    monkeypatch.setattr(crosschain, "probe", _fake_probe({"eth": "none", "bsc": "none"}))
    assert assess_call("eth", TO, SWAP).verdict == "NCD_NO_CODE_ANYWHERE"
    assert assess_call("eth", TO, "0x").verdict == "PLAIN_TRANSFER"
    assert assess_call("eth", TO, "0x" + b"hello from vietnam".hex()).verdict == "INPUT_MESSAGE"
    monkeypatch.setattr(crosschain, "probe", _fake_probe({"eth": "code", "bsc": "none"}))
    assert assess_call("eth", TO, SWAP).verdict == "CONTRACT"
    monkeypatch.setattr(crosschain, "probe", _fake_probe({"eth": "7702", "bsc": "none"}))
    assert assess_call("eth", TO, "0x").verdict == "EIP7702_DELEGATED"
    monkeypatch.setattr(crosschain, "probe", _fake_probe({"eth": "error", "bsc": "code"}))
    assert assess_call("eth", TO, SWAP).verdict == "UNKNOWN"
