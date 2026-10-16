import json

import pytest

from address_misuse import crosschain_matrix
from address_misuse.crosschain_matrix import _code_record, _find_create_nonce, _redeploy, _timing_label, create_address, rpc_batch
from address_misuse.known_multichain import summarize_candidates

DEPLOYER = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"


def test_create_address_known_vectors():
    assert create_address(DEPLOYER, 0) == "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
    assert create_address(DEPLOYER, 1) == "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"


def test_create_address_large_nonce_is_deterministic_and_distinct():
    addrs = {create_address(DEPLOYER, n) for n in (0, 127, 128, 255, 256, 2**32)}
    assert len(addrs) == 6 and all(len(a) == 42 for a in addrs)


def test_code_record_states():
    a = "0x" + "11" * 20
    assert _code_record(a, None) == {"a": a, "err": 1}
    assert _code_record(a, "0x") == {"a": a, "s": 0}
    r = _code_record(a, "0xef0100" + "cd" * 20)
    assert r["d"] == "0x" + "cd" * 20 and "h" not in r
    r = _code_record(a, "0x6080604052")
    assert r["s"] == 5 and len(r["h"]) == 16


def test_redeploy_labels():
    eoa = {"kind": "eoa_create", "create_nonce": 5}
    assert _redeploy({**eoa, "deployer_nonce_on_misuse_chain": 3}, "none") == "claimable"
    assert _redeploy({**eoa, "deployer_nonce_on_misuse_chain": 5}, "none") == "claimable"
    assert _redeploy({**eoa, "deployer_nonce_on_misuse_chain": 6}, "none") == "burned"
    assert _redeploy({**eoa, "deployer_nonce_on_misuse_chain": 9}, "code") == "already_deployed"
    assert _redeploy({**eoa, "deployer_nonce_on_misuse_chain": None}, "none") == "unknown"
    assert _redeploy({"kind": "factory", "factory_on_misuse_chain": True}, "none") == "factory_present"
    assert _redeploy({"kind": "factory", "factory_on_misuse_chain": False}, "none") == "factory_absent"
    assert _redeploy({"kind": "no_creation_api"}, "none") == "unknown"


def test_find_create_nonce():
    assert _find_create_nonce(DEPLOYER, create_address(DEPLOYER, 300)) == 300
    assert _find_create_nonce(DEPLOYER, "0x" + "00" * 20, limit=50) is None


class _Resp:
    def __init__(self, data):
        self._d = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


def _fake_rpc(monkeypatch, replies):
    """Mỗi lần post trả phần tử kế tiếp của `replies` (hàm nhận body → list JSON-RPC response)."""
    sent = []

    def post(url, data, timeout):
        body = json.loads(data)
        sent.append([x["id"] for x in body])
        return _Resp(replies[len(sent) - 1](body))

    monkeypatch.setattr(crosschain_matrix._session, "post", post)
    monkeypatch.setattr(crosschain_matrix.time, "sleep", lambda s: None)
    return sent


def test_rpc_batch_retries_only_failed_items(monkeypatch):
    sent = _fake_rpc(monkeypatch, [
        lambda b: [{"id": 0, "result": "0x6000"}, {"id": 1, "error": {"code": -32005}}, {"id": 2, "result": "0x"}],
        lambda b: [{"id": 1, "result": "0x"}],
    ])
    assert rpc_batch("eth", [("eth_getCode", [a, "latest"]) for a in "abc"]) == ["0x6000", "0x", "0x"]
    assert sent == [[0, 1, 2], [1]]


def test_rpc_batch_partial_and_total_failure(monkeypatch):
    _fake_rpc(monkeypatch, [lambda b: [{"id": 0, "result": "0x"}]] + [lambda b: []] * 2)
    assert rpc_batch("eth", [("eth_getCode", ["a", "latest"]), ("eth_getCode", ["b", "latest"])], retries=3) \
        == ["0x", None]
    _fake_rpc(monkeypatch, [lambda b: {"error": "429"}] * 2)
    with pytest.raises(RuntimeError):
        rpc_batch("eth", [("eth_getCode", ["a", "latest"])], retries=2)


def test_n7_summarize_candidates():
    a, b = "0x" + "aa" * 20, "0x" + "bb" * 20
    same, other = _code_record(a, "0x6080"), _code_record(a, "0x6081")
    recs = {"eth": {a: same, b: _code_record(b, "0x")},
            "bsc": {a: same, b: _code_record(b, "0x6080")},
            "arb": {a: other, b: _code_record(b, None)},
            "op": {a: _code_record(a, "0xef0100" + "cd" * 20)}}
    df = summarize_candidates(recs, {a: "A", b: "B"}).set_index("name")
    assert df.loc["A", "n_networks_with_code"] == 3 and df.loc["A", "kept"]
    assert df.loc["A", "n_distinct_bytecode"] == 2 and not df.loc["A", "identical_bytecode"]
    assert df.loc["B", "networks_with_code"] == "bsc" and not df.loc["B", "kept"]
    assert df.loc["B", "errors"] == "arb,op"


def test_timing_label():
    assert _timing_label(100, 200) == "deployed_before"
    assert _timing_label("100", "100") == "deployed_before"
    assert _timing_label(300, 200) == "deployed_after"
    assert _timing_label(None, 200) == "unknown"
    assert _timing_label(100, float("nan")) == "unknown"


def test_classify_binplorer_creators(monkeypatch):
    eoa, fac, a = "0x" + "e0" * 20, "0x" + "fa" * 20, "0x" + "11" * 20
    monkeypatch.setattr(crosschain_matrix, "rpc_batch",
                        lambda net, calls: ["0x6080" if c[1][0] == fac else "0x" for c in calls])
    src = {"source": "binplorer"}
    rows = [{"net": "bsc", "address": a, "creation": src, "deployer": eoa, "kind": "eoa_create"},
            {"net": "bsc", "address": a, "creation": src, "deployer": eoa, "kind": "create_nonce_not_found"},
            {"net": "bsc", "address": a, "creation": src, "deployer": fac, "kind": "eoa_create"},
            {"net": "eth", "address": a, "creation": {}, "deployer": fac, "kind": "eoa_create"}]
    crosschain_matrix._classify_binplorer_creators(rows)
    assert [r["kind"] for r in rows] == ["eoa_create", "factory_unknown", "factory", "eoa_create"]
    assert rows[2]["factory"] == fac
