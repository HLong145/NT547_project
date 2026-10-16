from address_misuse.crosschain_matrix import _code_record, _find_create_nonce, _redeploy, _timing_label, create_address

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


def test_timing_label():
    assert _timing_label(100, 200) == "deployed_before"
    assert _timing_label("100", "100") == "deployed_before"
    assert _timing_label(300, 200) == "deployed_after"
    assert _timing_label(None, 200) == "unknown"
    assert _timing_label(100, float("nan")) == "unknown"
