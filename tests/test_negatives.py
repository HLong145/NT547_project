import pandas as pd

from address_misuse.negatives import classify_n5, classify_n6, sample_n1


def test_sample_n1_excludes_flagged_and_dedups():
    cand = pd.DataFrame({"chain": ["eth"] * 6 + ["bsc"] * 2, "source": ["github"] * 8,
                         "address": ["0xA", "0xb", "0xb", "0xc", "0xd", "0xe", "0xf", "0x1"],
                         "n_tx": [1, 2, 2, 3, 0, 4, 5, 6], "balance_wei": ["0"] * 8})
    df = sample_n1(cand, {("eth", "0xa"), ("bsc", "0x1")}, per_chain=10)
    assert set(zip(df.chain, df.address)) == {("eth", "0xb"), ("eth", "0xc"), ("eth", "0xe"), ("bsc", "0xf")}


def test_classify_n6_requires_verified_name_and_code():
    rows = [{"address": "0x1", "expected_name": "W", "verified_name": "W", "code_eth": "code"},
            {"address": "0x2", "expected_name": "W", "verified_name": "Other", "code_eth": "code"},
            {"address": "0x3", "expected_name": "W", "verified_name": "W", "code_eth": "code"},
            {"address": "0x4", "expected_name": "W", "verified_name": "W", "code_eth": "none"}]
    df = classify_n6(rows, author_set={"0x3"})
    assert df.kept.tolist() == [True, False, True, False]           # có trong tập tác giả vẫn giữ (tập đó không phải tập độc)
    assert df.in_author_delegate_set.tolist() == [False, False, True, False]


def test_scan_rows_selector_and_readable_text():
    from address_misuse.negatives import scan_rows
    text = "0x" + "hello world".encode().hex()
    block = {"timestamp": "0x64", "number": "0x10", "transactions": [
        {"transactionIndex": "0x0", "hash": "0x1", "from": "0xAA", "to": "0xBB", "value": "0x5", "gasPrice": "0x2",
         "type": "0x2", "input": "0x7ff36ab5" + "00" * 32},
        {"transactionIndex": "0x1", "hash": "0x2", "from": "0xaa", "to": None, "value": "0x0", "gasPrice": "0x2",
         "input": text}]}
    a, b = scan_rows("eth", block)
    assert (a["selector"], a["readable"], a["input_len"], a["target"], a["from"]) == ("0x7ff36ab5", False, 36, "0xbb", "0xaa")
    assert (b["readable"], b["target"], b["block_ts"]) == (True, None, 100)


def test_n4_deposit_like_requires_forwarding_to_hub():
    from address_misuse.negatives import n4_deposit_like
    a, hub, user = "0xa", "0xh", "0xu"
    t = pd.DataFrame({"from_address": [user, a], "to_address": [a, hub], "value": [100, 98]})
    assert n4_deposit_like(t, a, hub)
    t2 = pd.DataFrame({"from_address": [user, a, a], "to_address": [a, hub, user], "value": [100, 50, 48]})
    assert not n4_deposit_like(t2, a, hub)


def test_classify_n5_keeps_recovery_names_and_author_benign():
    df = pd.DataFrame({"blockscout": ["Recovery", None, None, "PancakeRouter"],
                       "sourcify": [None, "TokenRescue", None, None],
                       "manual": [None, None, 0, 1]})
    out = classify_n5(df)
    assert out.kept.tolist() == [True, True, True, False]
    assert out.evidence.tolist() == ["verified_name", "verified_name", "author_manual", ""]
    assert out.needs_review.tolist() == [True, True, False, False]
    bad = classify_n5(pd.DataFrame({"blockscout": ["Rescue", "Retriever"], "sourcify": [None, None],
                                    "manual": [None, 1], "deployer_leaked": [True, False]}))
    assert not bad.kept.any()           # sweeper của kẻ tấn công cũng hay đặt tên "Rescue"
