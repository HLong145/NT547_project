import pandas as pd

from address_misuse.negatives import classify_n6, sample_n1


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
