"""Kiểm tra data/seed/ khớp với số liệu công bố trong Shao et al. (USENIX Sec '26).

Chạy `python -m address_misuse.seed` trước.
"""

import json

import pandas as pd
import pytest

from address_misuse.config import SEED_DIR


def load(name: str) -> pd.DataFrame:
    path = SEED_DIR / f"{name}.parquet"
    if not path.exists():
        pytest.skip(f"{path} chưa được tạo — chạy python -m address_misuse.seed")
    return pd.read_parquet(path)


def test_manifest_has_no_invalid_addresses():
    manifest = json.loads((SEED_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    assert len(manifest["outputs"]) == 14
    for out in manifest["outputs"]:
        assert all(v == 0 for v in out["invalid_addresses"].values()), out["table"]


def test_candidate_counts_match_section_6_1():
    c = load("candidate_addresses").groupby(["source", "chain"]).size().to_dict()
    assert c == {("github", "eth"): 5_018_957, ("github", "bsc"): 2_552_183,
                 ("stackexchange", "eth"): 6_044, ("stackexchange", "bsc"): 2_946}
    pk = load("candidate_pk_addresses").groupby(["source", "chain"]).size().to_dict()
    assert pk == {("github", "eth"): 4_189, ("github", "bsc"): 12_660,
                  ("stackexchange", "eth"): 454, ("stackexchange", "bsc"): 668}
    assert len(load("github_repos")) == 63_004


def test_ca_misuse_matches_table_3():
    ca = load("ca_misuse")
    n = ca.groupby(["chain", "source", "subtype"]).size().to_dict()
    assert n == {("eth", "github", "PCD"): 582, ("eth", "github", "NCD"): 26_908,
                 ("eth", "stackexchange", "PCD"): 31, ("eth", "stackexchange", "NCD"): 791,
                 ("bsc", "github", "PCD"): 576, ("bsc", "github", "NCD"): 21_160,
                 ("bsc", "stackexchange", "PCD"): 40, ("bsc", "stackexchange", "NCD"): 856}
    # Tổng sau khi bỏ trùng: paper lấy giá trị lớn nhất của mỗi địa chỉ giữa hai nguồn
    dedup = ca.groupby(["chain", "address"]).cost_native.max().groupby("chain")
    assert dedup.size().to_dict() == {"eth": 27_569, "bsc": 21_775}
    assert dedup.sum()["eth"] == pytest.approx(22_738.41, abs=0.01)
    assert dedup.sum()["bsc"] == pytest.approx(8_681.41, abs=0.01)


def test_eoa_misuse_matches_table_3():
    eo = load("eoa_misuse")
    pos = eo[eo.cost_native > 0]       # file KEY gồm cả địa chỉ có giao dịch nhưng loss = 0
    n = pos.groupby(["chain", "source", "subtype"]).size().to_dict()
    assert n == {("eth", "github", "KEY"): 3_765, ("eth", "github", "ADDR"): 3_852,
                 ("eth", "stackexchange", "KEY"): 375, ("eth", "stackexchange", "ADDR"): 56,
                 ("bsc", "github", "KEY"): 3_452, ("bsc", "github", "ADDR"): 4_796,
                 ("bsc", "stackexchange", "KEY"): 556, ("bsc", "stackexchange", "ADDR"): 40}
    dedup = pos.groupby(["chain", "address"]).cost_native.max().groupby("chain")
    assert dedup.size().to_dict() == {"eth": 7_699, "bsc": 8_297}
    assert dedup.sum()["eth"] == pytest.approx(104_244.53, abs=0.01)
    assert dedup.sum()["bsc"] == pytest.approx(9_045.29, abs=0.05)


def test_rq1_labels_match_table_1():
    r = load("rq1_labels").groupby(["chain", "misuse_type", "label"]).size().to_dict()
    assert r == {("eth", "CA", 1): 370, ("eth", "CA", 0): 9, ("bsc", "CA", 1): 374, ("bsc", "CA", 0): 4,
                 ("eth", "EOA_ADDR", 1): 350, ("bsc", "EOA_ADDR", 1): 356}


def test_rq3_contract_labels_match_table_4():
    r = load("rq3_contract_labels")
    cm = r.groupby(["chain", "detected", "manual"]).size().to_dict()
    # (detected, manual): (1,1)=TP (1,0)=FP (0,0)=TN (0,1)=FN
    assert {k[1:]: v for k, v in cm.items() if k[0] == "eth"} == {(1, 1): 31, (1, 0): 6, (0, 0): 44, (0, 1): 2}
    assert {k[1:]: v for k, v in cm.items() if k[0] == "bsc"} == {(1, 1): 24, (1, 0): 3, (0, 0): 51, (0, 1): 5}


def test_eip7702_delegation_counts():
    d = load("eip7702_delegations").drop_duplicates(["chain", "eoa"]).groupby("chain").size().to_dict()
    assert d == {"eth": 7_826, "bsc": 9_444}       # khớp header của *_EOAMisuse_eip7702.csv
    s = load("eip7702_delegate_stats").groupby("chain").size().to_dict()
    assert s == {"eth": 50, "bsc": 51}


def test_no_private_keys_in_seed():
    # Không có cột nào chứa chuỗi 64 hex (định dạng private key)
    for name in ("candidate_pk_addresses", "eoa_misuse", "eip7702_delegations"):
        df = load(name)
        for col in df.select_dtypes(include=["object", "string"]).columns:
            assert not df[col].astype(str).str.fullmatch(r"(0x)?[0-9a-fA-F]{64}").any(), (name, col)
