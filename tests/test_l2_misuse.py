import json

import pytest

from address_misuse import l2_misuse as m


class _Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


def test_out_of_credits_raises_immediately_without_retry(monkeypatch):
    calls = []
    monkeypatch.setattr(m.requests, "get", lambda *a, **k: calls.append(1) or _Resp(402))
    monkeypatch.setattr(m, "BS_GAP", 0)
    with pytest.raises(m.OutOfCredits):
        m._bs_get("op", {"module": "account"})
    assert len(calls) == 1                         # 402 không thử lại: hết credit trong ngày


def test_txlist_stops_on_out_of_credits(monkeypatch, tmp_path):
    import pandas as pd
    cand = pd.DataFrame({"address": ["0xa", "0xb", "0xc"], "kind": "NCD"})
    monkeypatch.setattr(m, "candidates", lambda chain, focus="all": cand)
    monkeypatch.setattr(m, "txlist_path", lambda chain, a: tmp_path / f"{a}.json.gz")
    seen = []

    def fake(chain, a):
        seen.append(a)
        raise m.OutOfCredits("hết")

    monkeypatch.setattr(m, "fetch_txlist", fake)
    m.cmd_txlist("op", ["NCD"])
    assert seen == ["0xa"]                         # dừng ngay, không gọi tiếp các địa chỉ còn lại


def test_creation_falls_back_to_blockscout_when_rpc_lacks_old_blocks(monkeypatch, tmp_path):
    addr = "0x" + "1" * 40
    monkeypatch.setattr(m, "creation_path", lambda chain: tmp_path / "creation.jsonl")

    def bs(chain, params, retries=6):
        if params["action"] == "getcontractcreation":
            return {"result": [{"contractAddress": addr, "blockNumber": "100", "contractCreator": "0xc", "txHash": "0xt"}]}
        assert params["action"] == "getblockreward" and params["blockno"] == 100
        return {"result": {"timeStamp": 1650000000}}

    def rpc_fail(chain, calls):
        raise RuntimeError("op: 1/1 phần tử lỗi")   # block trước Bedrock: publicnode không có

    monkeypatch.setattr(m, "_bs_get", bs)
    monkeypatch.setattr(m, "rpc_batch", rpc_fail)
    m.fetch_creations("op", [addr])
    rec = json.loads((tmp_path / "creation.jsonl").read_text(encoding="utf-8"))
    assert rec["creation"]["timestamp"] == "1650000000"
