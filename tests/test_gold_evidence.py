import pandas as pd

from address_misuse import gold_evidence as ge
from address_misuse import sample_gold as sg
from address_misuse.config import EIP7702_ACTIVATION_TS, NETWORKS

A = "0x" + "ab" * 20


def test_calldata_kind():
    assert ge.calldata_kind(None) is None
    assert ge.calldata_kind("0x") == "-" and ge.calldata_kind("") == "-"
    assert ge.calldata_kind("0xa9059cbb" + "00" * 64) == "call"
    assert ge.calldata_kind("0x64617461" + "3a2c" * 20) == "text"        # "data:,..." (inscription)
    assert ge.calldata_kind("0x1234") == "short"


def test_token_recipient():
    to = "11" * 20
    assert ge.token_recipient("0xa9059cbb" + "00" * 12 + to + "00" * 32) == "0x" + to
    frm = "00" * 12 + "22" * 20
    assert ge.token_recipient("0x23b872dd" + frm + "00" * 12 + to + "00" * 32) == "0x" + to
    assert ge.token_recipient("0x095ea7b3" + "00" * 64) is None
    assert ge.token_recipient("0xa9059cbb") is None and ge.token_recipient(None) is None


def test_state_at_event_rules():
    ev = {"block": 100, "index": 5}
    found = lambda b, i=None: {"status": "found", "block": b, "index": i}
    act = EIP7702_ACTIVATION_TS["eth"]
    assert ge.state_at_event("eth", "7702", act - 1, ev, None) == "none"         # trước khi EIP-7702 có hiệu lực
    assert ge.state_at_event("eth", "7702", act + 1, ev, None) == "7702"
    assert ge.state_at_event("eth", "code", 0, ev, found(99)) == "code"
    assert ge.state_at_event("eth", "code", 0, ev, found(101)) == "none"         # tạo sau tx → PCD
    assert ge.state_at_event("eth", "code", 0, ev, found(100, 4)) == "code"      # cùng block: theo vị trí
    assert ge.state_at_event("eth", "code", 0, ev, found(100, 6)) == "none"
    assert ge.state_at_event("eth", "code", 0, ev, found(100)) == "unknown"      # cùng block, thiếu vị trí
    assert ge.state_at_event("eth", "none", 0, ev, found(50)) == "destroyed"
    assert ge.state_at_event("eth", "none", 0, ev, {"status": "not_found"}) == "none"
    assert ge.state_at_event("eth", "code", 0, ev, {"status": "not_found"}) == "unknown"
    assert ge.state_at_event("eth", "code", 0, ev, None) == "unknown"            # lỗi tra cứu
    assert ge.state_at_event("op", "code", 0, ev, {"status": "no_api"}) == "unknown"
    assert ge.state_at_event("eth", None, 0, ev, found(50)) == "unknown"         # getCode lỗi


def test_xc_fields_rules():
    f = lambda ts, who="0xd": {"status": "found", "ts": ts, "creator": who}
    r = ge.xc_fields(100, ["bsc", "arb"], {"bsc": f(150), "arb": f(50, "0xa")})
    assert r["xc_timing"] == "before" and r["origin_net"] == "arb" and r["deployer"] == "0xa"
    assert ge.xc_fields(100, ["bsc"], {"bsc": f(100)})["xc_timing"] == "after"      # cùng giây: không tính là trước
    assert ge.xc_fields(100, ["bsc", "op"], {"bsc": f(150), "op": {"status": "no_api"}})["xc_timing"] == "unknown"
    assert ge.xc_fields(100, ["bsc", "op"], {"bsc": f(50), "op": {"status": "no_api"}})["xc_timing"] == "before"
    r = ge.xc_fields(100, ["op"], {})
    assert r["xc_timing"] == "unknown" and r["origin_net"] is None and r["xc_net_link"] == "op"
    assert ge.xc_fields(10, ["eth"], {"eth": f(0)})["xc_timing"] == "before"        # genesis/predeploy


def _fake_world(monkeypatch, tmp_path):
    """3 mẫu: contract tạo trước tx, contract tạo sau tx (có mạng khác), EOA không code. Không gọi mạng."""
    addrs = ["0x" + c * 40 for c in "123"]
    live = pd.DataFrame({"chain": "eth", "address": addrs})
    for n in NETWORKS:
        live[f"code_{n}"] = "none"
    live["code_eth"] = ["code", "code", "none"]
    live["code_bsc"] = ["none", "code", "none"]
    live["xc_nets"] = ["-", "bsc", "-"]
    for c in sg.LIVE_COLS:
        if c not in live:
            live[c] = "-"
    p = tmp_path / "old_items.csv"
    live.to_csv(p, index=False)
    hashes = ["0x" + c * 64 for c in "abc"]
    txs = {("eth", h): {"block": 100, "index": 1, "input": "0xa9059cbb" + "00" * 64, "status": 1, "value": "0"}
           for h in hashes}
    cr = {("eth", addrs[0]): {"status": "found", "ts": 1, "block": 10, "index": 0, "creator": "0xc"},
          ("eth", addrs[1]): {"status": "found", "ts": 9_999, "block": 200, "index": 0, "creator": "0xc"},
          ("eth", addrs[2]): {"status": "not_found"},
          ("bsc", addrs[1]): {"status": "found", "ts": 5, "creator": "0xd"}}
    monkeypatch.setattr(ge, "fetch_event_txs", lambda pairs: txs)
    monkeypatch.setattr(ge, "fetch_creations", lambda pairs: cr)
    sample = pd.DataFrame({"item_id": ["G1", "G2", "G3"], "chain": "eth", "address": addrs, "tx_hash": hashes,
                           "at": [1_000, 1_000, 1_000]})
    return sample, str(p)


def test_main_evidence_uniform_and_blind_to_stratum(monkeypatch, tmp_path):
    sample, live_from = _fake_world(monkeypatch, tmp_path)
    a = sg.main_evidence(sample.assign(stratum=["+NCD", "-N2", "+KEY"], label=[1, 0, 1]), None, live_from)
    b = sg.main_evidence(sample.assign(stratum=["-N8", "+PCD", "-N3"], label=[0, 1, 0]), None, live_from)
    pd.testing.assert_frame_equal(a, b)                       # cột tầng / nhãn không ảnh hưởng bằng chứng
    assert list(a.columns) == sg.MAIN_COLS
    r = a.set_index("item_id")
    assert r.loc["G1", "code_at_event"] == "code" and r.loc["G1", "own_create_time"] != "-"
    assert r.loc["G2", "code_at_event"] == "none" and r.loc["G2", "own_create_time"] != "-"   # tạo sau tx (PCD)
    assert r.loc["G2", "xc_timing"] == "before" and r.loc["G2", "origin_net"] == "bsc"
    assert r.loc["G1", "xc_timing"] == "-" and r.loc["G3", "xc_timing"] == "-"
    assert r.loc["G3", "code_at_event"] == "none" and r.loc["G3", "own_create_time"] == "-"
    assert set(a.calldata_kind) == {"call"} and set(a.tx_status) == {"success"}


def test_main_items_fill_rules_depend_only_on_visible_columns():
    """Trên main_items.csv thật (nếu có): cột xc_* điền đúng khi xc_nets ≠ '-' và code_at_event ∉ {code, 7702};
    code / destroyed luôn có own_create_time. Không đọc file khoá."""
    p = sg.GOLD_DIR / "main_items.csv"
    if not p.exists():
        return
    it = pd.read_csv(p, dtype=str).fillna("-")
    if "code_at_event" not in it or "own_create_time" not in it:
        return
    rule = (it.xc_nets != "-") & ~it.code_at_event.isin(["code", "7702"])
    for c in ("xc_timing", "explorer_url_xc"):
        assert ((it[c] != "-") == rule).all(), c
    assert (it.own_create_time[it.code_at_event.isin(["code", "destroyed"])] != "-").all()
    assert set(it.code_at_event) <= {"none", "code", "destroyed", "7702", "unknown"}


def test_write_delegate_lookup_keeps_filled_cells(monkeypatch, tmp_path):
    monkeypatch.setattr(sg, "GOLD_DIR", tmp_path)
    pd.DataFrame({"chain": ["eth", "bsc"], "delegate": ["0xd1", "0xd2"], "n_items": [1, 1], "explorer_url": ["u", "v"],
                  "class_A": ["", ""], "class_B": ["unknown", ""], "final_class": ["forwarder_sweeper", "legit_wallet"],
                  "source": ["verified", "bytecode"], "note": ["n1", ""]}).to_csv(tmp_path / "delegate_lookup.csv",
                                                                                  index=False)
    items = pd.DataFrame({"item_id": ["G1", "G2", "G3", "G4"], "chain": ["eth", "eth", "bsc", "bsc"],
                          "delegate_7702": ["0xd1", "0xd1", "0xd2", "0xd3"]})
    t = sg.write_delegate_lookup(items).set_index("delegate")
    assert t.loc["0xd1", "final_class"] == "forwarder_sweeper" and t.loc["0xd1", "class_B"] == "unknown"
    assert t.loc["0xd1", "n_items"] == 2 and t.loc["0xd2", "source"] == "bytecode"
    assert t.loc["0xd3", "final_class"] == ""                  # delegate mới: dòng trống, chờ người điều phối
    assert list(t.index[:2]) == ["0xd1", "0xd2"]               # giữ thứ tự cũ


def test_calldata_len():
    assert ge.calldata_len(None) is None and ge.calldata_len("0x") == 0
    assert ge.calldata_len("0xa9059cbb" + "00" * 64) == 68
    assert ge.calldata_len("0x" + "dd" * 32) == 32


def test_creation_inside_event_tx_is_not_pcd():
    ev = {"hash": "0xabc", "block": 100, "index": 5}
    same_hash = {"status": "found", "block": 100, "index": None, "tx_hash": "0xABC"}
    same_pos = {"status": "found", "block": 100, "index": 5, "tx_hash": "0xdef"}
    for c in (same_hash, same_pos):
        assert ge.state_at_event("eth", "code", 0, ev, c) == "unknown"
        assert ge.state_at_event("eth", "none", 0, ev, c) == "unknown"


def test_parse_etherscan_creation_is_explicit():
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    ok = {"status": "1", "message": "OK", "result": [{"contractAddress": a.upper().replace("0X", "0x"), "txHash": "0x1"}]}
    assert set(ge.parse_etherscan_creation(ok, [a, b])) == {a}                 # b không có trong list = không phải contract
    assert ge.parse_etherscan_creation({"status": "0", "message": "No data found", "result": None}, [a]) == {}
    assert ge.parse_etherscan_creation({"status": "0", "message": "NOTOK", "result": "Max rate limit reached"}, [a]) is None
    assert ge.parse_etherscan_creation({"status": "1", "message": "OK", "result": "lạ"}, [a]) is None


def test_check_delegates_requires_explicit_review():
    t = pd.DataFrame({"chain": ["eth"] * 4, "delegate": ["0xd1", "0xd2", "0xd3", "0xd4"],
                      "class_A": ["ok", "", "unknown", "ok"], "class_B": ["ok", "ok", "ok", "legit_wallet"],
                      "final_class": ["forwarder_sweeper", "unknown", "forwarder_sweeper", "legit_wallet"],
                      "note": ["", "", "", ""]})
    errs = sg.check_delegates(t)
    assert not any("0xd1" in e for e in errs) and not any("0xd4" in e for e in errs)   # ok, hoặc ghi đúng lớp cuối
    assert any("0xd2" in e and "trống" in e for e in errs)                            # ô trống = chưa rà
    assert any("0xd3" in e and "note" in e for e in errs)                             # phản đối phải có note
    t.loc[2, "note"] = "bytecode giống ví hợp lệ"
    assert not any("0xd3" in e for e in sg.check_delegates(t))


def test_kappa_reports_without_delegate_decided_items(tmp_path):
    lab = lambda m: pd.DataFrame({"item_id": ["G1", "G2", "G3", "G4"], "is_misuse": m, "type": ["T5", "T1", "NONE", "T1"],
                                  "subtype": "-", "xc_chain": "-", "malicious": "-", "confidence": "high",
                                  "evidence": "tx", "note": ""})
    lab(["1", "1", "0", "1"]).to_csv(tmp_path / "a.csv", index=False)
    lab(["0", "1", "0", "1"]).to_csv(tmp_path / "b.csv", index=False)
    pd.DataFrame({"item_id": ["G1", "G2", "G3", "G4"], "code_at_event": ["7702", "none", "code", "none"],
                  "delegate_7702": ["0xd", "-", "-", "-"], "creator": "-", "deployer": "-"}).to_csv(tmp_path / "it.csv",
                                                                                                    index=False)
    out = sg.cmd_kappa(str(tmp_path / "a.csv"), str(tmp_path / "b.csv"), str(tmp_path / "it.csv"))
    assert out["is_misuse"] < 1 and out["is_misuse_no_delegate"] == 1.0          # bất đồng duy nhất ở mẫu 7702
