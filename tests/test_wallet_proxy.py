from address_misuse.wallet.proxy import decode_raw_tx, rlp_decode, tx_from_request

TO = "627306090abab3a6e1400e9345bc60c78a8bef57"


def rlp(x) -> bytes:
    """Bộ mã hoá RLP tối thiểu cho test."""
    if isinstance(x, list):
        body = b"".join(rlp(i) for i in x)
        return (bytes([0xc0 + len(body)]) if len(body) < 56 else
                bytes([0xf7 + len(len(body).to_bytes(8, "big").lstrip(b"\0"))]) + len(body).to_bytes(8, "big").lstrip(b"\0")) + body
    if len(x) == 1 and x[0] < 0x80:
        return x
    return (bytes([0x80 + len(x)]) if len(x) < 56 else
            bytes([0xb7 + len(len(x).to_bytes(8, "big").lstrip(b"\0"))]) + len(x).to_bytes(8, "big").lstrip(b"\0")) + x


def test_rlp_roundtrip():
    v = [b"\x01", b"", [b"abc", b"x" * 60], b"\x7f"]
    assert rlp_decode(rlp(v)) == v


def test_decode_legacy_and_eip1559():
    to, val, data = bytes.fromhex(TO), (10 ** 18).to_bytes(8, "big"), bytes.fromhex("a9059cbb" + "00" * 64)
    legacy = rlp([b"\x05", b"\x01", b"\x52\x08", to, val, data, b"\x25", b"\x01", b"\x02"])
    t = decode_raw_tx("0x" + legacy.hex())
    assert (t["type"], t["to"], t["value"], t["data"][:10]) == (0, "0x" + TO, 10 ** 18, "0xa9059cbb")
    t2 = b"\x02" + rlp([b"\x01", b"\x05", b"\x01", b"\x02", b"\x52\x08", to, val, data, [], b"\x01", b"\x01", b"\x02"])
    assert decode_raw_tx("0x" + t2.hex())["to"] == "0x" + TO


def test_decode_7702_authorizations():
    dlg = bytes.fromhex("ab" * 20)
    auth = [[b"\x01", dlg, b"\x00", b"\x01", b"\x01", b"\x02"]]
    t4 = b"\x04" + rlp([b"\x01", b"\x05", b"\x01", b"\x02", b"\x52\x08", bytes.fromhex(TO), b"", b"", [], auth,
                        b"\x01", b"\x01", b"\x02"])
    assert decode_raw_tx("0x" + t4.hex())["authorizations"] == ["0x" + "ab" * 20]


def test_send_transaction_params():
    t = tx_from_request("eth_sendTransaction", [{"to": "0x" + TO, "value": "0x10", "data": "0x"}])
    assert t["value"] == 16 and t["to"] == "0x" + TO
    assert tx_from_request("eth_call", [{}]) is None


def test_api_check_request_parses_hex_value_and_handles_edge_cases():
    from address_misuse.wallet.api import check_request, parse_value

    class Store:
        def check(self, to, chain, value, data, authorizations=None):
            return {"to": to, "chain": chain, "value": value, "data": data, "auth": authorizations}

    assert parse_value("0x10") == 16 and parse_value("16") == 16 and parse_value(None) == 0
    r = check_request(Store(), {"to": "0xAB", "chain": "bsc", "value": "0xde0b6b3a7640000", "authorizations": ["0xd"]})
    assert r == {"to": "0xAB", "chain": "bsc", "value": 10**18, "data": "0x", "auth": ["0xd"]}
    assert check_request(Store(), {"to": None})["decision"] == "ok"                     # tạo contract
    assert check_request(Store(), {"to": "0xAB", "chain": "solana"})["decision"] == "unsupported"


def test_online_code_waits_for_own_chain(monkeypatch):
    """Mạng của giao dịch trả muộn hơn `timeout` vẫn được chờ; mạng khác thì bỏ."""
    import time
    from concurrent.futures import ThreadPoolExecutor

    from address_misuse.wallet.online import OnlineStore

    st = OnlineStore.__new__(OnlineStore)
    st.timeout, st.ttl, st.nets, st.cache = 0.05, 600, ("eth", "bsc"), {}
    st.pool = ThreadPoolExecutor(4)

    def slow(net, address):
        time.sleep(0.3)
        return "0xef0100" + "ab" * 20
    monkeypatch.setattr(st, "_get_code", slow)
    recs, missed, _ = st.code("0x" + "11" * 20, use_cache=False, must="eth")
    assert "eth" in recs and recs["eth"][0] == "7702" and missed == ["bsc"]
    recs, missed, _ = st.code("0x" + "22" * 20, use_cache=False)
    assert recs == {} and set(missed) == {"eth", "bsc"}
