from address_misuse.rules import (detect_ca_misuse, detect_eoa_addr, detect_eoa_key, find_sweep_pairs,
                                  is_hex_readable)

A = "0x" + "aa" * 20          # địa chỉ đang xét
U = "0x" + "11" * 20          # người dùng
BOT = "0x" + "22" * 20
GWEI = 10**9
ETH = 10**18
SWAP = "0x7ff36ab5" + "00" * 64     # swapExactETHForTokens(...)


def tx(h, frm, to, value=0, inp="0x", block=100, ts=None, gas_used=21_000, gas_price=10 * GWEI, err="0", fn=None):
    return {"hash": h, "from": frm, "to": to, "value": str(value), "input": inp, "blockNumber": str(block),
            "timeStamp": str(ts if ts is not None else block * 12), "gasUsed": str(gas_used),
            "gasPrice": str(gas_price), "isError": err, "methodId": inp[:10] if inp != "0x" else "0x",
            "functionName": fn if fn is not None else ("swapExactETHForTokens(uint256,address[],address,uint256)" if inp != "0x" else "")}


def test_is_hex_readable():
    assert is_hex_readable("0x" + b"hello world".hex())
    assert not is_hex_readable(SWAP)


def test_ncd_flags_function_call_to_codeless_address():
    txs = [tx("0x1", U, A, value=ETH, inp=SWAP, gas_used=25_000),
           tx("0x2", U, A, value=ETH),                                        # chuyển tiền thường: bỏ qua
           tx("0x3", U, A, value=ETH, inp="0x" + b"gm frens".hex()),         # tin nhắn (IDM): bỏ qua
           tx("0x4", U, A, value=ETH, inp=SWAP, err="1"),                     # revert: bỏ qua
           tx("0x5", U, A, value=ETH, inp=SWAP, gas_used=40_000)]             # gasUsed > 30k: bỏ qua
    r = detect_ca_misuse(A, txs, "eth")
    assert r.subtype == "NCD"
    assert [f["hash"] for f in r.flagged] == ["0x1"]
    assert r.value_wei == ETH and r.cost_wei == ETH + 25_000 * 10 * GWEI


def test_pcd_flags_only_calls_before_deployment():
    creation = {"blockNumber": "200", "timestamp": str(200 * 12)}
    txs = [tx("0x1", U, A, value=ETH, inp=SWAP, block=150),
           tx("0x2", U, A, value=ETH, inp=SWAP, block=250)]
    r = detect_ca_misuse(A, txs, "eth", creation=creation)
    assert r.subtype == "PCD" and [f["hash"] for f in r.flagged] == ["0x1"]


def test_ffffffff_bug_is_reproduced_by_default():
    inp = "0xffffffff"
    txs = [tx("0x1", U, A, value=ETH, inp=inp)]
    assert detect_ca_misuse(A, txs, "eth").n_misuse_tx == 0                       # như bản gốc
    assert detect_ca_misuse(A, txs, "eth", paper_compat=False).n_misuse_tx == 1   # bản đã sửa


def test_key_counts_all_incoming():
    txs = [tx("0x1", U, A, value=ETH), tx("0x2", A, BOT, value=ETH // 2), tx("0x3", U, A, value=0, inp=SWAP)]
    r = detect_eoa_key(A, txs)
    assert r.n_misuse_tx == 2 and r.value_wei == ETH


def _sweep_txs(extra_out=False):
    txs = [tx("0xin", U, A, value=ETH, block=100, gas_price=10 * GWEI),
           tx("0xout", A, BOT, value=ETH - 21_000 * 20 * GWEI, block=101, gas_price=20 * GWEI)]
    if extra_out:
        txs.append(tx("0xout2", A, BOT, value=ETH - 21_000 * 30 * GWEI, block=102, gas_price=30 * GWEI))
    return txs


def test_sweep_pair_detected():
    assert [(i["hash"], o["hash"]) for i, o in find_sweep_pairs(A, _sweep_txs())] == [("0xin", "0xout")]


def test_sweep_requires_gas_war_and_window():
    slow = _sweep_txs()
    slow[1]["blockNumber"] = "103"            # 3 block sau: ngoài cửa sổ
    assert find_sweep_pairs(A, slow) == []
    cheap = _sweep_txs()
    cheap[1]["gasPrice"] = str(15 * GWEI)     # 1.5x < 1.61x
    assert find_sweep_pairs(A, cheap) == []


def test_sweep_double_count_bug_is_reproduced_by_default():
    assert len(find_sweep_pairs(A, _sweep_txs(extra_out=True))) == 2                     # bản gốc đếm 2 lần
    assert len(find_sweep_pairs(A, _sweep_txs(extra_out=True), paper_compat=False)) == 1


def test_addr_requires_malicious_7702_and_dust_balance():
    txs = _sweep_txs()
    assert detect_eoa_addr(A, txs, balance_wei=0, eip7702_delegate_malicious=False).n_misuse_tx == 0
    assert detect_eoa_addr(A, txs, balance_wei=10**15, eip7702_delegate_malicious=True).n_misuse_tx == 0
    r = detect_eoa_addr(A, txs, balance_wei=0, eip7702_delegate_malicious=True)
    assert r.n_misuse_tx == 1 and r.value_wei == ETH
    assert detect_eoa_addr(A, txs, balance_wei=0, require_eip7702=False).n_misuse_tx == 1
