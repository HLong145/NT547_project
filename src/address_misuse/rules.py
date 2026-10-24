"""Rule phát hiện Address Misuse — port trung thành từ misuse_analyzer/txs_analyzer.py của Shao et al.

Khác bản gốc:
- Hàm thuần (không đọc/ghi file), nhận danh sách giao dịch định dạng Etherscan `txlist`.
- Trả về **từng giao dịch** bị gắn cờ (bản gốc chỉ cộng dồn tổng) → có nhãn mức giao dịch.
- Các chỗ bản gốc có lỗi được giữ nguyên theo mặc định (`paper_compat=True`) để tái lập đúng số liệu,
  và có thể tắt để dùng bản đã sửa:
    (B1) selector 0xffffffff: điều kiện `len != 10 or len != 74` luôn đúng → mọi tx 0xffffffff bị bỏ.
         Bản sửa: chỉ giữ khi độ dài input là 10 hoặc 74 (đúng ý trong comment gốc).
    (B2) findSweepTxPair không dừng sau khi khớp → một tx nạp có thể bị cộng loss nhiều lần.
         Bản sửa: mỗi tx nạp chỉ khớp với tx rút đầu tiên.
- Ghi chú (không phải lỗi, nhưng cần biết):
    * Rule NCD dựa vào `functionName` do Etherscan gắn (từ cơ sở chữ ký hàm). Dữ liệu từ BigQuery/RPC
      không có trường này → cần nguồn chữ ký hàm riêng (vd. 4byte) mới chạy được rule giống hệt.
    * Paper ghi `tx.gas < 30000`, code dùng `gasUsed <= 30000`.
    * Với PCD, bất kỳ tx nào do chính địa chỉ gửi đi đều làm địa chỉ bị loại (giả định contract
      không tự gửi tx) — giả định này sai với EOA đã ủy quyền EIP-7702.
"""

from dataclasses import dataclass, field

from address_misuse.config import EIP7702_ACTIVATION_BLOCK

KEY_BALANCE_DUST_WEI = 100_000_000_000_000    # 0.0001 ETH/BNB: ngưỡng "dust" của ADDR
SWEEP_BLOCK_WINDOW = 2
SWEEP_GAS_RATIO = 1.61
SWEEP_DRAIN_RATIO = 0.95


@dataclass
class MisuseResult:
    address: str
    subtype: str                       # NCD / PCD / KEY / ADDR
    n_tx: int
    flagged: list = field(default_factory=list)   # dict cho từng tx (hoặc cặp tx) bị gắn cờ
    cost_wei: int = 0                  # value + phí gas của tx bị gắn cờ (định nghĩa "loss" của paper)
    value_wei: int = 0
    gas_wei: int = 0

    @property
    def n_misuse_tx(self) -> int:
        return len(self.flagged)

    def _add(self, value: int, gas: int, record: dict):
        self.value_wei += value
        self.gas_wei += gas
        self.cost_wei += value + gas
        self.flagged.append({**record, "gas_wei": gas})


def _lc(x) -> str:
    return (x or "").lower()


def _gas_fee(tx: dict) -> int:
    return int(tx["gasUsed"]) * int(tx["gasPrice"])


def is_hex_readable(hex_str: str, min_ratio: float = 0.9) -> bool:
    """Input data có phải văn bản đọc được (Input Data Message) không — giống common.is_hex_readable."""
    try:
        text = bytes.fromhex(hex_str[2:] if hex_str.startswith("0x") else hex_str).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    if not text:
        return False
    return sum(c.isprintable() for c in text) / len(text) >= min_ratio


# ---------------------------------------------------------------- CA Misuse (Algorithm 1)

def find_creation_tx(address: str, txs: list[dict]) -> dict | None:
    for tx in txs:
        if tx["to"] == "" and _lc(tx["from"]) != _lc(address):
            return tx
    return None


def detect_ca_misuse(address: str, txs: list[dict], chain: str, creation: dict | None = None,
                     is_eip7702: bool = False, paper_compat: bool = True) -> MisuseResult:
    """Rule 1 (NCD) và Rule 2 (PCD).

    creation: kết quả `getcontractcreation` (có blockNumber, timestamp) nếu có.
    is_eip7702: code hiện tại của địa chỉ bắt đầu bằng 0xef0100.
    """
    addr = _lc(address)
    in_txs_creation = find_creation_tx(addr, txs)
    if creation is None and in_txs_creation is None:
        subtype, c_block, c_ts = "NCD", 0, 0
    elif creation is not None:
        subtype, c_block, c_ts = "PCD", int(creation["blockNumber"]), int(creation["timestamp"])
    else:
        subtype, c_block, c_ts = "PCD", int(in_txs_creation["blockNumber"]), int(in_txs_creation["timeStamp"])

    res = MisuseResult(addr, subtype, len(txs))
    if not txs:
        return res

    if subtype == "NCD":
        for tx in txs:
            inp = tx["input"]
            if not (tx["isError"] == "0" and _lc(tx["to"]) == addr and _lc(tx["from"]) != addr
                    and inp != "0x" and len(tx.get("methodId", "")) == 10 and not is_hex_readable(inp)
                    and tx.get("functionName", "") != "" and int(tx["gasUsed"]) <= 30_000):
                continue
            if is_eip7702 and int(tx["blockNumber"]) > EIP7702_ACTIVATION_BLOCK[chain]:
                continue        # sau khi EOA ủy quyền 7702, input có thể là lời gọi hợp lệ
            if len(inp) == 138 and inp.startswith("0xa9059cbb"):
                to_arg, amount = inp[34:74], inp[74:]
                if f"0x{to_arg}" == addr and int(amount, 16) == int(tx["value"]):
                    continue
            if inp.startswith("0x00000000") and len(inp) != 74:
                continue        # buyAndFree22457070633(uint256) và các selector rác
            if inp.startswith("0xffffffff"):
                if paper_compat or len(inp) not in (10, 74):      # (B1)
                    continue
            res._add(int(tx["value"]), _gas_fee(tx), {"hash": tx["hash"], "block": int(tx["blockNumber"]),
                                                     "from": _lc(tx["from"]), "value_wei": int(tx["value"]),
                                                     "selector": inp[:10], "rule": "R1_NCD_CALL"})
    else:
        if any(_lc(tx["from"]) == addr for tx in txs):
            return MisuseResult(addr, subtype, len(txs))           # bản gốc: coi là dữ liệu lỗi, bỏ qua
        for tx in txs:
            inp = tx["input"]
            if (tx["isError"] == "0" and int(tx["blockNumber"]) < c_block and int(tx["timeStamp"]) < c_ts
                    and _lc(tx["to"]) == addr and inp != "0x" and len(tx.get("methodId", "")) == 10
                    and not is_hex_readable(inp)):
                res._add(int(tx["value"]), _gas_fee(tx), {"hash": tx["hash"], "block": int(tx["blockNumber"]),
                                                         "from": _lc(tx["from"]), "value_wei": int(tx["value"]),
                                                         "selector": inp[:10], "rule": "R2_PREMATURE_CALL",
                                                         "creation_block": c_block})
    return res


# ---------------------------------------------------------------- EOA Misuse (Algorithm 2, 3)

def detect_eoa_key(address: str, txs: list[dict]) -> MisuseResult:
    """KEY: địa chỉ có private key lộ → mọi giao dịch nạp vào đều tính là loss."""
    addr = _lc(address)
    res = MisuseResult(addr, "KEY", len(txs))
    for tx in txs:
        if tx["isError"] == "0" and _lc(tx["to"]) == addr and _lc(tx["from"]) != addr:
            res._add(int(tx["value"]), _gas_fee(tx), {"hash": tx["hash"], "block": int(tx["blockNumber"]),
                                                     "from": _lc(tx["from"]), "value_wei": int(tx["value"]),
                                                     "rule": "KEY_INCOMING"})
    return res


def _is_plain_in(tx, addr):
    return (tx["isError"] == "0" and _lc(tx["to"]) == addr and _lc(tx["from"]) != addr and int(tx["value"]) > 0
            and tx["input"] == "0x" and int(tx["gasUsed"]) == 21_000)


def _is_plain_out(tx, addr):
    return (tx["isError"] == "0" and _lc(tx["from"]) == addr and _lc(tx["to"]) != addr and tx["input"] == "0x"
            and int(tx["gasUsed"]) == 21_000 and int(tx["value"]) > 0)


def find_sweep_pairs(address: str, txs: list[dict], block_window: int = SWEEP_BLOCK_WINDOW,
                     gas_ratio: float = SWEEP_GAS_RATIO, drain_ratio: float = SWEEP_DRAIN_RATIO,
                     paper_compat: bool = True) -> list[tuple[dict, dict]]:
    """findSweepTxPair: tx nạp → tx rút trong ≤ block_window block, gas cao hơn gas_ratio lần, rút gần hết."""
    addr = _lc(address)
    pairs = []
    for i in range(len(txs) - 1):
        tin = txs[i]
        if not _is_plain_in(tin, addr):
            continue
        in_block, in_value, in_gp = int(tin["blockNumber"]), int(tin["value"]), int(tin["gasPrice"])
        for tout in txs[i + 1:]:
            diff = int(tout["blockNumber"]) - in_block
            if diff > block_window:
                break
            if not _is_plain_out(tout, addr):
                continue
            out_total = int(tout["value"]) + _gas_fee(tout)
            if (0 <= diff <= block_window and int(tout["gasPrice"]) > in_gp * gas_ratio
                    and drain_ratio * in_value < out_total <= in_value):
                pairs.append((tin, tout))
                if not paper_compat:                                # (B2)
                    break
    return pairs


def detect_eoa_addr(address: str, txs: list[dict], balance_wei: int, eip7702_delegate_malicious: bool | None = None,
                    require_eip7702: bool = True, paper_compat: bool = True) -> MisuseResult:
    """ADDR: phát hiện theo hành vi.

    Cấu hình mà tác giả dùng để ra số liệu paper (main.py truyền codes_dir): địa chỉ PHẢI đang ủy quyền
    EIP-7702 tới delegate độc (`require_eip7702=True`), số dư hiện tại ≤ 0.0001, và có cặp sweep.
    """
    addr = _lc(address)
    res = MisuseResult(addr, "ADDR", len(txs))
    if require_eip7702 and not eip7702_delegate_malicious:
        return res
    if balance_wei > KEY_BALANCE_DUST_WEI:
        return res
    for tin, tout in find_sweep_pairs(addr, txs, paper_compat=paper_compat):
        res._add(int(tin["value"]), _gas_fee(tin), {
            "hash": tin["hash"], "out_hash": tout["hash"], "block": int(tin["blockNumber"]),
            "block_diff": int(tout["blockNumber"]) - int(tin["blockNumber"]),
            "value_wei": int(tin["value"]), "withdrawn_wei": int(tout["value"]),
            "gas_ratio": int(tout["gasPrice"]) / max(int(tin["gasPrice"]), 1), "rule": "ADDR_SWEEP_PAIR"})
    return res
