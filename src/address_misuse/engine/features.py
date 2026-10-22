"""FeatureStore offline cho risk score (docs/RISK_SCORE.md §5).

Tra sẵn mọi đặc trưng từ dữ liệu đã có, để các hàm S_* là hàm thuần, không gọi mạng:
- code 8 mạng: `crosschain_matrix.parquet` (CA Misuse) + `engine_code.parquet` (địa chỉ khác, tạo bằng `probe()`);
- thời điểm contract xuất hiện ở mạng khác, khả năng deploy lại: ma trận cross-chain;
- symexec: kết quả tác giả + chạy lại (`symexec_repro`), proxy → logic qua `proxy_map`;
- delegate EIP-7702: N6 (hợp lệ), danh sách đen (mặc định lấy từ dữ liệu tác giả, xem `default_malicious_delegates`);
- OSINT: tập lộ private key, tập địa chỉ ứng viên trong code công khai;
- lịch sử giao dịch trước thời điểm `at`: BigQuery `bq_txs.parquet` (chỉ ETH).

Dùng: `fs = FeatureStore(); fs.prepare(pairs); f = fs.features(address, chain, at)`.
"""

from dataclasses import dataclass, field

import pandas as pd
import pyarrow.dataset as ds

from address_misuse.config import INTERIM_DIR, NETWORKS, RAW_DIR, SEED_DIR
from address_misuse.rules import find_sweep_pairs

NETS = tuple(NETWORKS)
MATRIX = INTERIM_DIR / "crosschain_matrix.parquet"
ENGINE_CODE = INTERIM_DIR / "engine_code.parquet"      # getCode bổ sung cho địa chỉ ngoài ma trận
BQ_TXS = RAW_DIR / "eth" / "bq_txs.parquet"
HISTORY_CHAINS = ("eth",)                               # chain có tx thô (D1); BSC sau khi có NodeReal txlist


@dataclass
class Features:
    address: str
    chain: str
    at: int | None = None                               # unix ts; None = hôm nay
    code: dict = field(default_factory=dict)            # net -> "none" / "code" / "7702"; thiếu = chưa tra
    code_hash: dict = field(default_factory=dict)
    delegate: str | None = None                         # delegate EIP-7702 trên `chain`
    own_create_ts: int | None = None                    # contract được tạo trên `chain` lúc nào (nếu biết)
    first_create_ts: int | None = None                  # contract xuất hiện sớm nhất ở mạng khác
    redeploy: str | None = None
    symexec: dict | None = None                         # {"transfer", "delegatecall", "selfdestruct"} của code trên `chain`
    delegate_symexec: dict | None = None
    delegate_benign: bool = False
    delegate_malicious: bool = False
    leaked_key: bool = False
    osint: bool | None = None                           # None = chưa tra
    history: dict | None = None                         # None = không có tx thô cho chain này

    def state(self, net: str | None = None) -> str | None:
        """Trạng thái code tại `at`. Trên chính `chain`: contract tạo sau `at` coi như chưa có."""
        net = net or self.chain
        s = self.code.get(net)
        if (net == self.chain and s == "code" and self.at is not None and self.own_create_ts is not None
                and self.own_create_ts > self.at):
            return "none"
        return s


def _str(x) -> str | None:
    return x if isinstance(x, str) else None


def _symexec_dict(transfer, delegatecall, selfdestruct) -> dict:
    return {"transfer": bool(transfer), "delegatecall": bool(delegatecall),
            "selfdestruct": None if pd.isna(selfdestruct) else bool(selfdestruct)}


def load_symexec() -> dict[tuple[str, str], dict]:
    """(chain, address) -> symexec. Kết quả chạy lại (status ok) ghi đè chỗ tác giả không có."""
    out = {}
    a = pd.read_parquet(SEED_DIR / "symexec_results.parquet")
    for r in a.itertuples():
        out[(r.chain, r.address)] = _symexec_dict(r.transfer_all_eth or r.transfer_msg_value or r.transfer_input_amount,
                                                  r.delegatecall, r.self_destruct)
    p = INTERIM_DIR / "symexec_repro.parquet"
    if p.exists():
        for r in pd.read_parquet(p).query("status == 'ok'").itertuples():
            out.setdefault((r.chain, r.address), _symexec_dict(
                r.ours_transfer_all_eth or r.ours_transfer_msg_value or r.ours_transfer_input_amount,
                r.ours_delegatecall, None))
    return out


def benign_delegates() -> set[str]:
    p = INTERIM_DIR / "n6_benign_7702_delegates.parquet"
    return set(pd.read_parquet(p).query("kept").address.str.lower()) if p.exists() else set()


def default_malicious_delegates(benign: set[str]) -> set[str]:
    """Danh sách đen tạm: delegate trong dữ liệu tác giả có đường chuyển tiền (flag 1), trừ ví hợp lệ N6.

    Dữ liệu tác giả chỉ chứa delegate của EOA KEY/ADDR nên đây là xấp xỉ, và **được dựng từ chính tập dương**:
    khi đánh giá phải dựng lại chỉ từ tập train (FINDINGS_LOG 2026-10-19: `flag` = symexec, không phải nhãn độc)."""
    st = pd.read_parquet(SEED_DIR / "eip7702_delegate_stats.parquet")
    return set(st[st.flag == 1].delegate.str.lower()) - benign


def history_features(address: str, txs: pd.DataFrame, at: int | None = None) -> dict:
    """Đặc trưng lịch sử từ tx thô dạng BigQuery (không có input). Chỉ dùng tx có block_ts < at.

    receipt_gas_used == 21.000 ⇔ không có calldata (với đích không có code), nên `input` được suy ra từ gas
    để chạy lại `rules.find_sweep_pairs` đúng như trên dữ liệu Etherscan."""
    if at is not None:
        txs = txs[txs.block_ts < at]
    a = address.lower()
    inc = txs[txs.to_address == a]
    ok_in = inc[inc.receipt_status == 1]
    call_in = ok_in[ok_in.receipt_gas_used > 21_000]
    plain = txs[(txs.receipt_gas_used == 21_000) & (txs.receipt_status == 1)]
    recs = [{"isError": "0", "from": r.from_address, "to": r.to_address or "", "value": str(int(r.value)),
             "input": "0x", "gasUsed": "21000", "gasPrice": str(int(r.gas_price)), "blockNumber": str(r.block_number),
             "hash": f"{r.block_number}:{r.transaction_index}"} for r in plain.itertuples()]
    n_plain_in = sum(1 for t in recs if t["to"] == a and t["from"] != a and int(t["value"]) > 0)
    return {"n_tx": len(txs), "n_in": len(inc), "n_in_fail": int((inc.receipt_status == 0).sum()),
            "n_in_call": len(call_in), "call_senders": call_in.from_address.nunique(),
            "n_out": int((txs.from_address == a).sum()), "n_plain_in": n_plain_in,
            "n_sweep": len(find_sweep_pairs(a, recs)) if n_plain_in else 0}


class FeatureStore:
    def __init__(self, malicious_delegates: set[str] | None = None, load_history: bool = True):
        m = pd.read_parquet(MATRIX)
        self.matrix = m.set_index(["chain", "address"])
        self.code = {}                                   # address -> {net: (state, hash, delegate)}
        for net in NETS:
            for a, s, h in zip(m.address, m[f"{net}_state"], m[f"{net}_hash"]):
                if isinstance(s, str):
                    self.code.setdefault(a, {})[net] = (s, _str(h), None)
        if ENGINE_CODE.exists():
            for r in pd.read_parquet(ENGINE_CODE).itertuples():
                self.code.setdefault(r.address, {})[r.net] = (r.state, _str(r.code_hash), _str(r.delegate))
        self.symexec = load_symexec()
        self.proxy = {(r.chain, r.proxy): r.logic for r in pd.read_parquet(SEED_DIR / "proxy_map.parquet").itertuples()}
        self.benign = benign_delegates()
        self.malicious = default_malicious_delegates(self.benign) if malicious_delegates is None else malicious_delegates
        d = pd.read_parquet(SEED_DIR / "eip7702_delegations.parquet")
        self.author_delegate = dict(zip(zip(d.chain, d.eoa), d.delegate))
        pk = pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet", columns=["chain", "address"])
        self.leaked = set(zip(pk.chain, pk.address))
        self.osint: dict[tuple[str, str], bool] = {}
        self.txs: dict[str, pd.DataFrame] = {}
        self.own_create: dict[str, int] = {}
        self._load_history = load_history

    # ------------------------------------------------------------ nạp theo lô

    def prepare(self, pairs: list[tuple[str, str]]):
        """Nạp OSINT và tx thô cho một lô (chain, address) — đọc mỗi file lớn một lần."""
        pairs = [(c, a.lower()) for c, a in pairs]
        need = sorted({a for c, a in pairs if (c, a) not in self.osint})
        if need:
            t = ds.dataset(SEED_DIR / "candidate_addresses.parquet").to_table(
                columns=["chain", "address"], filter=ds.field("address").isin(need))
            hit = set(zip(t["chain"].to_pylist(), t["address"].to_pylist()))
            for c, a in pairs:
                self.osint[(c, a)] = (c, a) in hit
        need = sorted({a for c, a in pairs if c in HISTORY_CHAINS and a not in self.txs})
        if need and self._load_history and BQ_TXS.exists():
            f = ds.field
            t = ds.dataset(BQ_TXS).to_table(
                columns=["block_number", "transaction_index", "block_ts", "from_address", "to_address", "value",
                         "gas_price", "receipt_gas_used", "receipt_status", "receipt_contract_address"],
                filter=f("to_address").isin(need) | f("from_address").isin(need)
                | f("receipt_contract_address").isin(need)).to_pandas()
            t = t.sort_values(["block_number", "transaction_index"])
            cr = t.dropna(subset=["receipt_contract_address"]).groupby("receipt_contract_address").block_ts.min()
            self.own_create.update({a: int(ts) for a, ts in cr.items() if a in set(need)})
            for a in need:
                self.txs[a] = t[(t.to_address == a) | (t.from_address == a) | (t.receipt_contract_address == a)]

    def missing_code(self, addresses) -> list[str]:
        return sorted({a.lower() for a in addresses if len(self.code.get(a.lower(), {})) < len(NETS)})

    def probe(self, addresses, workers: int = 4):
        """getCode hiện tại trên 8 mạng cho địa chỉ chưa có trong ma trận; lưu `engine_code.parquet`."""
        from concurrent.futures import ThreadPoolExecutor

        from address_misuse.crosschain_matrix import _code_record, rpc_batch
        todo = self.missing_code(addresses)
        if not todo:
            return

        def one(net):
            try:
                codes = rpc_batch(net, [("eth_getCode", [a, "latest"]) for a in todo])
            except Exception:
                codes = [None] * len(todo)
            rows = []
            for a, c in zip(todo, codes):
                r = _code_record(a, c)
                if r.get("err"):
                    continue
                state = "7702" if r.get("d") else "code" if r.get("h") else "none"
                rows.append({"net": net, "address": a, "state": state, "code_hash": r.get("h"), "delegate": r.get("d")})
            return rows

        with ThreadPoolExecutor(workers) as ex:
            new = pd.DataFrame([r for rows in ex.map(one, NETS) for r in rows])
        old = pd.read_parquet(ENGINE_CODE) if ENGINE_CODE.exists() else None
        df = pd.concat([old, new]).drop_duplicates(["net", "address"], keep="last") if old is not None else new
        df.to_parquet(ENGINE_CODE, index=False)
        for r in new.itertuples():
            self.code.setdefault(r.address, {})[r.net] = (r.state, _str(r.code_hash), _str(r.delegate))

    # ------------------------------------------------------------ đặc trưng một địa chỉ

    def _symexec_of(self, chain: str, address: str) -> dict | None:
        logic = self.proxy.get((chain, address))
        return self.symexec.get((chain, logic)) if logic else self.symexec.get((chain, address))

    def features(self, address: str, chain: str, at: int | None = None) -> Features:
        a = address.lower()
        recs = self.code.get(a, {})
        f = Features(a, chain, at, code={n: s for n, (s, _, _) in recs.items()},
                     code_hash={n: h for n, (_, h, _) in recs.items()})
        own = recs.get(chain)
        f.delegate = (own[2] if own and own[2] else None) or (
            self.author_delegate.get((chain, a)) if f.code.get(chain) == "7702" else None)
        if (chain, a) in self.matrix.index:
            row = self.matrix.loc[(chain, a)]
            f.first_create_ts = None if pd.isna(row.first_create_ts) else int(row.first_create_ts)
            f.redeploy = row.redeploy if isinstance(row.redeploy, str) else None
        f.own_create_ts = self.own_create.get(a) if chain in HISTORY_CHAINS else None
        f.symexec = self._symexec_of(chain, a)
        if f.delegate:
            f.delegate_symexec = self.symexec.get((chain, f.delegate))
            f.delegate_benign = f.delegate in self.benign
            f.delegate_malicious = f.delegate in self.malicious
        f.leaked_key = (chain, a) in self.leaked
        f.osint = self.osint.get((chain, a))
        if chain in HISTORY_CHAINS and a in self.txs:
            f.history = history_features(a, self.txs[a], at)
        return f
