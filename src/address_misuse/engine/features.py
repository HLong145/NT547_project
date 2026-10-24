"""FeatureStore offline cho risk score (docs/RISK_SCORE.md §5).

Tra sẵn mọi đặc trưng từ dữ liệu đã có, để các hàm S_* là hàm thuần, không gọi mạng:
- code 8 mạng: `crosschain_matrix.parquet` (CA Misuse) + `engine_code.parquet` (địa chỉ khác, tạo bằng `probe()`);
  selector dispatcher từ `xc_code/<net>.parquet` (nếu có) và `engine_code.parquet`;
- thời điểm contract xuất hiện ở mạng khác, khả năng deploy lại: ma trận cross-chain;
- thời điểm contract được tạo trên chính chain: BigQuery (ETH, tạo từ EOA) + `engine_creation.parquet`;
- symexec: kết quả tác giả + chạy lại (`symexec_repro`, `engine_symexec.jsonl`), proxy → logic qua `proxy_map`;
- delegate EIP-7702: N6 (hợp lệ), danh sách đen (mặc định lấy từ dữ liệu tác giả, xem `default_malicious_delegates`);
- OSINT: tập lộ private key, tập địa chỉ ứng viên trong code công khai;
- lịch sử giao dịch trước thời điểm `at`: ETH từ BigQuery `bq_txs.parquet`; địa chỉ ngoài BigQuery và mọi địa chỉ
  BSC dùng txlist đã cache ở `data/raw/<chain>/txlist/` (Etherscan hoặc NodeReal,
  `python -m address_misuse.engine.prepare history`).

Dùng: `fs = FeatureStore(); fs.prepare(pairs); f = fs.features(address, chain, at)`.
"""

import gzip
import json
from dataclasses import dataclass, field

import pandas as pd
import pyarrow.dataset as ds

from address_misuse.bq_fetch import targets as bq_targets
from address_misuse.config import EIP7702_ACTIVATION_TS, INTERIM_DIR, NETWORKS, RAW_DIR, SEED_DIR
from address_misuse.rules import find_sweep_pairs

NETS = tuple(NETWORKS)
MATRIX = INTERIM_DIR / "crosschain_matrix.parquet"
XC_CODE_DIR = INTERIM_DIR / "xc_code"
PROBE_CHUNK = 100
ENGINE_CODE = INTERIM_DIR / "engine_code.parquet"           # getCode bổ sung cho địa chỉ ngoài ma trận
ENGINE_CREATION = INTERIM_DIR / "engine_creation.parquet"   # thời điểm tạo contract trên chính chain
ENGINE_SYMEXEC = INTERIM_DIR / "engine_symexec.jsonl"       # symexec bổ sung (delegate 7702 mới, ...)
BQ_TXS = RAW_DIR / "eth" / "bq_txs.parquet"
HISTORY_CHAINS = ("eth", "bsc")                            # BigQuery chỉ có ETH; BSC chỉ từ txlist NodeReal
HISTORY_WINDOW = 1_000                                     # mọi mẫu: chỉ xét 1.000 tx gần nhất trước `at`
TXWIN_DIR = "txwin"                                        # data/raw/<chain>/txwin/<address>_<at>.json.gz
TX_COLS = ["block_number", "transaction_index", "block_ts", "from_address", "to_address", "value", "gas_price",
           "receipt_gas_used", "receipt_status", "receipt_contract_address"]


@dataclass
class Features:
    address: str
    chain: str
    at: int | None = None                               # unix ts; None = hôm nay
    code: dict = field(default_factory=dict)            # net -> "none" / "code" / "7702"; thiếu = chưa tra
    code_hash: dict = field(default_factory=dict)
    selectors: dict = field(default_factory=dict)       # net -> frozenset selector dispatcher
    delegate: str | None = None                         # delegate EIP-7702 trên `chain`
    own_create_ts: int | None = None                    # contract được tạo trên `chain` lúc nào (nếu biết)
    first_create_ts: int | None = None                  # contract xuất hiện sớm nhất ở mạng khác
    redeploy: str | None = None
    symexec: dict | None = None                         # {"transfer", "delegatecall", "selfdestruct"} của code trên `chain`
    delegate_symexec: dict | None = None
    delegate_benign: bool = False
    delegate_malicious: bool = False
    delegate_src: str | None = None                     # "recorded" (dữ liệu tác giả, gần `at`) hoặc "current" (getCode hôm nay)
    leaked_key: bool = False
    osint: bool | None = None                           # None = chưa tra
    history: dict | None = None                         # None = không có tx thô cho chain này

    def state(self, net: str | None = None) -> str | None:
        """Trạng thái code tại `at`. Trên chính `chain`: contract tạo sau `at` coi như chưa có, contract đã tạo trước `at`
        mà nay không còn code là đã tự huỷ (coi như có code); trên mọi mạng:
        trước khi EIP-7702 kích hoạt, EOA đang ủy quyền hôm nay khi đó vẫn là EOA thường."""
        net = net or self.chain
        s = self.code.get(net)
        if s == "7702" and self.at is not None and self.at < EIP7702_ACTIVATION_TS.get(net, 0):
            return "none"
        if net == self.chain and self.at is not None and self.own_create_ts is not None:
            if s == "code" and self.own_create_ts > self.at:
                return "none"
            if s == "none" and self.own_create_ts <= self.at:
                return "code"                   # contract đã tự huỷ sau `at` (getCode hôm nay rỗng, symexec không có)
        return s


def _str(x) -> str | None:
    return x if isinstance(x, str) else None


def _sels(x) -> frozenset | None:
    return frozenset(x.split(",")) if isinstance(x, str) and x else None


def _symexec_dict(transfer, delegatecall, selfdestruct) -> dict:
    return {"transfer": bool(transfer), "delegatecall": bool(delegatecall),
            "selfdestruct": None if pd.isna(selfdestruct) else bool(selfdestruct)}


def load_symexec() -> dict[tuple[str, str], dict]:
    """(chain, address) -> symexec. Kết quả chạy lại (status ok) bổ sung chỗ tác giả không có."""
    out = {}
    a = pd.read_parquet(SEED_DIR / "symexec_results.parquet")
    for r in a.itertuples():
        out[(r.chain, r.address)] = _symexec_dict(r.transfer_all_eth or r.transfer_msg_value or r.transfer_input_amount,
                                                  r.delegatecall, r.self_destruct)
    rows = []
    p = INTERIM_DIR / "symexec_repro.parquet"
    if p.exists():
        rows += pd.read_parquet(p).to_dict("records")
    if ENGINE_SYMEXEC.exists():
        rows += [json.loads(line) for line in ENGINE_SYMEXEC.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in rows:
        if r.get("status") == "ok":
            out.setdefault((r["chain"], r["address"]), _symexec_dict(
                r["ours_transfer_all_eth"] or r["ours_transfer_msg_value"] or r["ours_transfer_input_amount"],
                r["ours_delegatecall"], None))
    return out


def benign_delegates() -> set[str]:
    p = INTERIM_DIR / "n6_benign_7702_delegates.parquet"
    return set(pd.read_parquet(p).query("kept").address.str.lower()) if p.exists() else set()


def default_malicious_delegates(benign: set[str]) -> set[str]:
    """Danh sách đen: delegate có đường chuyển tiền trong dữ liệu tác giả (`flag` = symexec, FINDINGS_LOG 2026-10-19)
    HỢP delegate của EOA 7702 mới (D6) thoả điều kiện ADDR của tác giả (`d6_delegates.author_rule`), trừ ví hợp lệ N6.
    Hai nguồn cùng một định nghĩa với nhãn ADDR, nên engine dùng chung một danh sách (cả `wallet.online`) thay vì mỗi
    nơi một nguồn. Danh sách **không có mốc thời gian** và dựng từ chính các delegate đã thấy ở dương (không dựng được
    chỉ từ train: EIP-7702 kích hoạt 2025-05), nên luật cứng `malicious_delegate` ≈ định nghĩa nhãn ADDR."""
    st = pd.read_parquet(SEED_DIR / "eip7702_delegate_stats.parquet")
    bad = set(st[st.flag == 1].delegate.str.lower())
    p = INTERIM_DIR / "d6_delegates.parquet"
    if p.exists():
        d = pd.read_parquet(p)
        bad |= set(d[(d.author_rule == True) & d.known_wallet.isna()].delegate.str.lower())    # noqa: E712
    return bad - benign


def txlist_frame(txs: list[dict]) -> pd.DataFrame:
    """txlist Etherscan → khung cột giống `bq_txs` (để dùng chung `history_features`)."""
    rows = [{"block_number": int(t["blockNumber"]), "transaction_index": int(t["transactionIndex"]),
             "block_ts": int(t["timeStamp"]), "from_address": (t["from"] or "").lower(),
             "to_address": (t["to"] or "").lower() or None, "value": int(t["value"]), "gas_price": int(t["gasPrice"]),
             "receipt_gas_used": int(t["gasUsed"]),
             "receipt_status": int(t["isError"] == "0" and t.get("txreceipt_status", "1") != "0"),
             "receipt_contract_address": (t.get("contractAddress") or "").lower() or None,
             "input": t.get("input") or "0x"}
            for t in txs if t["from"] != "GENESIS"]
    return pd.DataFrame(rows, columns=TX_COLS + ["input"])          # `input` chỉ có ở txlist, BigQuery không có


def txlist_path(chain: str, address: str):
    return RAW_DIR / chain / "txlist" / f"{address}.json.gz"          # cùng chỗ với reproduce_rules


def txwin_path(chain: str, address: str, at: int):
    return RAW_DIR / chain / TXWIN_DIR / f"{address}_{int(at)}.json.gz"


def load_txwin(address: str, chain: str, at: int) -> pd.DataFrame | None:
    """`HISTORY_WINDOW` tx gần nhất trước `at` (lấy riêng khi txlist đã cache bị cắt trước `at`)."""
    p = txwin_path(chain, address, at)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return txlist_frame(json.load(f)["result"])


def load_txlist(address: str, chain: str = "eth") -> pd.DataFrame | None:
    p = txlist_path(chain, address)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return txlist_frame(json.load(f)["result"])


def history_features(address: str, txs: pd.DataFrame, at: int | None = None, window: int | None = HISTORY_WINDOW) -> dict:
    """Đặc trưng lịch sử từ tx thô dạng BigQuery (không có input). Chỉ dùng tx có block_ts < at, và chỉ `window` tx
    gần nhất: cùng một cửa sổ cho dương (lịch sử đầy đủ) và âm hạ tầng (chỉ lấy được 1.000 tx trước `at`).

    receipt_gas_used == 21.000 ⇔ không có calldata (với đích không có code), nên `input` được suy ra từ gas
    để chạy lại `rules.find_sweep_pairs` đúng như trên dữ liệu Etherscan."""
    if at is not None:
        txs = txs[txs.block_ts < at]
    if window is not None and len(txs) > window:
        txs = txs.sort_values(["block_number", "transaction_index"]).tail(window)
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
        self.code = {}                                   # address -> {net: (state, hash, delegate, selectors)}
        for net in NETS:
            sels = {}
            p = XC_CODE_DIR / f"{net}.parquet"
            if p.exists():
                x = pd.read_parquet(p, columns=["address", "selectors"]).dropna()
                sels = dict(zip(x.address, x.selectors))
            for a, s, h in zip(m.address, m[f"{net}_state"], m[f"{net}_hash"]):
                if isinstance(s, str):
                    self.code.setdefault(a, {})[net] = (s, _str(h), None, _sels(sels.get(a)))
        if ENGINE_CODE.exists():
            for r in pd.read_parquet(ENGINE_CODE).itertuples():
                self.code.setdefault(r.address, {})[r.net] = (r.state, _str(r.code_hash), _str(r.delegate),
                                                              _sels(getattr(r, "selectors", None)))
        self.own_create: dict[tuple[str, str], int] = {}
        if ENGINE_CREATION.exists():
            c = pd.read_parquet(ENGINE_CREATION).dropna(subset=["create_ts"])
            self.own_create = {(ch, a): int(t) for ch, a, t in zip(c.chain, c.address, c.create_ts)}
        self.symexec = load_symexec()
        self.proxy = {(r.chain, r.proxy): r.logic for r in pd.read_parquet(SEED_DIR / "proxy_map.parquet").itertuples()}
        self.benign = benign_delegates()
        self.malicious = default_malicious_delegates(self.benign) if malicious_delegates is None else malicious_delegates
        d = pd.read_parquet(SEED_DIR / "eip7702_delegations.parquet")
        self.author_delegate = dict(zip(zip(d.chain, d.eoa), d.delegate))
        pk = pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet", columns=["chain", "address"])
        self.leaked = set(zip(pk.chain, pk.address))
        self.osint: dict[tuple[str, str], bool] = {}
        self.txs: dict[tuple[str, str], pd.DataFrame] = {}
        self.history_source: dict[tuple[str, str], str] = {}     # (chain, address) -> "bq" / "txlist"
        self._load_history = load_history
        # BigQuery chỉ chứa tx của các địa chỉ đã truy vấn (bq_fetch.targets): địa chỉ khác (router, sàn…) chỉ có
        # phần tx với địa chỉ misuse, nên không được lấy lịch sử từ đó.
        self.bq_covered = set(bq_targets().address) if BQ_TXS.exists() else set()

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
        if not self._load_history:
            return
        for c, a in sorted({k for k in pairs if k[0] in HISTORY_CHAINS and k not in self.txs and k[0] != "eth"}):
            if (tl := load_txlist(a, c)) is not None:
                self.txs[(c, a)], self.history_source[(c, a)] = tl, "txlist"
        # ETH: ưu tiên txlist (có input, cùng nguồn với mẫu âm); BigQuery chỉ dùng khi chưa có txlist, để nguồn dữ
        # liệu không trùng với nhãn (trước đây dương ETH đều lấy từ BigQuery, âm từ Etherscan).
        todo = sorted({a for c, a in pairs if c == "eth" and ("eth", a) not in self.txs})
        for a in todo:
            if (tl := load_txlist(a)) is not None:
                self.txs[("eth", a)], self.history_source[("eth", a)] = tl, "txlist"
                cr = tl.dropna(subset=["receipt_contract_address"])
                if len(cr) and (cr.receipt_contract_address == a).any():
                    self.own_create.setdefault(("eth", a), int(cr[cr.receipt_contract_address == a].block_ts.min()))
        need = [a for a in todo if a in self.bq_covered and ("eth", a) not in self.txs]
        if not need:
            return
        t = pd.DataFrame(columns=TX_COLS)
        if BQ_TXS.exists():
            f = ds.field
            t = ds.dataset(BQ_TXS).to_table(columns=TX_COLS, filter=f("to_address").isin(need)
                                            | f("from_address").isin(need)
                                            | f("receipt_contract_address").isin(need)).to_pandas()
            t = t.sort_values(["block_number", "transaction_index"])
            cr = t.dropna(subset=["receipt_contract_address"]).groupby("receipt_contract_address").block_ts.min()
            for a, ts in cr.items():
                if a in set(need):
                    self.own_create.setdefault(("eth", a), int(ts))
        for a in need:
            rows = t[(t.to_address == a) | (t.from_address == a) | (t.receipt_contract_address == a)]
            self.txs[("eth", a)], self.history_source[("eth", a)] = rows, "bq"     # 0 dòng = thật sự không có tx

    def missing_code(self, addresses) -> list[str]:
        return sorted({a.lower() for a in addresses if len(self.code.get(a.lower(), {})) < len(NETS)})

    def probe(self, addresses, workers: int = 4, force: bool = False):
        """getCode hiện tại trên 8 mạng (kèm selector dispatcher); lưu `engine_code.parquet`."""
        from concurrent.futures import ThreadPoolExecutor

        from address_misuse.crosschain import dispatcher_selectors
        from address_misuse.crosschain_matrix import _code_record, rpc_batch
        todo = sorted({a.lower() for a in addresses}) if force else self.missing_code(addresses)
        if not todo:
            return

        def one(net):
            codes = []
            for i in range(0, len(todo), PROBE_CHUNK):   # một lô lớn (~2.000 getCode) luôn timeout ở RPC công khai
                part = todo[i:i + PROBE_CHUNK]
                try:
                    codes += rpc_batch(net, [("eth_getCode", [a, "latest"]) for a in part])
                except Exception as e:                   # không im lặng: địa chỉ thiếu code → state None
                    print(f"probe {net}: lỗi RPC ({e!r:.120}), {len(part)} địa chỉ chưa có code", flush=True)
                    codes += [None] * len(part)
            rows = []
            for a, c in zip(todo, codes):
                r = _code_record(a, c)
                if r.get("err"):
                    continue
                state = "7702" if r.get("d") else "code" if r.get("h") else "none"
                sels = ",".join(sorted(dispatcher_selectors(c))) if state == "code" else None
                rows.append({"net": net, "address": a, "state": state, "code_hash": r.get("h"), "delegate": r.get("d"),
                             "selectors": sels})
            return rows

        with ThreadPoolExecutor(workers) as ex:
            new = pd.DataFrame([r for rows in ex.map(one, NETS) for r in rows])
        old = pd.read_parquet(ENGINE_CODE) if ENGINE_CODE.exists() else None
        df = pd.concat([old, new]).drop_duplicates(["net", "address"], keep="last") if old is not None else new
        df.to_parquet(ENGINE_CODE, index=False)
        for r in new.itertuples():
            self.code.setdefault(r.address, {})[r.net] = (r.state, _str(r.code_hash), _str(r.delegate),
                                                          _sels(r.selectors))

    # ------------------------------------------------------------ đặc trưng một địa chỉ

    def _symexec_of(self, chain: str, address: str) -> dict | None:
        logic = self.proxy.get((chain, address))
        return self.symexec.get((chain, logic)) if logic else self.symexec.get((chain, address))

    def features(self, address: str, chain: str, at: int | None = None) -> Features:
        a = address.lower()
        recs = self.code.get(a, {})
        f = Features(a, chain, at, code={n: r[0] for n, r in recs.items()}, code_hash={n: r[1] for n, r in recs.items()},
                     selectors={n: r[3] for n, r in recs.items() if r[3]})
        if f.code.get(chain) == "7702":
            current = recs[chain][2]
            recorded = self.author_delegate.get((chain, a))
            # Xét theo thời gian: delegate lúc tác giả thu thập gần thời điểm `at` hơn delegate hôm nay
            # (sweeper đổi delegate liên tục — FINDINGS_LOG 2026-10-22).
            f.delegate = (recorded or current) if at is not None else (current or recorded)
            f.delegate_src = "recorded" if f.delegate and f.delegate == recorded else "current" if f.delegate else None
        if (chain, a) in self.matrix.index:
            row = self.matrix.loc[(chain, a)]
            f.first_create_ts = None if pd.isna(row.first_create_ts) else int(row.first_create_ts)
            f.redeploy = row.redeploy if isinstance(row.redeploy, str) else None
        f.own_create_ts = self.own_create.get((chain, a))
        f.symexec = self._symexec_of(chain, a)
        if f.delegate:
            f.delegate_symexec = self.symexec.get((chain, f.delegate))
            f.delegate_benign = f.delegate in self.benign
            f.delegate_malicious = f.delegate in self.malicious
        f.leaked_key = (chain, a) in self.leaked
        f.osint = self.osint.get((chain, a))
        win = load_txwin(a, chain, at) if at is not None and self._load_history else None
        if win is not None:
            f.history = history_features(a, win, at)
        elif (chain, a) in self.txs:
            f.history = history_features(a, self.txs[(chain, a)], at)
        return f
