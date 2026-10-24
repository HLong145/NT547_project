"""Chấm điểm online cho ví (RISK_SCORE §4): bảng tính sẵn nạp vào RAM một lần, chỉ getCode là gọi mạng.

python -X utf8 -m address_misuse.wallet.online 0x... [--chain eth] [--data 0x...] [--value 0]

- getCode trên 8 mạng song song, mỗi mạng một Session keep-alive, quá `timeout` thì bỏ mạng đó và ghi vào lý do
  (không chặn giao dịch chỉ vì RPC chậm); kết quả cache `ttl` giây theo địa chỉ.
- Tra cục bộ: OSINT (7,6M địa chỉ ứng viên, lưu dạng 8 byte đầu kiểu uint64 đã sắp xếp, ~60 MB), ví lộ key, symexec
  (tác giả + nhóm chạy lại), proxy → logic, delegate 7702 hợp lệ (N6) / có đường chuyển tiền (`d6_delegates`),
  thời điểm deploy ở mạng khác + khả năng deploy lại (ma trận cross-chain).
- Không có lịch sử giao dịch online (S_history = 0, không có luật cứng `sweeper`), nên trọng số và ngưỡng lấy từ cấu
  hình học KHÔNG có S_history (ablation "bỏ history" trong `engine_metrics.json`, Module 3) — dùng `w`/`τ` có
  history rồi bỏ S_history thì R bị kéo thấp mà ngưỡng không đổi.
"""

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, wait

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import requests

from address_misuse.config import INTERIM_DIR, SEED_DIR, rpc_url
from address_misuse.crosschain import dispatcher_selectors
from address_misuse.crosschain_matrix import _code_record
from address_misuse.engine.features import MATRIX, NETS, Features, benign_delegates, load_symexec
from address_misuse.engine.score import DEFAULT_WEIGHTS, TxContext, score_features

OSINT_CACHE = INTERIM_DIR / "wallet_osint_{}.npy"
METRICS = INTERIM_DIR / "engine_metrics.json"
D6_DELEGATES = INTERIM_DIR / "d6_delegates.parquet"
DEFAULT_TAU = {"warn": 40.0, "block": 70.0}
REQUEST_TIMEOUT = 5.0           # một request getCode; còn `timeout` của OnlineStore là thời gian ví chịu chờ


def _key(address: str) -> int:
    return int(address[2:18], 16)


def osint_index(chain: str) -> np.ndarray:
    """8 byte đầu (uint64) của địa chỉ ứng viên trên `chain`, đã sắp xếp; cache .npy để khởi động nhanh."""
    p = OSINT_CACHE.with_name(OSINT_CACHE.name.format(chain))
    if p.exists():
        return np.load(p)
    t = pq.read_table(SEED_DIR / "candidate_addresses.parquet", columns=["chain", "address"]).to_pandas()
    arr = np.unique(np.array([_key(a) for a in t.address[t.chain == chain]], dtype=np.uint64))
    np.save(p, arr)
    return arr


def learned_config(history: bool = True) -> tuple[dict, dict]:
    """(w, τ) của Module 3: cấu hình đủ 4 thành phần, hoặc cấu hình học lại không có S_history (`history=False`)."""
    if METRICS.exists():
        j = json.loads(METRICS.read_text(encoding="utf-8"))
        m = j["main"] if history else j["ablation"].get("bỏ history")
        if m:
            return {k: m["weights"].get(k, 0.0) for k in DEFAULT_WEIGHTS}, m["thresholds"]
    return DEFAULT_WEIGHTS, DEFAULT_TAU


class OnlineStore:
    def __init__(self, timeout: float = 0.3, ttl: float = 600, nets=NETS):
        self.timeout, self.ttl, self.nets = timeout, ttl, tuple(nets)
        self.sessions = {n: requests.Session() for n in self.nets}
        self.pool = ThreadPoolExecutor(3 * len(self.nets))
        self.cache: dict[str, tuple[float, dict]] = {}
        self.osint = {c: osint_index(c) for c in ("eth", "bsc")}
        pk = pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet", columns=["chain", "address"])
        self.leaked = set(zip(pk.chain, pk.address.str.lower()))
        self.symexec = load_symexec()
        self.proxy = {(r.chain, r.proxy): r.logic for r in pd.read_parquet(SEED_DIR / "proxy_map.parquet").itertuples()}
        self.benign = benign_delegates()
        self.malicious = set()
        if D6_DELEGATES.exists():                          # điều kiện của tác giả: delegate có đường chuyển tiền
            d = pd.read_parquet(D6_DELEGATES)
            self.malicious = set(d[(d.author_rule == True) & d.known_wallet.isna()].delegate)    # noqa: E712
        m = pd.read_parquet(MATRIX, columns=["chain", "address", "first_create_ts", "redeploy"])
        m = m[m.first_create_ts.notna() | m.redeploy.notna()]
        self.xc = {(c, a): (None if pd.isna(t) else int(t), r if isinstance(r, str) else None)
                   for c, a, t, r in zip(m.chain, m.address, m.first_create_ts, m.redeploy)}
        self.weights, self.tau = learned_config(history=False)

    # ------------------------------------------------------------ mạng

    def _get_code(self, net: str, address: str) -> str | None:
        r = self.sessions[net].post(rpc_url(net), json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
                                                         "params": [address, "latest"]}, timeout=REQUEST_TIMEOUT)
        return r.json().get("result")

    def warm(self):
        """Mở sẵn kết nối keep-alive tới 8 RPC (lần đầu tốn thêm bắt tay TLS ~0,5 s)."""
        wait([self.pool.submit(self._get_code, n, "0x" + "00" * 20) for n in self.nets], timeout=REQUEST_TIMEOUT)

    def code(self, address: str, use_cache: bool = True) -> tuple[dict, list[str], bool]:
        """{net: (state, hash, delegate, selectors)}, các mạng không trả kịp, có dùng cache không."""
        now = time.monotonic()
        hit = self.cache.get(address)
        if use_cache and hit and now - hit[0] < self.ttl:
            return dict(hit[1]), [n for n in self.nets if n not in hit[1]], True
        futs = {self.pool.submit(self._get_code, n, address): n for n in self.nets}
        done, _ = wait(futs, timeout=self.timeout)
        out = {}
        for fu in done:
            self._record(out, address, futs[fu], fu)
        missed = [n for n in self.nets if n not in out]
        self.cache[address] = (now, out)                  # cache cả kết quả thiếu; mạng trả muộn điền thêm sau
        late = [fu for fu in futs if fu not in done]
        for fu in late:
            fu.add_done_callback(lambda fu, n=futs[fu]: self._record(out, address, n, fu))
        return dict(out), missed, False

    @staticmethod
    def _record(out: dict, address: str, net: str, fu):
        try:
            c = fu.result()
        except Exception:
            return
        if c is None:
            return
        r = _code_record(address, c)
        st = "7702" if r.get("d") else "code" if r.get("h") else "none"
        out[net] = (st, r.get("h"), r.get("d"), frozenset(dispatcher_selectors(c)) if st == "code" else None)

    # ------------------------------------------------------------ chấm

    def features(self, address: str, chain: str, recs: dict) -> Features:
        a = address.lower()
        f = Features(a, chain, None, code={n: r[0] for n, r in recs.items()},
                     code_hash={n: r[1] for n, r in recs.items()},
                     selectors={n: r[3] for n, r in recs.items() if r[3]})
        if f.code.get(chain) == "7702":
            f.delegate = recs[chain][2]
        f.first_create_ts, f.redeploy = self.xc.get((chain, a), (None, None))
        logic = self.proxy.get((chain, a))
        f.symexec = self.symexec.get((chain, logic or a))
        if f.delegate:
            f.delegate_symexec = self.symexec.get((chain, f.delegate))
            f.delegate_benign = f.delegate in self.benign
            f.delegate_malicious = f.delegate in self.malicious
        f.leaked_key = (chain, a) in self.leaked
        idx = self.osint.get(chain)
        if idx is not None:
            k = np.uint64(_key(a))
            i = np.searchsorted(idx, k)
            f.osint = bool(i < len(idx) and idx[i] == k)
        return f

    def check(self, to: str, chain: str = "eth", value: int = 0, data: str = "0x", use_cache: bool = True,
              authorizations: list[str] | None = None) -> dict:
        """Kiểm tra một giao dịch sắp gửi. `authorizations` = delegate trong authorizationList (tx type 4)."""
        t0 = time.perf_counter()
        recs, missed, cached = self.code(to.lower(), use_cache)
        t1 = time.perf_counter()
        res = score_features(self.features(to, chain, recs), TxContext(value, data or "0x"), self.weights)
        reasons = list(res.reasons)
        hard = res.hard_rule
        for d in authorizations or []:
            if d.lower() in self.malicious:
                hard = hard or "malicious_delegate"
                reasons.insert(0, f"giao dịch ủy quyền EIP-7702 cho delegate có đường chuyển tiền đã bị dùng để rút ví ({d})")
        if missed:
            reasons.append("không kiểm tra được: " + ", ".join(missed))
        decision = "block" if hard or res.score >= self.tau["block"] else "warn" if res.score >= self.tau["warn"] else "ok"
        return {"decision": decision, "score": res.score, "components": res.components, "types": res.types,
                "hard_rule": hard, "reasons": reasons, "missed_nets": missed, "cached": cached,
                "ms_rpc": round((t1 - t0) * 1000, 2), "ms_total": round((time.perf_counter() - t0) * 1000, 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("address")
    ap.add_argument("--chain", default="eth")
    ap.add_argument("--data", default="0x")
    ap.add_argument("--value", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=0.3)
    a = ap.parse_args()
    t = time.perf_counter()
    st = OnlineStore(timeout=a.timeout)
    print(f"nạp bảng: {time.perf_counter() - t:.1f}s")
    st.warm()
    for _ in range(2):
        r = st.check(a.address, a.chain, a.value, a.data)
        print(json.dumps(r, ensure_ascii=False, default=list))


if __name__ == "__main__":
    main()
