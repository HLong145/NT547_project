"""D3 — Ma trận cross-chain đầy đủ cho mọi địa chỉ CA Misuse (Type 4 / S_cross-chain / RQ2).

python -m address_misuse.crosschain_matrix code        # 1. eth_getCode (batch) trên 8 mạng, có cache/resume
python -m address_misuse.crosschain_matrix origin      # 2. deployer/nonce/kiểu tạo + nonce deployer trên chain bị misuse
python -m address_misuse.crosschain_matrix build       # 3. ghép thành data/interim/crosschain_matrix.parquet + tóm tắt

Cache: data/raw/crosschain/code_<net>.jsonl, origin.jsonl (chỉ thêm dòng, chạy lại sẽ tiếp tục).

Nhãn (cột `xc_label`):
- NCD-XC   : NCD, và có contract (không phải 7702) ở ≥ 1 mạng khác.
- NCD-Other: NCD, không có contract ở mạng nào đã kiểm tra.
- PCD-XC / PCD-Other: tương tự cho PCD (hiện đã có code trên chính chain bị misuse).

Khả năng deploy lại (`redeploy`), cho địa chỉ có contract tạo bằng CREATE từ EOA ở chain khác:
- claimable  : nonce hiện tại của deployer trên chain bị misuse ≤ nonce lúc tạo → deployer vẫn có thể deploy đúng
               địa chỉ này và rút tiền kẹt (điều kiện của "CREATE trap", §4.1 paper).
- burned     : nonce đã vượt qua → không ai deploy được nữa, tiền kẹt vĩnh viễn (trừ khi đã có code).
- factory    : tạo bởi contract (CREATE2 hoặc CREATE từ factory) → cần factory + salt; ghi factory_on_misuse_chain.

Hạn chế: trạng thái HIỆN TẠI. Contract ở chain khác có thể được deploy sau thời điểm misuse; thời điểm misuse
cần giao dịch thô (ETH: Etherscan; BSC: chưa có nguồn — xem PROGRESS).
"""

import argparse
import hashlib
import json
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

import pandas as pd
import requests
from Crypto.Hash import keccak

from address_misuse.config import INTERIM_DIR, NETWORKS, RAW_DIR, SEED_DIR, rpc_url
from address_misuse.crosschain import EIP7702_PREFIX
from address_misuse.etherscan import Etherscan

XC_DIR = RAW_DIR / "crosschain"
BATCH = 100
# Mạng mà Etherscan gói miễn phí hỗ trợ (kiểm tra 2026-10-15) — dùng để lấy contract creation
ETHERSCAN_FREE = ("eth", "arb", "polygon", "sepolia")
# Binplorer (Ethplorer cho BNB Chain): getAddressInfo trả contractInfo {creatorAddress, creationTransactionHash,
# creationTimestamp}. freekey: 100 lệnh/giờ, 1.000/ngày; key cá nhân miễn phí: 10 lệnh/giây (BINPLORER_API_KEY).
BINPLORER_NETS = ("bsc",)
BINPLORER_URL = "https://api.binplorer.com/getAddressInfo/{}"
_session = requests.Session()
_session.headers.update({"Content-Type": "application/json", "User-Agent": "address-misuse-research/0.1"})


# ---------------------------------------------------------------- tiện ích

def keccak256(b: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(b)
    return k.digest()


def _rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    ln = len(b).to_bytes((len(b).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(ln)]) + ln + b


def create_address(deployer: str, nonce: int) -> str:
    """Địa chỉ contract của CREATE: keccak256(rlp([deployer, nonce]))[12:]."""
    payload = _rlp_bytes(bytes.fromhex(deployer[2:])) + _rlp_bytes(nonce.to_bytes((nonce.bit_length() + 7) // 8, "big"))
    body = bytes([0xC0 + len(payload)]) + payload            # payload luôn ≤ 55 byte (21 + ≤ 9)
    return "0x" + keccak256(body)[12:].hex()


NONCE_SEARCH = 200_000                                       # ~6 µs/nonce → tối đa ~1 s mỗi địa chỉ


def _find_create_nonce(deployer: str, address: str, limit: int = NONCE_SEARCH) -> int | None:
    """Nonce n sao cho create_address(deployer, n) == address, hoặc None nếu không có trong [0, limit)."""
    address = address.lower()
    for n in range(limit):
        if create_address(deployer, n) == address:
            return n
    return None


def _find_create_nonce_pair(pair: tuple[str, str]) -> int | None:
    return _find_create_nonce(*pair)


def rpc_batch(network: str, calls: list[tuple[str, list]], timeout: float = 30, retries: int = 5) -> list:
    """JSON-RPC batch; trả về danh sách result theo đúng thứ tự (None nếu phần tử vẫn lỗi sau `retries` lần).

    Mỗi lần thử lại chỉ gửi các phần tử còn lỗi, chờ lùi dần 2/4/8/16 s (publicnode giới hạn theo IP cho mọi
    chain: HTTP 429 hoặc lỗi -32005 cho từng phần tử). Chỉ raise khi không lấy được phần tử nào.
    """
    out = [None] * len(calls)
    todo = list(range(len(calls)))
    last = None
    for attempt in range(retries):
        body = [{"jsonrpc": "2.0", "id": i, "method": calls[i][0], "params": calls[i][1]} for i in todo]
        try:
            r = _session.post(rpc_url(network), data=json.dumps(body), timeout=timeout)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list):
                raise RuntimeError(str(data)[:200])
            for x in data:
                if "result" in x and isinstance(x.get("id"), int) and 0 <= x["id"] < len(calls):
                    out[x["id"]] = x["result"]
            todo = [i for i in todo if out[i] is None]
            if not todo:
                return out
            last = RuntimeError(f"{network}: {len(todo)}/{len(calls)} phần tử lỗi")
        except Exception as e:
            last = e
        if attempt < retries - 1:
            time.sleep(2 * 2 ** attempt)
    if len(todo) < len(calls):
        return out
    raise RuntimeError(f"{network} batch thất bại: {last!r}"[:300])


def _read_jsonl(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def targets() -> pd.DataFrame:
    """Mọi (chain, address) CA Misuse, bỏ trùng theo giá trị lớn nhất (như paper)."""
    ca = pd.read_parquet(SEED_DIR / "ca_misuse.parquet")
    return (ca.sort_values("cost_native").groupby(["chain", "address"], as_index=False).tail(1)
            [["chain", "address", "subtype", "n_tx", "n_misuse_tx", "cost_native"]].reset_index(drop=True))


# ---------------------------------------------------------------- 1. code matrix

def _code_record(addr: str, code: str | None) -> dict:
    if code is None:
        return {"a": addr, "err": 1}
    if code in ("0x", ""):
        return {"a": addr, "s": 0}
    if code.startswith(EIP7702_PREFIX):
        return {"a": addr, "s": (len(code) - 2) // 2, "d": "0x" + code[8:48]}
    return {"a": addr, "s": (len(code) - 2) // 2, "h": hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()[:16]}


def probe_network(network: str, addresses: list[str], workers: int = 2):
    path = XC_DIR / f"code_{network}.jsonl"
    done = {r["a"] for r in _read_jsonl(path) if not r.get("err")}
    todo = [a for a in addresses if a not in done]
    if not todo:
        print(f"  {network:12s} đã xong ({len(done):,})", flush=True)
        return
    lock, t0, n_done, n_err = threading.Lock(), time.time(), 0, 0
    batches = [todo[i:i + BATCH] for i in range(0, len(todo), BATCH)]

    def job(batch):
        try:
            return batch, rpc_batch(network, [("eth_getCode", [a, "latest"]) for a in batch])
        except Exception:
            return batch, [None] * len(batch)

    with path.open("a", encoding="utf-8") as f, ThreadPoolExecutor(workers) as ex:
        for batch, codes in ex.map(job, batches):
            with lock:
                for a, c in zip(batch, codes):
                    f.write(json.dumps(_code_record(a, c)) + "\n")
                    n_err += c is None
                n_done += len(batch)
                f.flush()
                if n_done % 5000 < BATCH:
                    print(f"  {network:12s} {n_done:,}/{len(todo):,} ({time.time() - t0:.0f}s, lỗi {n_err})", flush=True)
    print(f"  {network:12s} xong {n_done:,} trong {time.time() - t0:.0f}s, lỗi {n_err}", flush=True)


def cmd_code(networks: list[str]):
    XC_DIR.mkdir(parents=True, exist_ok=True)
    addrs = sorted(targets().address.unique())
    print(f"eth_getCode cho {len(addrs):,} địa chỉ trên {len(networks)} mạng (batch {BATCH}) ...", flush=True)
    with ThreadPoolExecutor(len(networks)) as ex:
        list(ex.map(lambda n: probe_network(n, addrs), networks))


def load_code(network: str) -> pd.DataFrame:
    """Bản ghi mới nhất (không lỗi) cho mỗi địa chỉ."""
    rows = [r for r in _read_jsonl(XC_DIR / f"code_{network}.jsonl") if not r.get("err")]
    df = pd.DataFrame(rows, columns=["a", "s", "h", "d"]).drop_duplicates("a", keep="last")
    state = pd.Series("none", index=df.index)
    state[df.d.notna()] = "7702"
    state[df.h.notna()] = "code"
    return pd.DataFrame({"address": df.a, f"{network}_state": state, f"{network}_size": df.s.fillna(0).astype(int),
                         f"{network}_hash": df.h})


# ---------------------------------------------------------------- 2. origin (deployer / nonce / redeploy)

def _code_matrix(networks) -> pd.DataFrame:
    m = targets()
    for n in networks:
        m = m.merge(load_code(n), on="address", how="left")
    return m


def _binplorer_creations(pairs: list[tuple[str, str]], creations: dict, f):
    """Tra contractInfo qua Binplorer, ghi vào creation.jsonl theo định dạng giống Etherscan (source=binplorer)."""
    pairs = pairs[:int(os.environ.get("BINPLORER_MAX", len(pairs)))]   # giới hạn mỗi lần chạy (freekey: ~1.000/ngày)
    if not pairs:
        return
    key = os.environ.get("BINPLORER_API_KEY") or "freekey"
    interval = 1 / float(os.environ.get("BINPLORER_RPS", 5)) if key != "freekey" else 36.0   # freekey: 100/giờ
    print(f"Binplorer: {len(pairs):,} địa chỉ ({'key riêng' if key != 'freekey' else 'freekey, ~100/giờ'})",
          flush=True)
    t0, done, waits = time.time(), 0, 0
    for net, a in pairs:
        while True:
            t = time.monotonic()
            try:
                r = _session.get(BINPLORER_URL.format(a), params={"apiKey": key}, timeout=30).json()
            except Exception as e:
                r = {"error": {"code": -1, "message": str(e)[:100]}}
            err = r.get("error")
            if not err:
                break
            if err.get("code") == 429 or err.get("code") == -1:
                waits += 1
                time.sleep(min(60 * waits, 900))                 # chờ lùi dần, tối đa 15 phút
                continue
            break                                                # lỗi khác (vd. địa chỉ không hợp lệ): bỏ qua
        waits = 0
        if err:
            print(f"  {net} {a} Binplorer lỗi: {err}", flush=True)
            continue
        ci = r.get("contractInfo") or {}
        c = {"contractCreator": (ci.get("creatorAddress") or "").lower(), "txHash": ci.get("creationTransactionHash"),
             "timestamp": str(ci["creationTimestamp"]) if ci.get("creationTimestamp") else None,
             "blockNumber": None, "contractFactory": "", "source": "binplorer"} if ci else {}
        creations[(net, a)] = c
        f.write(json.dumps({"net": net, "address": a, "creation": c}) + "\n")
        f.flush()
        done += 1
        if done % 100 == 0:
            print(f"  {net} binplorer {done:,}/{len(pairs):,} ({time.time() - t0:.0f}s)", flush=True)
        time.sleep(max(0.0, interval - (time.monotonic() - t)))


def _classify_binplorer_creators(rows: list[dict]):
    """Binplorer không có contractFactory → người tạo có code trên mạng đó thì là factory."""
    cand = [x for x in rows if (x["creation"] or {}).get("source") == "binplorer" and x["deployer"]]
    by_net: dict[str, set] = {}
    for x in cand:
        by_net.setdefault(x["net"], set()).add(x["deployer"])
    has_code = {}
    for net, ds in by_net.items():
        ds = sorted(ds)
        for i in range(0, len(ds), BATCH):
            chunk = ds[i:i + BATCH]
            res = rpc_batch(net, [("eth_getCode", [d, "latest"]) for d in chunk])
            has_code.update({(net, d): (None if v is None else v not in ("0x", "")
                                        and not v.startswith(EIP7702_PREFIX)) for d, v in zip(chunk, res)})
    for x in cand:
        code = has_code.get((x["net"], x["deployer"]))
        if code:                                                 # factory CREATE (nonce có thể đã tìm được)
            x.update(kind="factory", factory=x["deployer"], tx_from=None)
        elif x["kind"] == "create_nonce_not_found" and code is False:
            x["kind"] = "factory_unknown"                        # EOA gửi tx tới factory chưa rõ (CREATE2)


def cmd_origin(networks: list[str], creation_workers: int = 8):
    m = _code_matrix(networks)
    # mạng có contract, khác chain bị misuse
    m["xc_nets"] = m.apply(lambda r: [n for n in networks if n != r.chain and r.get(f"{n}_state") == "code"], axis=1)
    need = m[m.xc_nets.map(len) > 0]
    path = XC_DIR / "origin.jsonl"
    # dòng trước đây "no_creation_api" trên mạng nay tra được qua Binplorer → làm lại (build giữ dòng ghi sau cùng)
    have = {(r["chain"], r["address"], r["net"]) for r in _read_jsonl(path)
            if not (r["net"] in BINPLORER_NETS and r["kind"] == "no_creation_api")}

    # (a) getcontractcreation trên các mạng Etherscan miễn phí hỗ trợ — một lần cho mỗi (net, address)
    pairs = sorted({(n, r.address) for r in need.itertuples() for n in r.xc_nets if n in ETHERSCAN_FREE})
    print(f"{len(need):,} (chain, address) có contract ở mạng khác; {len(pairs):,} cặp (mạng, địa chỉ) tra được creation",
          flush=True)
    creations: dict[tuple[str, str], dict] = {}
    cache_path = XC_DIR / "creation.jsonl"
    for r in _read_jsonl(cache_path):
        creations[(r["net"], r["address"])] = r["creation"]
    todo = [p for p in pairs if p not in creations]
    # Mỗi response kèm creationBytecode (~30 KB/địa chỉ) và đường truyền tới Etherscan chậm → một lệnh có thể mất
    # ~20 s. Chạy nhiều lệnh song song (throttle chung vẫn giữ ≤ 3 lệnh/giây) và chỉ lưu keccak của init code.
    lock = threading.Lock()
    with cache_path.open("a", encoding="utf-8") as f:
        for net in ETHERSCAN_FREE:
            addrs = [a for n, a in todo if n == net]
            if not addrs:
                continue
            es = Etherscan(net)
            batches = [addrs[i:i + 5] for i in range(0, len(addrs), 5)]
            done, t0 = 0, time.time()

            def job(batch):
                try:
                    return batch, es.contract_creation(batch)
                except Exception as e:
                    return batch, e

            with ThreadPoolExecutor(creation_workers) as ex:
                for batch, got in ex.map(job, batches):
                    if isinstance(got, Exception):
                        print(f"  {net} creation lỗi: {str(got)[:120]}", flush=True)
                        continue
                    with lock:
                        for a in batch:
                            c = dict(got.get(a, {}))
                            code = c.pop("creationBytecode", None)
                            if code:
                                try:
                                    c["initcode_keccak"] = "0x" + keccak256(bytes.fromhex(code[2:])).hex()
                                except ValueError:                 # vài response arb trả chuỗi không phải hex
                                    c["initcode_keccak"] = None
                            creations[(net, a)] = c
                            f.write(json.dumps({"net": net, "address": a, "creation": c}) + "\n")
                        f.flush()
                        done += 1
                        if done % 50 == 0:
                            print(f"  {net} creation {done * 5:,}/{len(addrs):,} ({time.time() - t0:.0f}s)", flush=True)

        _binplorer_creations(sorted({(n, r.address) for r in need.itertuples() for n in r.xc_nets
                                     if n in BINPLORER_NETS and (n, r.address) not in creations
                                     and (r.chain, r.address, n) not in have}), creations, f)

    # (b) các dòng cần phân loại
    rows = []
    for r in need.itertuples():
        for net in r.xc_nets:
            if (r.chain, r.address, net) in have:
                continue
            c = creations.get((net, r.address))
            rows.append({"chain": r.chain, "address": r.address, "net": net, "creation": c})
    # (c) phân loại. Etherscan đã cho contractFactory (tạo bởi contract) và contractCreator. Với CREATE từ EOA,
    # nonce tìm được bằng cách thử create_address(creator, n) cục bộ — RPC công khai (publicnode) trả null cho
    # phần lớn tx cũ trên arb/polygon nên không dựa vào eth_getTransactionByHash nữa.
    t0 = time.time()
    eoa_pairs = sorted({((x["creation"].get("contractCreator") or "").lower(), x["address"]) for x in rows
                        if x["creation"] and str(x["creation"].get("txHash", "")).startswith("0x")
                        and not x["creation"].get("contractFactory") and x["creation"].get("contractCreator")})
    print(f"Tìm nonce CREATE cho {len(eoa_pairs):,} cặp (deployer, address) ...", flush=True)
    with ProcessPoolExecutor() as ex:
        found = dict(zip(eoa_pairs, ex.map(_find_create_nonce_pair, eoa_pairs, chunksize=64)))
    for x in rows:
        c = x["creation"] or {}
        x.update({"deployer": (c.get("contractCreator") or "").lower() or None, "create_block": c.get("blockNumber"),
                  "create_ts": c.get("timestamp"), "kind": "unknown", "create_nonce": None})
        if not c:
            x["kind"] = ("no_creation_found" if x["net"] in ETHERSCAN_FREE + BINPLORER_NETS
                         and (x["net"], x["address"]) in creations else "no_creation_api")
        elif not str(c.get("txHash", "")).startswith("0x"):
            x["kind"] = "genesis"                            # predeploy/system contract (txHash 'GENESIS_...')
        elif c.get("contractFactory"):
            x.update(kind="factory", factory=c["contractFactory"].lower(), tx_from=x["deployer"])
        else:
            nonce = found.get((x["deployer"], x["address"]))
            if nonce is not None:
                x.update(kind="eoa_create", create_nonce=nonce)
            else:
                x["kind"] = "create_nonce_not_found"         # nonce > NONCE_SEARCH hoặc CREATE2 không qua factory
    _classify_binplorer_creators(rows)
    print(f"Phân loại {len(rows):,} dòng ({time.time() - t0:.0f}s)", flush=True)
    for chain in sorted({x["chain"] for x in rows}):
        eoa = sorted({x["deployer"] for x in rows if x["chain"] == chain and x["kind"] == "eoa_create"})
        fac = sorted({x["factory"] for x in rows if x["chain"] == chain and x.get("factory")})
        nonces = {}
        for i in range(0, len(eoa), BATCH):
            chunk = eoa[i:i + BATCH]
            res = rpc_batch(chain, [("eth_getTransactionCount", [d, "latest"]) for d in chunk])
            nonces.update({d: (int(v, 16) if v else None) for d, v in zip(chunk, res)})
        fac_code = {}
        for i in range(0, len(fac), BATCH):
            chunk = fac[i:i + BATCH]
            res = rpc_batch(chain, [("eth_getCode", [f, "latest"]) for f in chunk])
            fac_code.update({f: bool(v and v != "0x") for f, v in zip(chunk, res)})
        for x in rows:
            if x["chain"] != chain:
                continue
            if x["kind"] == "eoa_create":
                x["deployer_nonce_on_misuse_chain"] = nonces.get(x["deployer"])
            if x.get("factory"):
                x["factory_on_misuse_chain"] = fac_code.get(x["factory"])
    with path.open("a", encoding="utf-8") as f:
        for x in rows:
            x.pop("tx", None)
            x.pop("creation", None)
            f.write(json.dumps(x) + "\n")
    print(f"Ghi {len(rows):,} dòng origin → {path}")


# ---------------------------------------------------------------- 3. timing

def _first_create_ts(origin: pd.DataFrame) -> pd.Series:
    """Thời điểm contract xuất hiện sớm nhất ở bất kỳ mạng khác, theo (chain, address)."""
    o = origin.dropna(subset=["create_ts"]).copy()
    o["create_ts"] = o.create_ts.astype(int)
    return o.groupby(["chain", "address"]).create_ts.min()


def cmd_timing(networks: list[str], workers: int = 8):
    """tx đầu tiên tới địa chỉ trên chain bị misuse (Etherscan txlist asc, 1 bản ghi) — chỉ cho dòng XC đã biết
    thời điểm deploy ở mạng khác. BSC không có trong gói Etherscan free nên bị bỏ qua."""
    first = _first_create_ts(pd.DataFrame(_read_jsonl(XC_DIR / "origin.jsonl")))
    path = XC_DIR / "first_tx.jsonl"
    have = {(r["chain"], r["address"]) for r in _read_jsonl(path)}
    todo = [k for k in first.index if k not in have]
    skipped = sum(c not in ETHERSCAN_FREE for c, _ in todo)
    todo = [k for k in todo if k[0] in ETHERSCAN_FREE]
    print(f"tx đầu tiên: {len(todo):,} địa chỉ cần tra, bỏ qua {skipped:,} (chain không có trong Etherscan free)",
          flush=True)
    clients = {c: Etherscan(c) for c in {c for c, _ in todo}}

    def job(k):
        chain, a = k
        try:
            data = clients[chain].call("account", "txlist", address=a, startblock=0, endblock=99_999_999,
                                       page=1, offset=1, sort="asc")
            r = (data.get("result") or [None])[0]
            return k, ({"ts": int(r["timeStamp"]), "block": int(r["blockNumber"]), "hash": r["hash"]} if r else {})
        except Exception as e:
            return k, e

    t0, done = time.time(), 0
    with path.open("a", encoding="utf-8") as f, ThreadPoolExecutor(workers) as ex:
        for (chain, a), got in ex.map(job, todo):
            done += 1
            if isinstance(got, Exception):
                print(f"  {chain} {a} lỗi: {str(got)[:100]}", flush=True)
                continue
            f.write(json.dumps({"chain": chain, "address": a, **got}) + "\n")
            if done % 250 == 0:
                f.flush()
                print(f"  {done:,}/{len(todo):,} ({time.time() - t0:.0f}s)", flush=True)


def _timing_label(first_create_ts, first_tx_ts) -> str:
    if pd.isna(first_create_ts) or pd.isna(first_tx_ts):
        return "unknown"
    return "deployed_before" if int(first_create_ts) <= int(first_tx_ts) else "deployed_after"


# ---------------------------------------------------------------- 4. build

def _redeploy(o: dict, misuse_state: str) -> str:
    if o["kind"] == "eoa_create":
        n = o.get("deployer_nonce_on_misuse_chain")
        if n is None:
            return "unknown"
        if misuse_state == "code":
            return "already_deployed"
        return "claimable" if n <= o["create_nonce"] else "burned"
    if o["kind"] == "factory":
        return "factory_present" if o.get("factory_on_misuse_chain") else "factory_absent"
    return "unknown"


def cmd_build(networks: list[str]) -> pd.DataFrame:
    m = _code_matrix(networks)
    origin = pd.DataFrame(_read_jsonl(XC_DIR / "origin.jsonl"))
    m["xc_nets"] = m.apply(lambda r: ",".join(n for n in networks if n != r.chain and r.get(f"{n}_state") == "code"),
                           axis=1)
    m["misuse_chain_state"] = m.apply(lambda r: r.get(f"{r.chain}_state"), axis=1)
    m["same_code_elsewhere"] = m.apply(lambda r: r.get(f"{r.chain}_state") == "code" and any(
        r.get(f"{n}_hash") == r.get(f"{r.chain}_hash") for n in r.xc_nets.split(",") if n), axis=1)
    m["xc_label"] = m.subtype + "-" + m.xc_nets.map(lambda s: "XC" if s else "Other")

    if not origin.empty:
        origin = origin.drop_duplicates(["chain", "address", "net"], keep="last")
        st = m.set_index(["chain", "address"]).misuse_chain_state
        origin["redeploy"] = [_redeploy(o, st.get((o["chain"], o["address"]), "none"))
                              for o in origin.to_dict("records")]
        # một nhãn cho mỗi (chain, address): ưu tiên eth rồi theo thứ tự networks
        order = {n: i for i, n in enumerate(networks)}
        origin["_o"] = origin.net.map(order)
        best = origin.sort_values("_o").drop_duplicates(["chain", "address"])
        cols = ["chain", "address", "net", "kind", "deployer", "create_block", "create_ts", "create_nonce",
                "deployer_nonce_on_misuse_chain", "factory", "factory_on_misuse_chain", "redeploy"]
        best = best.reindex(columns=cols).rename(columns={"net": "origin_net"})
        m = m.merge(best, on=["chain", "address"], how="left")
        fc = _first_create_ts(origin).rename("first_create_ts").reset_index()
        m = m.merge(fc, on=["chain", "address"], how="left")
        ft = pd.DataFrame(_read_jsonl(XC_DIR / "first_tx.jsonl"))
        if not ft.empty:
            ft = ft.drop_duplicates(["chain", "address"], keep="last").rename(
                columns={"ts": "first_tx_ts", "block": "first_tx_block", "hash": "first_tx_hash"})
            m = m.merge(ft.reindex(columns=["chain", "address", "first_tx_ts", "first_tx_block", "first_tx_hash"]),
                        on=["chain", "address"], how="left")
        else:
            m["first_tx_ts"] = None
        m["xc_timing"] = [_timing_label(c, t) for c, t in zip(m.first_create_ts, m.first_tx_ts)]
    out = INTERIM_DIR / "crosschain_matrix.parquet"
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    m.to_parquet(out, index=False)
    print(f"Ghi {out} ({len(m):,} dòng)")
    summarize(m, networks)
    return m


def summarize(m: pd.DataFrame, networks: list[str]):
    print("\nThiếu dữ liệu code theo mạng:", {n: int(m[f"{n}_state"].isna().sum()) for n in networks})
    for chain, g in m.groupby("chain"):
        print(f"\n== Misuse trên {chain}: {len(g):,} địa chỉ, tổng {g.cost_native.sum():,.1f} native")
        t = g.groupby("xc_label").agg(n=("address", "size"), loss=("cost_native", "sum"),
                                      misuse_tx=("n_misuse_tx", "sum"))
        t["% địa chỉ"] = (t.n / len(g)).map("{:.1%}".format)
        t["% loss"] = (t.loss / g.cost_native.sum()).map("{:.1%}".format)
        print(t.to_string())
        xc = g[g.xc_nets != ""]
        cnt = pd.Series([n for s in xc.xc_nets for n in s.split(",")]).value_counts()
        print("  mạng có contract:", cnt.to_dict())
        print("  trạng thái hiện tại trên chính chain bị misuse:", g.misuse_chain_state.value_counts(dropna=False).to_dict())
        if "redeploy" in g:
            r = xc.groupby(xc.redeploy.fillna("chưa tra")).agg(n=("address", "size"), loss=("cost_native", "sum"))
            print("  khả năng deploy lại (NCD/PCD-XC):\n" + r.to_string())
            print("  kiểu tạo:", xc.kind.value_counts(dropna=False).to_dict())
        if "xc_timing" in g:
            r = xc.groupby(["xc_label", "xc_timing"]).agg(n=("address", "size"), loss=("cost_native", "sum"),
                                                         misuse_tx=("n_misuse_tx", "sum"))
            print("  contract ở mạng khác có trước tx đầu tiên trên chain bị misuse không:\n" + r.to_string())
            k = xc[xc.xc_timing != "unknown"]
            if len(k):
                gap = (k.first_tx_ts.astype(float) - k.first_create_ts.astype(float)) / 86400
                print(f"  khoảng cách (ngày, tx đầu − deploy): trung vị {gap.median():.0f}, "
                      f"p10 {gap.quantile(.1):.0f}, p90 {gap.quantile(.9):.0f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["code", "origin", "timing", "build", "all"])
    ap.add_argument("--networks", default=",".join(NETWORKS))
    a = ap.parse_args()
    nets = a.networks.split(",")
    if a.step in ("code", "all"):
        cmd_code(nets)
    if a.step in ("origin", "all"):
        cmd_origin(nets)
    if a.step in ("timing", "all"):
        cmd_timing(nets)
    if a.step in ("build", "all"):
        cmd_build(nets)


if __name__ == "__main__":
    main()
