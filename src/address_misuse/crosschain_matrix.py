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
    """JSON-RPC batch; trả về danh sách result theo đúng thứ tự (None nếu phần tử lỗi). Thử lại khi lỗi mạng."""
    body = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]
    last = None
    for attempt in range(retries):
        try:
            r = _session.post(rpc_url(network), data=json.dumps(body), timeout=timeout)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list):
                raise RuntimeError(str(data)[:200])
            out = [None] * len(calls)
            for x in data:
                if "result" in x:
                    out[x["id"]] = x["result"]
            if all(o is not None for o in out):
                return out
            missing = sum(o is None for o in out)
            last = RuntimeError(f"{network}: {missing}/{len(calls)} phần tử lỗi")
            if attempt == retries - 1:
                return out
        except Exception as e:
            last = e
        time.sleep(2 * (attempt + 1))
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


def cmd_origin(networks: list[str], creation_workers: int = 8):
    m = _code_matrix(networks)
    # mạng có contract, khác chain bị misuse
    m["xc_nets"] = m.apply(lambda r: [n for n in networks if n != r.chain and r.get(f"{n}_state") == "code"], axis=1)
    need = m[m.xc_nets.map(len) > 0]
    path = XC_DIR / "origin.jsonl"
    have = {(r["chain"], r["address"], r["net"]) for r in _read_jsonl(path)}

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
            x["kind"] = "no_creation_api" if x["net"] not in ETHERSCAN_FREE else "no_creation_found"
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


# ---------------------------------------------------------------- 3. build

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["code", "origin", "build", "all"])
    ap.add_argument("--networks", default=",".join(NETWORKS))
    a = ap.parse_args()
    nets = a.networks.split(",")
    if a.step in ("code", "all"):
        cmd_code(nets)
    if a.step in ("origin", "all"):
        cmd_origin(nets)
    if a.step in ("build", "all"):
        cmd_build(nets)


if __name__ == "__main__":
    main()
