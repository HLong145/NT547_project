"""Chuyển dữ liệu Zenodo của Shao et al. thành các bảng Parquet chuẩn hoá trong data/seed/.

Chạy:  python -m address_misuse.seed

Nguyên tắc:
- Chỉ đọc data/Address-Misuse/, không sửa gì ở đó.
- Không suy diễn hay sửa giá trị: chỉ đổi tên cột, gắn chain/source/subtype lấy từ tên file,
  chuẩn hoá địa chỉ về chữ thường. Giá trị wei giữ dạng chuỗi (vượt int64).
- Ghi MANIFEST.json gồm SHA-256 của mọi file nguồn và file đầu ra.
"""

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

from address_misuse.config import AUTHOR_EXP_DIR, CHAINS, SEED_DIR, SOURCES

ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")
WEI_COLS = ["cost_wei", "value_wei", "gas_wei"]
_source_files: dict[str, dict] = {}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _src(path: Path) -> Path:
    """Đăng ký một file nguồn vào manifest."""
    rel = path.relative_to(AUTHOR_EXP_DIR.parent).as_posix()
    if rel not in _source_files:
        _source_files[rel] = {"path": rel, "bytes": path.stat().st_size, "sha256": _sha256(path)}
    return path


def _norm_addr(s: pd.Series) -> pd.Series:
    return s.astype(str).str.strip().str.lower()


def _with_native(df: pd.DataFrame) -> pd.DataFrame:
    df["cost_native"] = df["cost_wei"].map(lambda x: int(x) / 1e18)
    return df


def _read_headerless(path: Path, names: list[str]) -> pd.DataFrame:
    return pd.read_csv(_src(path), header=None, names=names, dtype=str)


# ---------------------------------------------------------------- dataset/

def build_candidate_addresses() -> pa.Table:
    tables = []
    for source in SOURCES:
        base = AUTHOR_EXP_DIR / "dataset" / source / "addrs_info"
        for chain in CHAINS:
            for path in sorted(base.glob(f"{chain}_addr_info*.csv")):
                t = pacsv.read_csv(_src(path), convert_options=pacsv.ConvertOptions(
                    column_types={"address": pa.string(), "txslen": pa.int64(), "balance": pa.string()}))
                n = t.num_rows
                tables.append(pa.table({
                    "chain": pa.array([chain] * n),
                    "source": pa.array([source] * n),
                    "address": pc.utf8_lower(t["address"]),
                    "n_tx": t["txslen"],
                    "balance_wei": t["balance"],
                }))
    return pa.concat_tables(tables)


def build_candidate_pk_addresses() -> pd.DataFrame:
    frames = []
    for source in SOURCES:
        for chain in CHAINS:
            path = AUTHOR_EXP_DIR / "dataset" / source / "pkaddrs_info" / f"{chain}_pkaddr_info.csv"
            df = pd.read_csv(_src(path), dtype={"address": str, "txslen": "int64"})
            frames.append(pd.DataFrame({"chain": chain, "source": source,
                                        "address": _norm_addr(df["address"]), "n_tx": df["txslen"]}))
    return pd.concat(frames, ignore_index=True)


def build_github_repos() -> pd.DataFrame:
    path = _src(AUTHOR_EXP_DIR / "dataset" / "all_repos.txt")
    repos = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return pd.DataFrame({"repo": repos})


# ---------------------------------------------------------------- RQ2

def build_ca_misuse() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        for source in SOURCES:
            df = _read_headerless(AUTHOR_EXP_DIR / "RQ2" / f"{chain}_{source}" / "CAMisuse.csv",
                                  ["address", "addr_type", "n_tx", "n_misuse_tx", *WEI_COLS])
            df.insert(0, "source", source)
            df.insert(0, "chain", chain)
            # Address = chưa từng có contract (NCD); Contract = có contract, misuse xảy ra trước khi deploy (PCD)
            df.insert(3, "subtype", df.pop("addr_type").map({"Address": "NCD", "Contract": "PCD"}))
            frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["address"] = _norm_addr(df["address"])
    df[["n_tx", "n_misuse_tx"]] = df[["n_tx", "n_misuse_tx"]].astype("int64")
    return _with_native(df)


def build_eoa_misuse() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        for source in SOURCES:
            for subtype in ("KEY", "ADDR"):
                df = _read_headerless(AUTHOR_EXP_DIR / "RQ2" / f"{chain}_{source}" / f"EOAMisuse_{subtype}.csv",
                                      ["address", "n_tx", "n_misuse_tx", *WEI_COLS])
                df.insert(0, "subtype", subtype)
                df.insert(0, "source", source)
                df.insert(0, "chain", chain)
                frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["address"] = _norm_addr(df["address"])
    df[["n_tx", "n_misuse_tx"]] = df[["n_tx", "n_misuse_tx"]].astype("int64")
    return _with_native(df)


# ---------------------------------------------------------------- RQ1

def build_rq1_labels() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        for kind, misuse_type in (("CAMisuse", "CA"), ("EOAMisuse", "EOA_ADDR")):
            df = _read_headerless(AUTHOR_EXP_DIR / "RQ1" / f"{chain.upper()}_{kind}_sample.csv", ["address", "label"])
            df.insert(0, "misuse_type", misuse_type)
            df.insert(0, "chain", chain)
            frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["address"] = _norm_addr(df["address"])
    df["label"] = df["label"].astype("int8")      # 1 = TP, 0 = FP (chỉ mẫu đã bị phát hiện)
    return df


# ---------------------------------------------------------------- RQ3

def build_rq3_contract_labels() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        df = pd.read_csv(_src(AUTHOR_EXP_DIR / "RQ3" / "sample" / f"{chain.upper()}_CAMisuse_contract_sample.csv"), dtype=str)
        frames.append(pd.DataFrame({"chain": chain, "address": _norm_addr(df["PCD_address"]),
                                    "detected": df["detection_res"].astype("int8"),
                                    "manual": df["manual_res"].astype("int8")}))
    return pd.concat(frames, ignore_index=True)


def build_rq3_pcd_patterns() -> pd.DataFrame:
    section = re.compile(r"^\d+ (github|stackexchange) misuse addresses found$")
    rows = []
    for chain in CHAINS:
        path = _src(AUTHOR_EXP_DIR / "RQ3" / "attack_pattern" / f"{chain.upper()}_CAMisuse_attack.csv")
        source = None
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if m := section.match(line):
                source = m.group(1)
            elif line.startswith("0x"):
                addr, malicious, pattern = line.split(",")
                rows.append({"chain": chain, "source": source, "address": addr.lower(),
                             "malicious": malicious == "True", "pattern": None if pattern == "None" else pattern})
    return pd.DataFrame(rows)


def build_eip7702_delegate_stats() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        path = AUTHOR_EXP_DIR / "RQ3" / "attack_pattern" / f"{chain.upper()}_EOAMisuse_eip7702.csv"
        df = pd.read_csv(_src(path), header=None, skiprows=2, names=["delegate", "n_delegations", "flag"], dtype=str)
        frames.append(pd.DataFrame({"chain": chain, "delegate": _norm_addr(df["delegate"]),
                                    "n_delegations": df["n_delegations"].astype("int64"),
                                    "flag": df["flag"].astype("int8")}))   # cờ thô của tác giả (1/0/-1), chưa có giải thích
    return pd.concat(frames, ignore_index=True)


def build_eip7702_delegations() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        for fname, eoa_list in (("eip7702_map.csv", "KEY"), ("eip7702_map_addr.csv", "ADDR")):
            df = _read_headerless(AUTHOR_EXP_DIR / "RQ3" / f"{chain}_res" / fname, ["eoa", "delegate"])
            frames.append(pd.DataFrame({"chain": chain, "eoa_list": eoa_list,
                                        "eoa": _norm_addr(df["eoa"]), "delegate": _norm_addr(df["delegate"])}))
    return pd.concat(frames, ignore_index=True)


def build_proxy_map() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        df = _read_headerless(AUTHOR_EXP_DIR / "RQ3" / f"{chain}_res" / "proxy_map.csv", ["proxy", "logic"])
        frames.append(pd.DataFrame({"chain": chain, "proxy": _norm_addr(df["proxy"]), "logic": _norm_addr(df["logic"])}))
    return pd.concat(frames, ignore_index=True)


def build_clones() -> pd.DataFrame:
    frames = []
    for chain in CHAINS:
        path = _src(AUTHOR_EXP_DIR / "RQ3" / "attack_pattern" / f"{chain}_simliar.csv")   # file gốc mã hoá UTF-16
        df = pd.read_csv(io.StringIO(path.read_text(encoding="utf-16")), header=None,
                         names=["contract", "n_exact_clones"], dtype=str)
        frames.append(pd.DataFrame({"chain": chain, "contract": _norm_addr(df["contract"]),
                                    "n_exact_clones": df["n_exact_clones"].astype("int64")}))
    return pd.concat(frames, ignore_index=True)


_ZIP_KIND = {"codes": "misuse_address", "eip7702_codes": "eip7702_delegate", "proxy_codes": "proxy_logic"}


def build_bytecode_and_symexec() -> tuple[pd.DataFrame, pd.DataFrame]:
    code_rows, res_rows = [], []
    for chain in CHAINS:
        for prefix, kind in _ZIP_KIND.items():
            with zipfile.ZipFile(_src(AUTHOR_EXP_DIR / "RQ3" / f"{chain}_res" / f"{prefix}.zip")) as z:
                for name in z.namelist():
                    if name.endswith(".txt"):
                        code_rows.append({"chain": chain, "kind": kind, "address": Path(name).stem.lower(),
                                          "bytecode": z.read(name).decode("utf-8").strip()})
            with zipfile.ZipFile(_src(AUTHOR_EXP_DIR / "RQ3" / f"{chain}_res" / f"{prefix}_res.zip")) as z:
                for name in z.namelist():
                    if not name.endswith(".txt"):
                        continue
                    r = json.loads(z.read(name))
                    flag = lambda k: (r.get(k) or {}).get("valid")
                    res_rows.append({
                        "chain": chain, "kind": kind, "address": Path(name).stem.lower(),
                        "time_s": r.get("time"),
                        "delegatecall": flag("delegatecall"),
                        "delegatecall_instances": json.dumps((r.get("delegatecall") or {}).get("instances", [])),
                        "transfer_all_eth": flag("transfer_all_eth"),
                        "transfer_msg_value": flag("transfer_msg_value"),
                        "transfer_input_amount": flag("transfer_input_amount"),
                        "self_destruct": flag("self_destruct"),     # thiếu trong một số file → null
                        "push_transfer_selector": (r.get("transfer_token") or {}).get("push_0xa9059cbb"),
                    })
    return pd.DataFrame(code_rows), pd.DataFrame(res_rows)


# ---------------------------------------------------------------- main

def _write(name: str, data, outputs: list, notes: dict):
    table = data if isinstance(data, pa.Table) else pa.Table.from_pandas(data, preserve_index=False)
    out = SEED_DIR / f"{name}.parquet"
    pq.write_table(table, out, compression="zstd")
    addr_cols = [c for c in ("address", "eoa", "delegate", "proxy", "logic", "contract") if c in table.column_names]
    invalid = {c: int(pc.sum(pc.invert(pc.match_substring_regex(table[c], ADDR_RE.pattern))).as_py() or 0)
               for c in addr_cols}
    outputs.append({"table": name, "file": out.name, "rows": table.num_rows, "columns": table.column_names,
                    "invalid_addresses": invalid, "sha256": _sha256(out), "note": notes.get(name)})
    print(f"  {name:28s} {table.num_rows:>10,d} rows")


NOTES = {
    "candidate_addresses": "Địa chỉ ứng viên có giao dịch trên chain (dataset/*/addrs_info). Không có ngữ cảnh repo/file.",
    "candidate_pk_addresses": "Địa chỉ suy ra từ private key lộ (tác giả không công bố key).",
    "ca_misuse": "RQ2. subtype: NCD = gọi hàm vào địa chỉ chưa từng có code; PCD = gọi trước khi contract được deploy.",
    "eoa_misuse": "RQ2. KEY = key lộ (gồm cả dòng loss = 0); ADDR = phát hiện theo pattern sweep + EIP-7702.",
    "rq1_labels": "Nhãn tay của tác giả, CHỈ trên các ca đã bị phát hiện (1 = TP, 0 = FP) → chỉ tính được precision.",
    "rq3_contract_labels": "Mẫu contract PCD: detected = kết quả symbolic exec, manual = nhãn tay.",
    "rq3_pcd_patterns": "Phân loại contract tại địa chỉ PCD (malicious, pattern).",
    "eip7702_delegate_stats": "Contract được ủy quyền EIP-7702, số EOA ủy quyền, flag thô của tác giả (chưa rõ nghĩa: 1/0/-1).",
    "eip7702_delegations": "EOA -> delegate. eoa_list = danh sách nguồn (KEY hoặc ADDR).",
    "symexec_results": "Kết quả symbolic execution của tác giả cho từng bytecode.",
}


def main():
    SEED_DIR.mkdir(parents=True, exist_ok=True)
    outputs: list = []
    print("Building seed tables ...")
    _write("candidate_addresses", build_candidate_addresses(), outputs, NOTES)
    _write("candidate_pk_addresses", build_candidate_pk_addresses(), outputs, NOTES)
    _write("github_repos", build_github_repos(), outputs, NOTES)
    _write("ca_misuse", build_ca_misuse(), outputs, NOTES)
    _write("eoa_misuse", build_eoa_misuse(), outputs, NOTES)
    _write("rq1_labels", build_rq1_labels(), outputs, NOTES)
    _write("rq3_contract_labels", build_rq3_contract_labels(), outputs, NOTES)
    _write("rq3_pcd_patterns", build_rq3_pcd_patterns(), outputs, NOTES)
    _write("eip7702_delegate_stats", build_eip7702_delegate_stats(), outputs, NOTES)
    _write("eip7702_delegations", build_eip7702_delegations(), outputs, NOTES)
    _write("proxy_map", build_proxy_map(), outputs, NOTES)
    _write("clones", build_clones(), outputs, NOTES)
    bytecode, symexec = build_bytecode_and_symexec()
    _write("bytecode", bytecode, outputs, NOTES)
    _write("symexec_results", symexec, outputs, NOTES)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "origin": "Shao et al., USENIX Security 2026 — https://zenodo.org/records/17984167",
        "generator": "src/address_misuse/seed.py",
        "sources": sorted(_source_files.values(), key=lambda x: x["path"]),
        "outputs": outputs,
    }
    (SEED_DIR / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Done. {len(outputs)} tables, {len(_source_files)} source files -> {SEED_DIR}")


if __name__ == "__main__":
    main()
