"""D8 — đóng băng Dataset (PLAN_V2 §2.3 D8): bảng mẫu đánh giá + chia tập + QA tự động.

python -X utf8 -m address_misuse.freeze                 → data/final/dataset_v2.parquet, splits_v2/*.csv, MANIFEST_v2.json
python -X utf8 -m address_misuse.freeze qa [--version v1] → chỉ chạy QA trên file đã có (không ghi lại)

v1 (2026-10-23) giữ nguyên file cũ (`dataset_v1.parquet`, `splits/`, `MANIFEST.json`); code hiện tại chỉ dựng v2.
v2 thêm: âm N5 (contract recovery; bỏ khỏi dương PCD của tác giả những địa chỉ trùng N5), dương mới D6 (luật của
nhóm, ETH, `at` ≥ 2025-09-01), cột `label_source`, `key_value0` (KEY mà tác giả không thấy đồng nào được gửi tới,
chỉ tx value 0), `needs_review` (cần nhãn vàng D5 trước khi tin).

Nguồn: `engine_eval.parquet` (mẫu + `at` + `split` của D8) ghép lại với bảng gốc của mẫu (dương: loss của tác giả
từ `seed/`; âm theo tx N2/N3/N8: hash, value, selector). Chỉ giữ nhãn và ngữ cảnh, không giữ điểm của engine.

QA (dừng nếu lỗi, cảnh báo thì chỉ in):
- khoá: `sample_id` duy nhất; không trùng (grp, chain, address, at, tx_hash);
- địa chỉ: đúng dạng 0x + 40 hex; cột `address_checksum` (EIP-55) khớp; địa chỉ chữ hoa/thường lẫn lộn trong dữ liệu
  gốc phải đúng checksum;
- nhãn: label = 1 ⇔ grp dương; một địa chỉ không mang hai nhãn; âm không nằm trong dương của tác giả; cảnh báo nếu âm
  nằm trong tập địa chỉ suy ra từ key lộ;
- chia tập: một địa chỉ chỉ ở một tập trong train/val/test; `split` khớp `at` và mốc trong `config`;
- loss: tính lại tổng loss các dương từ `seed/` (lấy max theo (chain, address) như paper), không âm;
- bí mật: không ô văn bản nào (ngoài cột hash) là chuỗi 64 hex (có thể là private key); không có từ khoá key/secret.
"""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone

import pandas as pd
from Crypto.Hash import keccak

from address_misuse.config import FINAL_DIR, INTERIM_DIR, OUT_OF_TIME_TS, SEED_DIR, SPLIT_TEST_TS, SPLIT_VAL_TS
from address_misuse.engine.evaluate import address_samples, split_of, tx_samples

EVAL = INTERIM_DIR / "engine_eval.parquet"
VERSION = "v2"
PATHS = {"v1": (FINAL_DIR / "dataset_v1.parquet", FINAL_DIR / "splits", FINAL_DIR / "MANIFEST.json"),
         "v2": (FINAL_DIR / "dataset_v2.parquet", FINAL_DIR / "splits_v2", FINAL_DIR / "MANIFEST_v2.json")}
OUT, SPLITS, MANIFEST = PATHS[VERSION]
LABEL_SOURCE = {"author": "author_rule", "d6": "d6_rule", "neg": "negative_group"}

ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")
HEX64_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{64}")
HASH_COLS = {"tx_hash"}
NEG_DESC = {
    "-N1": "địa chỉ ứng viên ngẫu nhiên tác giả không gắn cờ",
    "-N2": "tx gọi contract bình thường (có calldata)",
    "-N3": "tx gửi văn bản (input là chữ đọc được) tới EOA",
    "-N4": "địa chỉ nạp tiền sàn giao dịch",
    "-N5": "contract recovery chính thức tại địa chỉ PCD (tác giả gắn cờ nhầm)",
    "-N6": "delegate EIP-7702 của ví hợp lệ",
    "-N7": "contract đa chuỗi hợp lệ (cùng địa chỉ trên nhiều chain)",
    "-N8": "tx ngẫu nhiên trong block (nền bình thường)",
}


def to_checksum(addr: str) -> str:
    a = addr.lower()[2:]
    k = keccak.new(digest_bits=256)
    k.update(a.encode())
    h = k.hexdigest()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def author_loss() -> pd.DataFrame:
    """Loss tác giả cho mỗi (chain, address, subtype): max giữa hai nguồn github/stackexchange (như paper)."""
    parts = [pd.read_parquet(SEED_DIR / f"{n}.parquet") for n in ("ca_misuse", "eoa_misuse")]
    d = pd.concat(parts, ignore_index=True)
    d["address"] = d.address.str.lower()
    d["cost_wei_int"] = d.cost_wei.map(int)
    d = d.sort_values("cost_wei_int").drop_duplicates(["chain", "address", "subtype"], keep="last")
    return d[["chain", "address", "subtype", "source", "n_misuse_tx", "cost_wei", "cost_native"]]


def build() -> pd.DataFrame:
    ev = pd.read_parquet(EVAL)
    adr, txs = address_samples(), tx_samples()
    src = pd.concat([adr.assign(kind="address"), txs.assign(kind="tx")], ignore_index=True)
    if len(src) != len(ev) or not (src.grp.values == ev.grp.values).all() or not (src.address.values == ev.address.values).all():
        raise SystemExit("engine_eval.parquet không khớp với bảng mẫu hiện tại — chạy lại engine.evaluate trước")
    tx_meta = []
    for grp, name in (("-N2", "n2_contract_calls"), ("-N3", "n3_text_messages"), ("-N8", "n8_normal_txs")):
        p = INTERIM_DIR / f"{name}.parquet"
        if p.exists():
            tx_meta.append(pd.read_parquet(p)[["hash", "selector", "block_number"]])
    tx_meta = pd.concat(tx_meta, ignore_index=True) if tx_meta else pd.DataFrame(columns=["hash", "selector", "block_number"])
    is_tx = (src.kind == "tx").values
    df = pd.DataFrame({
        "sample_id": [f"{VERSION}-{i:05d}" for i in range(len(ev))],
        "kind": src.kind.values,
        "grp": ev.grp.values,
        "chain": ev.chain.values,
        "address": ev.address.values,
        "label": ev.label.values,
        "label_source": ev.src.map(LABEL_SOURCE).values,
        "at": ev["at"].astype("Int64").values,
        "split": ev.split.values,
        "out_of_time": ev.out_of_time.values,
    })
    df["subtype"] = df.grp.where(df.label == 1).str[1:]
    df["address_checksum"] = df.address.map(to_checksum)
    df["at_utc"] = pd.to_datetime(df["at"], unit="s", utc=True).dt.strftime("%Y-%m-%d %H:%M:%S")
    # âm theo tx: ghép theo thứ tự (tx_samples giữ thứ tự bảng gốc)
    meta = pd.DataFrame({"tx_hash": None, "value_wei": None, "selector": None, "block_number": pd.NA}, index=df.index)
    if is_tx.any():
        tm = tx_meta.reset_index(drop=True)
        meta.loc[is_tx, "tx_hash"] = tm.hash.values
        meta.loc[is_tx, "selector"] = tm.selector.values
        meta.loc[is_tx, "block_number"] = tm.block_number.values
        meta.loc[is_tx, "value_wei"] = src.loc[is_tx, "value_wei"].map(lambda v: str(int(v))).values
    df = pd.concat([df, meta], axis=1)
    loss = author_loss()
    df = df.merge(loss.rename(columns={"source": "author_source", "cost_wei": "loss_wei", "cost_native": "loss_native"}),
                  on=["chain", "address", "subtype"], how="left")
    kg = INTERIM_DIR / "key_genesis.parquet"
    if kg.exists():
        g = pd.read_parquet(kg)
        g = g[g.genesis_wei.map(int) > 0]
        df["key_genesis_wei"] = [str(gw) if s == "KEY" and c == "eth" else None for s, c, gw in
                                 zip(df.subtype, df.chain, df.address.map(dict(zip(g.address.str.lower(), g.genesis_wei))))]
        df.loc[df.key_genesis_wei == "nan", "key_genesis_wei"] = None
    # dương D6: số liệu theo luật của nhóm (chỉ phần misuse từ 2025-09)
    d6 = pd.read_parquet(INTERIM_DIR / "d6_new_positives.parquet").query("is_new_positive")
    d6 = d6.set_index(d6.address.str.lower())
    m = (df.label_source == "d6_rule").to_numpy()
    df.loc[m, "n_misuse_tx"] = df.address[m].map(d6.n_misuse_new).values
    df.loc[m, "loss_wei"] = df.address[m].map(d6.cost_wei_new.map(lambda v: str(int(v)))).values
    df.loc[m, "loss_native"] = df.loss_wei[m].map(lambda v: int(v) / 1e18).values
    # KEY tác giả không có đồng nào được gửi tới (chỉ tx value 0, phần lớn sau EIP-7702: FINDINGS 2026-10-24)
    eoa = pd.read_parquet(SEED_DIR / "eoa_misuse.parquet").query("subtype == 'KEY'")
    v0 = eoa.assign(address=eoa.address.str.lower(), v=eoa.value_wei.map(int)).groupby(["chain", "address"]).v.max() == 0
    df["key_value0"] = [bool(v0.get((c, a), False)) if s == "KEY" and ls == "author_rule" else None
                        for c, a, s, ls in zip(df.chain, df.address, df.subtype, df.label_source)]
    n5 = pd.read_parquet(INTERIM_DIR / "n5_recovery_contracts.parquet").query("kept")
    n5_review = set(zip(n5[n5.needs_review].chain, n5[n5.needs_review].address.str.lower()))
    df["needs_review"] = (df.label_source == "d6_rule") | pd.Series(
        [g == "-N5" and (c, a) in n5_review for g, c, a in zip(df.grp, df.chain, df.address)], index=df.index)
    cols = ["sample_id", "kind", "grp", "subtype", "chain", "address", "address_checksum", "label", "label_source",
            "at", "at_utc", "split", "out_of_time", "tx_hash", "block_number", "value_wei", "selector", "author_source",
            "n_misuse_tx", "loss_wei", "loss_native", "key_value0", "needs_review"] + (
        ["key_genesis_wei"] if "key_genesis_wei" in df else [])
    return df[cols]


def qa(df: pd.DataFrame) -> tuple[list[str], list[str], dict]:
    err, warn, info = [], [], {}
    if df.sample_id.duplicated().any():
        err.append("sample_id trùng")
    k = df.duplicated(["grp", "chain", "address", "at", "tx_hash"]).sum()
    if k:
        warn.append(f"{k} mẫu trùng (grp, chain, address, at, tx_hash)")
    bad = ~df.address.str.match(ADDR_RE)
    if bad.any():
        err.append(f"{bad.sum()} địa chỉ sai dạng")
    if (df.address_checksum.str.lower() != df.address).any():
        err.append("address_checksum không khớp address")
    # địa chỉ gốc có chữ hoa/thường lẫn lộn phải đúng EIP-55
    raw = pd.concat([pd.read_parquet(SEED_DIR / f"{n}.parquet", columns=["address"]) for n in ("ca_misuse", "eoa_misuse")]).address
    mixed = raw[(raw != raw.str.lower()) & (raw != raw.str.upper().str.replace("0X", "0x"))].drop_duplicates()
    bad_cs = int((mixed != mixed.map(to_checksum)).sum())
    info["seed_mixed_case_addresses"], info["seed_bad_checksum"] = int(len(mixed)), bad_cs
    if bad_cs:
        err.append(f"{bad_cs} địa chỉ gốc sai checksum EIP-55")
    if ((df.label == 1) != df.grp.str.startswith("+")).any():
        err.append("label không khớp grp")
    n_lab = df.groupby(["chain", "address"]).label.nunique()
    if (n_lab > 1).any():
        err.append(f"{(n_lab > 1).sum()} địa chỉ mang cả hai nhãn")
    loss = author_loss()
    pos_set = set(zip(loss.chain, loss.address))
    neg = df[df.label == 0]
    is_leak = pd.Series([(c, a) in pos_set for c, a in zip(neg.chain, neg.address)], index=neg.index, dtype=bool)
    info["n5_flagged_by_author"] = int((is_leak & (neg.grp == "-N5")).sum())      # N5: tác giả gắn cờ nhầm, có chủ ý
    leak = int((is_leak & (neg.grp != "-N5")).sum())
    if leak:
        err.append(f"{leak} mẫu âm là dương của tác giả")
    if "label_source" in df:
        if ((df.label == 0) & (df.label_source != "negative_group")).any() or (
                (df.label == 1) & ~df.label_source.isin(["author_rule", "d6_rule"])).any():
            err.append("label_source không khớp label")
        d6 = df[df.label_source == "d6_rule"]
        if sum((c, a) in pos_set for c, a in zip(d6.chain, d6.address)):
            err.append("dương D6 trùng dương của tác giả")
        if (d6["at"].fillna(0) < OUT_OF_TIME_TS).any():
            warn.append(f"{int((d6['at'].fillna(0) < OUT_OF_TIME_TS).sum())} dương D6 có at trước 2025-09-01 / không có at")
    pk = set(pd.read_parquet(SEED_DIR / "candidate_pk_addresses.parquet").address.str.lower())
    n_pk = int(neg.address.isin(pk).sum())
    if n_pk:
        warn.append(f"{n_pk} mẫu âm tới địa chỉ suy ra từ key lộ (xem lại)")
    s = df[df.split.isin(["train", "val", "test"])]
    multi = s.groupby(["chain", "address"]).split.nunique()
    if (multi > 1).any():
        err.append(f"{(multi > 1).sum()} địa chỉ nằm ở nhiều tập")
    exp = df["at"].map(lambda a: split_of(None if pd.isna(a) else a))
    ok = (df.split == exp) | ((df.split == "excluded") & (exp != "no_time"))
    if not ok.all():
        err.append(f"{(~ok).sum()} mẫu có split không khớp at")
    if (df.out_of_time != (df["at"].fillna(0) >= OUT_OF_TIME_TS)).any():
        err.append("out_of_time không khớp at")
    p = df[(df.label == 1) & (df.label_source == "author_rule")] if "label_source" in df else df[df.label == 1]
    miss = p.loss_wei.isna().sum()
    if miss:
        warn.append(f"{miss} mẫu dương không tìm thấy loss trong seed")
    lw = p.loss_wei.dropna().map(int)
    if (lw < 0).any():
        err.append(f"{(lw < 0).sum()} loss âm")
    tot = loss.assign(w=loss.cost_wei.map(int)).groupby(["chain", "subtype"]).w.sum()
    info["author_loss_native_total"] = {f"{c}/{t}": round(v / 1e18, 3) for (c, t), v in tot.items()}
    info["sample_loss_native_total"] = {f"{c}/{t}": round(float(x.loss_wei.dropna().map(int).sum()) / 1e18, 3)
                                        for (c, t), x in p.groupby(["chain", "subtype"])}
    re_tot = sum(float(x) for x in p.drop_duplicates(["chain", "address", "subtype"]).loss_native.dropna())
    if abs(re_tot - sum(info["sample_loss_native_total"].values())) > 1e-3 * max(re_tot, 1):
        err.append("loss_native không khớp loss_wei")
    for c in df.columns:
        if c in HASH_COLS or df[c].dtype != object:
            continue
        v = df[c].dropna().astype(str)
        hit = v[v.str.fullmatch(HEX64_RE) | v.str.contains(r"(?i)private|secret|mnemonic")]
        if len(hit):
            err.append(f"cột {c}: {len(hit)} ô giống key/bí mật")
    h = df.tx_hash.dropna()
    if not h.str.fullmatch(r"0x[0-9a-f]{64}").all():
        err.append("tx_hash sai dạng")
    return err, warn, info


def manifest(df: pd.DataFrame, info: dict, files: list) -> dict:
    cnt = df.groupby(["split", "chain", "grp"]).size()
    return {
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "script": "python -X utf8 -m address_misuse.freeze",
        "split_boundaries_utc": {"val_from": "2023-02-10", "test_from": "2023-10-05", "out_of_time_from": "2025-09-01",
                                 "val_ts": SPLIT_VAL_TS, "test_ts": SPLIT_TEST_TS, "out_of_time_ts": OUT_OF_TIME_TS},
        "n_samples": len(df), "n_addresses": int(df[["chain", "address"]].drop_duplicates().shape[0]),
        "counts": {f"{s}/{c}/{g}": int(n) for (s, c, g), n in cnt.items()},
        "negative_groups": NEG_DESC,
        "qa": info,
        "files": {f.relative_to(FINAL_DIR).as_posix(): {"sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
                                                       "bytes": f.stat().st_size} for f in files},
    }


def write(df: pd.DataFrame, info: dict):
    SPLITS.mkdir(parents=True, exist_ok=True)
    df.to_parquet(OUT, index=False)
    files = [OUT]
    keep = ["sample_id", "kind", "grp", "chain", "address", "label", "at", "tx_hash"]
    for s in ("train", "val", "test"):
        p = SPLITS / f"{s}.csv"
        df[df.split == s][keep].to_csv(p, index=False, lineterminator="\n")
        files.append(p)
    p = SPLITS / "out_of_time.csv"
    df[df.out_of_time & (df.split != "excluded")][keep].to_csv(p, index=False, lineterminator="\n")
    files.append(p)
    p = SPLITS / "test_in_time.csv"               # test không trùng out_of_time (`test.csv` chứa cả mẫu ≥ 2025-09)
    df[(df.split == "test") & ~df.out_of_time][keep].to_csv(p, index=False, lineterminator="\n")
    files.append(p)
    MANIFEST.write_text(json.dumps(manifest(df, info, files), ensure_ascii=False, indent=1) + "\n", encoding="utf-8",
                        newline="\n")


def report(df: pd.DataFrame, err, warn, info):
    print(f"{len(df):,} mẫu, {df[['chain', 'address']].drop_duplicates().shape[0]:,} địa chỉ")
    print(pd.crosstab([df.split, df.chain], df.label, margins=True).to_string())
    print("loss mẫu dương (native):", info["sample_loss_native_total"])
    print(f"checksum: {info['seed_mixed_case_addresses']:,} địa chỉ gốc chữ lẫn, {info['seed_bad_checksum']} sai")
    for w in warn:
        print("CẢNH BÁO:", w)
    for e in err:
        print("LỖI:", e)
    print("QA: " + ("ĐẠT" if not err else f"{len(err)} lỗi"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="build", choices=["build", "qa"])
    ap.add_argument("--version", default=VERSION, choices=list(PATHS), help="qa: phiên bản cần kiểm (build chỉ dựng v2)")
    a = ap.parse_args()
    if a.cmd == "build" and a.version != VERSION:
        raise SystemExit("code hiện tại chỉ dựng được v2; v1 đã đóng băng")
    df = build() if a.cmd == "build" else pd.read_parquet(PATHS[a.version][0])
    err, warn, info = qa(df)
    report(df, err, warn, info)
    if err:
        raise SystemExit(1)
    if a.cmd == "build":
        write(df, info)
        print(f"ghi {OUT}, {SPLITS}, {MANIFEST}")


if __name__ == "__main__":
    main()
