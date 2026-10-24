"""Chấm engine trên mẫu đánh giá (dương + âm) theo thời gian — chỉ mô tả, KHÔNG chọn ngưỡng hay trọng số.

python -m address_misuse.engine.evaluate [--seed 0]   → data/interim/engine_eval.parquet + bảng tóm tắt

Cùng một quy trình cho mẫu dương và âm (tránh lệch giữa hai nhóm):
- mẫu theo địa chỉ (dương trong `engine_eval_sample`, N1, N4, N6, N7): chọn ngẫu nhiên một tx đi vào địa chỉ làm
  thời điểm xét `at` và ngữ cảnh; chỉ dùng dữ liệu trước `at`. Dương chọn trong tx misuse theo đúng luật tác giả:
  NCD = tx gọi hàm; PCD = tx gọi hàm TRƯỚC khi contract được tạo (Rule 2: `block < creation`; sau khi tạo là gọi
  contract bình thường). N5 (contract recovery) ngược lại: chỉ tx SAU khi contract được tạo — câu hỏi là engine có
  báo nhầm contract hợp lệ không. Không có lịch sử → at = hôm nay.
  Lịch sử từ txlist (Etherscan / NodeReal) có input thật; chỉ khi phải dùng BigQuery (không input) ngữ cảnh mới là
  "có calldata" (gas dùng > 21.000) và không chạy được bộ lọc IDM / T3;
- mẫu theo tx (N2, N3, N8): `at` = thời điểm block, ngữ cảnh = value + input thật; lịch sử là 1.000 tx gần nhất trước
  `at` (`prepare windows` khi txlist đã cache bị cắt trước `at`).

Chia tập (D8): `split` theo `at` (train / val / test, mốc ở `config`); một địa chỉ chỉ thuộc một tập — tập của mẫu
sớm nhất, các mẫu khác của nó ở tập sau bị bỏ (`split = "excluded"`); mẫu không có `at` không thuộc tập nào
(`split = "no_time"`). `out_of_time` = at ≥ 2025-09-01 (tập test thứ hai, cho dương mới của D6).
"""

import argparse
import zlib

import numpy as np
import pandas as pd

from address_misuse.config import INTERIM_DIR, OUT_OF_TIME_TS, SPLIT_TEST_TS, SPLIT_VAL_TS
from address_misuse.engine.features import FeatureStore
from address_misuse.engine.prepare import ENGINE_SAMPLE
from address_misuse.engine.score import TxContext, score_features
from address_misuse.rules import is_hex_readable

OUT = INTERIM_DIR / "engine_eval.parquet"
CALL_PLACEHOLDER = "0xffffffff"                   # có calldata nhưng không biết nội dung (BigQuery)


NCD_MAX_GAS = 30_000                                     # rules.py: gasUsed <= 30000


def address_samples() -> pd.DataFrame:
    cols = ["grp", "chain", "address", "label", "src"]
    s = pd.read_parquet(ENGINE_SAMPLE).assign(label=1, src="author")
    s["grp"] = "+" + s.subtype
    parts = [s[cols]]
    p = INTERIM_DIR / "d6_new_positives.parquet"
    if p.exists():                                       # dương mới D6 (luật của nhóm, ETH, sau 2025-09)
        d6 = pd.read_parquet(p).query("is_new_positive")
        parts.append(pd.DataFrame({"grp": "+" + d6.subtype, "chain": "eth", "address": d6.address, "label": 1,
                                   "src": "d6"}))
    n1 = pd.read_parquet(INTERIM_DIR / "n1_random_unflagged.parquet")
    parts.append(n1.assign(grp="-N1", label=0, src="neg")[cols])
    p = INTERIM_DIR / "n4_exchange_deposits.parquet"
    if p.exists():
        n4 = pd.read_parquet(p)
        n4 = n4[n4.kept.fillna(False).astype(bool)] if "kept" in n4 else n4
        parts.append(n4.assign(grp="-N4", label=0, src="neg")[cols])
    p = INTERIM_DIR / "n5_recovery_contracts.parquet"
    if p.exists():
        n5 = pd.read_parquet(p).query("kept")
        n5["address"] = n5.address.str.lower()
        parts.append(n5.assign(grp="-N5", label=0, src="neg")[cols])
        # contract recovery tác giả gắn cờ PCD nhầm: bỏ khỏi dương, chỉ giữ ở N5
        n5_keys = set(zip(n5.chain, n5.address))
        parts[0] = parts[0][[k not in n5_keys for k in zip(parts[0].chain, parts[0].address.str.lower())]]
    n6 = pd.read_parquet(INTERIM_DIR / "n6_benign_7702_delegates.parquet").query("kept")
    parts.append(pd.DataFrame({"grp": "-N6", "chain": "eth", "address": n6.address, "label": 0, "src": "neg"}))
    n7 = pd.read_parquet(INTERIM_DIR / "n7_multichain_contracts.parquet").query("kept")
    for ch in ("eth", "bsc"):
        parts.append(pd.DataFrame({"grp": "-N7", "chain": ch, "address": n7.address, "label": 0, "src": "neg"}))
    df = pd.concat(parts, ignore_index=True)
    df["address"] = df.address.str.lower()
    return df


def tx_samples() -> pd.DataFrame:
    parts = []
    for grp, name in (("-N2", "n2_contract_calls"), ("-N3", "n3_text_messages"), ("-N8", "n8_normal_txs")):
        p = INTERIM_DIR / f"{name}.parquet"
        if p.exists():
            d = pd.read_parquet(p)
            parts.append(pd.DataFrame({"grp": grp, "chain": d.chain, "address": d.target.str.lower(), "label": 0, "src": "neg",
                                       "at": d.block_ts, "value_wei": d.value_wei, "calldata": d.input}))
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def pick_event(txs: pd.DataFrame | None, address: str, grp: str, own_create_ts: int | None, seed: int,
               min_ts: int | None = None):
    """(at, TxContext) từ một tx đi vào chọn ngẫu nhiên (tái lập được theo địa chỉ); None nếu không có.
    `min_ts`: chỉ chọn tx từ thời điểm này (dương D6 chỉ là misuse từ 2025-09)."""
    if txs is None or not len(txs):
        return None
    inc = txs[txs.to_address == address]
    if min_ts is not None:
        inc = inc[inc.block_ts >= min_ts]
    if grp in ("+NCD", "+PCD"):
        inc = inc[inc.receipt_gas_used > 21_000]
    if grp == "+NCD":                                    # luật NCD của tác giả: gasUsed ≤ 30.000, thành công, không phải văn bản
        inc = inc[(inc.receipt_gas_used <= NCD_MAX_GAS) & (inc.receipt_status == 1)]
        if "input" in inc and inc.input.map(lambda x: isinstance(x, str)).all():
            inc = inc[~inc.input.map(lambda x: x != "0x" and is_hex_readable(x))]
    if grp == "+PCD" and own_create_ts is not None:
        inc = inc[inc.block_ts < own_create_ts]
    elif grp == "-N5" and own_create_ts is not None:
        inc = inc[inc.block_ts >= own_create_ts]
    if not len(inc):
        return None
    rng = np.random.default_rng(seed + zlib.crc32(address.encode()))
    t = inc.iloc[int(rng.integers(len(inc)))]
    if isinstance(t.get("input"), str):                  # txlist: input thật (chạy được bộ lọc IDM / T3 như mẫu âm)
        call = t.input
    else:
        call = CALL_PLACEHOLDER if t.receipt_gas_used > 21_000 else "0x"
    return int(t.block_ts), TxContext(int(t.value), call)


def evaluate(seed: int = 0) -> pd.DataFrame:
    adr, txs = address_samples(), tx_samples()
    fs = FeatureStore()
    allp = pd.concat([adr, txs])
    fs.prepare(list(zip(allp.chain, allp.address)))
    fs.probe(allp.address.unique())
    if miss := fs.missing_code(allp.address.unique()):  # state None → S_bytecode 0: lệch theo nhãn (FINDINGS 2026-10-24)
        print(f"CẢNH BÁO: {len(miss)} địa chỉ chưa có getCode đủ 8 mạng, chạy lại để tra tiếp", flush=True)
    rows = []
    for r in adr.itertuples():
        own = fs.own_create.get((r.chain, r.address))
        ev = pick_event(fs.txs.get((r.chain, r.address)), r.address, r.grp, own, seed,
                        OUT_OF_TIME_TS if r.src == "d6" else None)
        at, ctx = ev if ev else (None, None)
        rows.append(_row(r, fs, at, ctx))
    for r in txs.itertuples():
        rows.append(_row(r, fs, int(r.at), TxContext(int(r.value_wei), r.calldata or "0x")))
    return assign_split(pd.DataFrame(rows))


def split_of(at) -> str:
    if at is None or pd.isna(at):
        return "no_time"
    return "train" if at < SPLIT_VAL_TS else "val" if at < SPLIT_TEST_TS else "test"


def assign_split(df: pd.DataFrame) -> pd.DataFrame:
    """Tập theo `at`; địa chỉ xuất hiện ở nhiều tập chỉ giữ ở tập của mẫu sớm nhất (không trùng địa chỉ, D8)."""
    df = df.copy()
    df["split"] = [split_of(a) for a in df["at"]]
    df["out_of_time"] = df["at"].fillna(0) >= OUT_OF_TIME_TS
    timed = df[df.split != "no_time"]
    home = timed.sort_values("at").drop_duplicates(["chain", "address"]).set_index(["chain", "address"]).split
    keys = list(zip(df.chain, df.address))
    clash = [(s != "no_time") and home.get(k) != s for k, s in zip(keys, df.split)]
    df.loc[clash, "split"] = "excluded"
    return df


def _row(r, fs: FeatureStore, at, ctx) -> dict:
    f = fs.features(r.address, r.chain, at)
    res = score_features(f, ctx)
    return {"grp": r.grp, "chain": r.chain, "address": r.address, "label": r.label, "src": r.src, "at": at,
            "has_ctx": ctx is not None, "has_call": bool(ctx and ctx.has_call), "state": f.state(), "R": res.score, **res.components,
            "hard": res.hard_rule, "types": ",".join(res.types),
            "hist": fs.history_source.get((r.chain, r.address)), "n_tx_before": (f.history or {}).get("n_tx")}


def auc(pos: pd.Series, neg: pd.Series) -> float:
    """AUC theo hạng (Mann–Whitney), hoà tính 0,5."""
    if not len(pos) or not len(neg):
        return float("nan")
    r = pd.concat([pos, neg]).rank()
    return float((r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def summary(df: pd.DataFrame) -> str:
    pd.set_option("display.width", 220)
    g = df.groupby(["grp", "chain"])
    t = g.agg(n=("R", "size"), R_med=("R", "median"), R_p90=("R", lambda x: x.quantile(.9)),
              bytecode=("bytecode", "mean"), cross=("cross", "mean"), osint=("osint", "mean"),
              history=("history", "mean"), hard=("hard", lambda x: x.notna().mean()),
              ctx=("has_ctx", "mean"), hist=("hist", lambda x: x.notna().mean())).round(2)
    lines = [t.to_string(), "", "AUC (dương vs từng nhóm âm, cùng chain; 'không OSINT' = bỏ S_osint, "
                                "'không luật cứng' = bỏ mẫu dính luật cứng):"]
    no_osint = df.R - 100 * 0.25 * df.osint
    for ch in ("eth", "bsc"):
        d = df[df.chain == ch]
        pos = d[d.label == 1]
        soft = pos[pos.hard.isna()]
        for grp in sorted(d[d.label == 0].grp.unique()):
            neg = d[d.grp == grp]
            lines.append(f"  {ch} {grp}: AUC {auc(pos.R, neg.R):.3f} | không OSINT "
                         f"{auc(no_osint[pos.index], no_osint[neg.index]):.3f} | không luật cứng {auc(soft.R, neg.R):.3f}")
    return "\n".join(lines)


def split_summary(df: pd.DataFrame) -> str:
    lines = ["Theo tập (D8): số mẫu dương/âm và AUC dương vs mọi mẫu âm cùng chain:"]
    for ch in ("eth", "bsc"):
        for sp in ("train", "val", "test", "excluded", "no_time"):
            d = df[(df.chain == ch) & (df.split == sp)]
            pos, neg = d[d.label == 1], d[d.label == 0]
            lines.append(f"  {ch} {sp:8s}: dương {len(pos):4d}, âm {len(neg):4d}"
                         + (f", AUC {auc(pos.R, neg.R):.3f}" if sp in ("train", "val", "test") else ""))
        d = df[(df.chain == ch) & df.out_of_time]
        lines.append(f"  {ch} ngoài thời gian (≥ 2025-09-01): dương {int((d.label == 1).sum())}, "
                     f"âm {int((d.label == 0).sum())}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    df = evaluate(a.seed)
    df.to_parquet(OUT, index=False)
    print(f"ghi {OUT} ({len(df)} mẫu)\n")
    print(summary(df))
    print()
    print(split_summary(df))


if __name__ == "__main__":
    main()
