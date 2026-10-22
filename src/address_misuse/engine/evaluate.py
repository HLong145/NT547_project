"""Chấm engine trên mẫu đánh giá (dương + âm) theo thời gian — chỉ mô tả, KHÔNG chọn ngưỡng hay trọng số.

python -m address_misuse.engine.evaluate [--seed 0]   → data/interim/engine_eval.parquet + bảng tóm tắt

Cùng một quy trình cho mẫu dương và âm (tránh lệch giữa hai nhóm):
- mẫu theo địa chỉ (dương trong `engine_eval_sample`, N1, N4, N6, N7): chọn ngẫu nhiên một tx đi vào địa chỉ làm
  thời điểm xét `at` và ngữ cảnh; chỉ dùng dữ liệu trước `at`. Với NCD chỉ chọn tx gọi hàm (tx misuse), với PCD chỉ
  chọn tx sau khi contract được tạo trên chính chain (trước đó địa chỉ chưa phải PCD). Không có lịch sử → at = hôm nay.
  BigQuery không có input, nên ngữ cảnh chỉ biết "có calldata" (gas dùng > 21.000), không chạy được bộ lọc IDM / T3;
- mẫu theo tx (N2, N3, N8): `at` = thời điểm block, ngữ cảnh = value + input thật.
"""

import argparse
import zlib

import numpy as np
import pandas as pd

from address_misuse.config import INTERIM_DIR
from address_misuse.engine.features import FeatureStore
from address_misuse.engine.prepare import ENGINE_SAMPLE
from address_misuse.engine.score import TxContext, score_features

OUT = INTERIM_DIR / "engine_eval.parquet"
CALL_PLACEHOLDER = "0xffffffff"                   # có calldata nhưng không biết nội dung (BigQuery)


def address_samples() -> pd.DataFrame:
    s = pd.read_parquet(ENGINE_SAMPLE).assign(label=1)
    s["grp"] = "+" + s.subtype
    parts = [s[["grp", "chain", "address", "label"]]]
    n1 = pd.read_parquet(INTERIM_DIR / "n1_random_unflagged.parquet")
    parts.append(n1.assign(grp="-N1", label=0)[["grp", "chain", "address", "label"]])
    p = INTERIM_DIR / "n4_exchange_deposits.parquet"
    if p.exists():
        n4 = pd.read_parquet(p)
        n4 = n4[n4.kept.fillna(False).astype(bool)] if "kept" in n4 else n4
        parts.append(n4.assign(grp="-N4", label=0)[["grp", "chain", "address", "label"]])
    n6 = pd.read_parquet(INTERIM_DIR / "n6_benign_7702_delegates.parquet").query("kept")
    parts.append(pd.DataFrame({"grp": "-N6", "chain": "eth", "address": n6.address, "label": 0}))
    n7 = pd.read_parquet(INTERIM_DIR / "n7_multichain_contracts.parquet").query("kept")
    for ch in ("eth", "bsc"):
        parts.append(pd.DataFrame({"grp": "-N7", "chain": ch, "address": n7.address, "label": 0}))
    df = pd.concat(parts, ignore_index=True)
    df["address"] = df.address.str.lower()
    return df


def tx_samples() -> pd.DataFrame:
    parts = []
    for grp, name in (("-N2", "n2_contract_calls"), ("-N3", "n3_text_messages"), ("-N8", "n8_normal_txs")):
        p = INTERIM_DIR / f"{name}.parquet"
        if p.exists():
            d = pd.read_parquet(p)
            parts.append(pd.DataFrame({"grp": grp, "chain": d.chain, "address": d.target.str.lower(), "label": 0,
                                       "at": d.block_ts, "value_wei": d.value_wei, "calldata": d.input}))
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def pick_event(txs: pd.DataFrame | None, address: str, grp: str, own_create_ts: int | None, seed: int):
    """(at, TxContext) từ một tx đi vào chọn ngẫu nhiên (tái lập được theo địa chỉ); None nếu không có."""
    if txs is None or not len(txs):
        return None
    inc = txs[txs.to_address == address]
    if grp == "+NCD":
        inc = inc[inc.receipt_gas_used > 21_000]
    elif grp == "+PCD" and own_create_ts is not None:
        inc = inc[inc.block_ts >= own_create_ts]
    if not len(inc):
        return None
    rng = np.random.default_rng(seed + zlib.crc32(address.encode()))
    t = inc.iloc[int(rng.integers(len(inc)))]
    call = CALL_PLACEHOLDER if t.receipt_gas_used > 21_000 else "0x"
    return int(t.block_ts), TxContext(int(t.value), call)


def evaluate(seed: int = 0) -> pd.DataFrame:
    adr, txs = address_samples(), tx_samples()
    fs = FeatureStore()
    allp = pd.concat([adr, txs])
    fs.prepare(list(zip(allp.chain, allp.address)))
    fs.probe(allp.address.unique())
    rows = []
    for r in adr.itertuples():
        own = fs.own_create.get((r.chain, r.address))
        ev = pick_event(fs.txs.get((r.chain, r.address)), r.address, r.grp, own, seed)
        at, ctx = ev if ev else (None, None)
        rows.append(_row(r, fs, at, ctx))
    for r in txs.itertuples():
        rows.append(_row(r, fs, int(r.at), TxContext(int(r.value_wei), r.calldata or "0x")))
    return pd.DataFrame(rows)


def _row(r, fs: FeatureStore, at, ctx) -> dict:
    f = fs.features(r.address, r.chain, at)
    res = score_features(f, ctx)
    return {"grp": r.grp, "chain": r.chain, "address": r.address, "label": r.label, "at": at,
            "has_ctx": ctx is not None, "state": f.state(), "R": res.score, **res.components,
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    df = evaluate(a.seed)
    df.to_parquet(OUT, index=False)
    print(f"ghi {OUT} ({len(df)} mẫu)\n")
    print(summary(df))


if __name__ == "__main__":
    main()
