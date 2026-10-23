"""Module 4 — phát lại lịch sử (PLAN_V2 §5): ví có kiểm tra này thì lẽ ra đã cảnh báo bao nhiêu tx misuse / bao
nhiêu tiền, và báo nhầm bao nhiêu tx bình thường.

python -X utf8 -m address_misuse.wallet.replay   → data/interim/wallet_replay.parquet + bảng tóm tắt

- Tx misuse: địa chỉ dương thuộc tập test (`engine_eval`, D8) có txlist đầy đủ kèm input trong cache
  (`data/raw/<chain>/txlist/`); chạy luật tác giả (`rules.py`) để lấy đúng các tx bị gắn cờ. NodeReal (BSC) không trả
  `methodId`/`functionName` như Etherscan → lấy `methodId` = 4 byte đầu input, coi như có tên hàm.
  ADDR dùng số dư tác giả ghi lại.
- Mỗi tx chấm tại đúng thời điểm của nó (`FeatureStore.features(at=ts)`, chỉ dùng thông tin trước ts) với ngữ cảnh
  thật (value, input), trọng số + ngưỡng từ Module 3. Cảnh báo = luật cứng HOẶC R ≥ τ_warn.
  Hạn chế: tập lộ key / OSINT không có mốc thời gian nên coi như đã biết từ trước.
- Tx bình thường: N8 (1 tx ngẫu nhiên mỗi block), cùng cách chấm; thêm N2 (gọi contract) và N3 (văn bản tới EOA).
- Cửa sổ: test (≥ 2023-10-05) và ngoài thời gian (≥ 2025-09-01).
"""

import gzip
import json

import pandas as pd

from address_misuse.config import INTERIM_DIR, OUT_OF_TIME_TS, SPLIT_TEST_TS
from address_misuse.engine.features import FeatureStore, txlist_path
from address_misuse.engine.score import TxContext, score_features
from address_misuse.reproduce_rules import author_balances
from address_misuse.rules import detect_ca_misuse, detect_eoa_addr, detect_eoa_key
from address_misuse.wallet.online import learned_config

EVAL = INTERIM_DIR / "engine_eval.parquet"
OUT = INTERIM_DIR / "wallet_replay.parquet"


def _raw(chain: str, address: str) -> list[dict] | None:
    p = txlist_path(chain, address)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        txs = json.load(f)["result"]
    for t in txs:                                       # NodeReal: thiếu methodId / functionName
        inp = t.get("input") or "0x"
        t.setdefault("methodId", inp[:10] if len(inp) >= 10 else "0x")
        t.setdefault("functionName", "?" if len(inp) >= 10 else "")
    return txs


def flagged_txs(grp: str, chain: str, address: str, txs: list[dict], fs: FeatureStore, bal: dict) -> list[dict]:
    if grp == "+KEY":
        res = detect_eoa_key(address, txs)
    elif grp == "+ADDR":
        res = detect_eoa_addr(address, txs, balance_wei=bal.get(address, 0), eip7702_delegate_malicious=True)
    else:
        ts = fs.own_create.get((chain, address))
        creation = {"blockNumber": 10 ** 12, "timestamp": ts} if ts else None
        res = detect_ca_misuse(address, txs, chain, creation=creation)
    by_hash = {t["hash"]: t for t in txs}
    return [by_hash[f["hash"]] for f in res.flagged if f["hash"] in by_hash]


def misuse_rows(fs: FeatureStore, w: dict, tau: dict) -> list[dict]:
    ev = pd.read_parquet(EVAL)
    pos = ev[(ev.label == 1) & (ev.split == "test")].drop_duplicates(["chain", "address"])
    rows, skipped = [], {}
    for chain in ("eth", "bsc"):
        p = pos[pos.chain == chain]
        bal = author_balances(chain, p.address[p.grp == "+ADDR"])
        fs.prepare(list(zip(p.chain, p.address)))
        for r in p.itertuples():
            txs = _raw(chain, r.address)
            if txs is None:
                skipped[chain] = skipped.get(chain, 0) + 1
                continue
            for t in flagged_txs(r.grp, chain, r.address, txs, fs, bal):
                ts = int(t["timeStamp"])
                if ts < SPLIT_TEST_TS:
                    continue
                rows.append(_score(fs, w, tau, r.grp, chain, r.address, ts, int(t["value"]),
                                   int(t["gasUsed"]) * int(t["gasPrice"]), t.get("input") or "0x", 1))
    print("địa chỉ dương test không có txlist (bỏ): " + ", ".join(f"{c} {n}" for c, n in skipped.items()), flush=True)
    return rows


def normal_rows(fs: FeatureStore, w: dict, tau: dict) -> list[dict]:
    rows = []
    for grp, name in (("-N8", "n8_normal_txs"), ("-N2", "n2_contract_calls"), ("-N3", "n3_text_messages")):
        d = pd.read_parquet(INTERIM_DIR / f"{name}.parquet")
        d = d[d.block_ts >= SPLIT_TEST_TS]
        fs.prepare(list(zip(d.chain, d.target.str.lower())))
        for r in d.itertuples():
            rows.append(_score(fs, w, tau, grp, r.chain, r.target.lower(), int(r.block_ts), int(r.value_wei), 0,
                               r.input or "0x", 0))
    return rows


def _score(fs, w, tau, grp, chain, address, ts, value, gas, data, label) -> dict:
    res = score_features(fs.features(address, chain, ts), TxContext(value, data), w)
    warn = bool(res.hard_rule) or res.score >= tau["warn"]
    return {"grp": grp, "chain": chain, "address": address, "ts": ts, "label": label, "value_wei": str(value),
            "gas_wei": str(gas), "R": res.score, "hard": res.hard_rule, "warn": warn,
            "block": bool(res.hard_rule) or res.score >= tau["block"], "types": ",".join(res.types)}


def summary(df: pd.DataFrame) -> str:
    L = []
    for win, m in (("test (≥ 2023-10-05)", df.ts >= SPLIT_TEST_TS), ("ngoài thời gian (≥ 2025-09-01)", df.ts >= OUT_OF_TIME_TS)):
        L.append(f"== {win}")
        for chain in ("eth", "bsc"):
            d = df[m & (df.chain == chain)]
            mis, nor = d[d.label == 1], d[d.label == 0]
            if len(mis):
                v = mis.value_wei.map(int) + mis.gas_wei.map(int)
                vw = v[mis.warn].sum()
                L.append(f"  {chain} misuse: {len(mis):,} tx ({mis.address.nunique()} địa chỉ); cảnh báo "
                         f"{mis.warn.mean():.1%} tx, {vw / max(v.sum(), 1):.1%} giá trị ({vw / 1e18:,.3f} / "
                         f"{v.sum() / 1e18:,.3f} native); do luật cứng {mis.hard.notna().mean():.1%} tx")
                top = v.groupby(mis.address).sum().sort_values()
                rest = ~mis.address.eq(top.index[-1])
                L.append(f"      (địa chỉ lớn nhất chiếm {top.iloc[-1] / max(v.sum(), 1):.0%} giá trị; bỏ nó ra: cảnh báo "
                         f"{v[mis.warn & rest].sum() / max(v[rest].sum(), 1):.1%} giá trị)")
                for g, x in mis.groupby("grp"):
                    xv = x.value_wei.map(int) + x.gas_wei.map(int)
                    L.append(f"      {g}: {len(x):,} tx, cảnh báo {x.warn.mean():.1%} tx / "
                             f"{xv[x.warn].sum() / max(xv.sum(), 1):.1%} giá trị")
            for g, x in nor.groupby("grp"):
                L.append(f"  {chain} {g}: {len(x):,} tx bình thường, báo nhầm {x.warn.mean():.2%} "
                         f"(mức chặn {x.block.mean():.2%})")
    return "\n".join(L)


def main():
    w, tau = learned_config()
    print(f"trọng số {w}, ngưỡng {tau}", flush=True)
    fs = FeatureStore()
    df = pd.DataFrame(misuse_rows(fs, w, tau) + normal_rows(fs, w, tau))
    df.to_parquet(OUT, index=False)
    print(summary(df))
    print(f"ghi {OUT}")


if __name__ == "__main__":
    main()
