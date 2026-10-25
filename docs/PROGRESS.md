# TIẾN ĐỘ DỰ ÁN (cập nhật liên tục)

> **Đọc file này đầu mỗi phiên làm việc mới**, rồi đến [GOALS.md](GOALS.md) và [PLAN_V2.md](PLAN_V2.md).
> Cập nhật sau mỗi bước xong, mỗi lần chạy dài, mỗi quyết định. Phát hiện cho paper → [FINDINGS_LOG.md](FINDINGS_LOG.md).
> Ký hiệu: ✅ xong · 🔄 đang làm · ⏳ chờ người dùng · ⬜ chưa làm

**Cập nhật lần cuối:** 2026-10-25
**Giai đoạn hiện tại:** Tuần 1 — D0 (chuẩn bị dữ liệu và code)

## 1. Đang làm / bước kế tiếp

- 🔄 **Rà soát quy trình 2 lượt (2026-10-24, FINDINGS_LOG cùng ngày):** lượt 1 sửa 5 lỗi Module 3; lượt 2 (mọi module)
  sửa PCD chọn tx sau khi tạo contract (sai Rule 2), contract tự huỷ, loss D6 thiếu gas, ví online dùng w/τ có
  history. ✅ symexec 727 + 77 contract, cửa sổ lịch sử 3.010, txlist ETH dương, thời điểm tạo PCD/N5 (476),
  `engine.evaluate` chạy lại; luật `sweeper` vẫn 0 báo nhầm trên âm train/val (33 ADDR). ✅ GoPlus tra xong (99,3%):
  F1 0,04 so với engine 0,86. Lỗi 6 (FINDINGS_LOG cùng ngày): `probe` nuốt timeout RPC → 1.939 địa chỉ (42 dương D6, nhiều
  âm) không có code, đã sửa. ✅ **Chuỗi chạy lại xong (2026-10-24 23:08):** symexec → evaluate → metrics → replay → freeze.
  Số mới (FINDINGS_LOG cuối file): test F1 0,926 (P 0,985, R 0,873), test_in_time F1 0,890, out_of_time F1 0,974; chỉ R
  trên mẫu mềm test R 0,728; GoPlus F1 0,038; τ_warn không ổn định (p5 26 – p95 66). dataset_v2 đóng băng 6.547 mẫu, QA đạt.
  ✅ D7 xong nhưng GitHub không phân biệt dương/âm (AUC ≈ 0,5, dấu đổi giữa train và val/test) nên không nối vào S_osint;
  ✅ 2026-10-25 rà soát lần 4 xong (mẫu vàng lộ nhãn, proxy fail-open, README/DATASHEET) và tính lại độc lập số liệu chính (`engine.verify_independent`): khớp; w không xác định, kết quả không đổi theo l2. OP: 5.149/7.615 txlist, dừng vì hết credit 402, chạy lại sau reset.
  ✅ D5 `sample_gold main` (605 mẫu, 200 gán đôi) đã sinh; 2026-10-25 sửa lỗi lộ nhãn qua tx_hash (FINDINGS_LOG), sinh lại `main_items.csv`, khoá không đổi.
  🔄 **OP (2026-10-25):** credit Blockscout reset theo ngày; crawl `l2_misuse txlist --chain op --focus author` chạy lại; sửa
  lỗi thời điểm tạo contract trước Bedrock (FINDINGS 2026-10-25). Hết credit thì dừng sạch (HTTP 402), chạy tiếp ngày sau.
  ✅ 2026-10-25 `key_sweep` xong cho ETH (FINDINGS_LOG): theo lần nạp 54% bị rút ≤ 10 phút, theo giá trị chỉ 4,2% (hai ví giữ 83% tiền); ✅ BSC xong (NodeReal, 3.495 ví): theo lần nạp 70,8% bị rút ≤ 10 phút, theo giá trị 52,4%, trung vị ví 36% (FINDINGS_LOG).
  **Bước kế tiếp:** hết txlist OP (dừng 402 ở 5.149/7.615, chạy lại sau khi credit reset) → `l2_misuse rules --chain op --focus author`; khung paper.
  **Chặn bởi người dùng (quyết định 2026-10-25):** ✅ pilot 1 xong: κ(is_misuse) = 0,615 (< 0,8), κ(type) = 0,823; 7 bất đồng, 6/7 do định nghĩa T2/PCD (FINDINGS_LOG 2026-10-25). ✅ CODEBOOK v0.4.1 (advisor Opus duyệt có sửa; §4.1 quy trình từng bước + ví dụ). Cột `leak_list` đã thử rồi BỎ (làm lộ nhãn 60/60 KEY; KEY nay gán theo mẫu hình rút nhanh, hạn chế ở CODEBOOK §10.3). Người dùng KHÔNG muốn pilot 2: κ chính thức lấy từ 200 mẫu gán đôi, gán theo lô, kiểm κ lô đầu trước khi gán tiếp. ⏳ A xác nhận v0.4.1 → rồi MỚI sinh Excel mẫu chính (`sample_gold sheet B --set main`, `--only-double` cho A). Mẫu chính 605 < mục tiêu ~2.000 của GOALS vì dataset_v2 chỉ có 42 dương mới và ~450 dương test (biện luận trong paper).

- 🔄 **Dataset v2 (DATASHEET §8):** code xong, chạy thử QA đạt. v2 = v1 + N5 (118; 42 contract recovery bị tác giả
  gắn cờ PCD chuyển sang âm) + 42 dương mới D6 + cột `label_source`, `needs_review`, `key_value0`. Dựng bản cuối sau
  bước trên.

- ✅ Symexec tái lập xong: khớp tác giả 100% trên 246 contract chạy trọn vẹn (xem nhật ký). Kết quả ở `data/interim/symexec_repro.parquet`.
- ✅ Đã chốt (2026-10-20): Module 4 = MetaMask Snap (RPC proxy chỉ để đo độ trễ); nguồn BSC = NodeReal free (Moralis đổi sang bắt gói trả phí $149+).
- ⏳ `NODEREAL_API_KEY` đã có trong `.env`; chạy `python -X utf8 -m address_misuse.crosschain_matrix timing` (tự resume, dừng khi hết CU/ngày) và `build`.
- ✅ Pilot 500 địa chỉ ETH: snapshot khớp tác giả 500/500 (FINDINGS_LOG 2026-10-15).
- ✅ D3 ma trận cross-chain đầy đủ (FINDINGS_LOG 2026-10-16).
- ✅ D3 thời gian (ETH misuse, 19.273 địa chỉ XC sau khi có creation BSC qua Binplorer): 98,4% ca đã biết có contract trước tx đầu tiên (FINDINGS_LOG 2026-10-17).
- ✅ D3 timing BSC xong (2026-10-20) qua NodeReal: 16.562 địa chỉ trong ~5 phút, 98,8% ca đã biết có contract trước tx đầu tiên (FINDINGS_LOG 2026-10-20).
- ✅ Pilot rule mở rộng (2026-10-21): 580 địa chỉ ETH (thêm 50 EOA ADDR, 30 CA có 5.000 < n_tx ≤ 50.000), snapshot khớp tác giả 580/580, loss lệch +0,00% (FINDINGS_LOG 2026-10-21).
- ✅ D1 ETH (2026-10-22): `data/raw/eth/bq_txs.parquet` (bạn chạy BigQuery), 22,4M tx đến 2026-10-20, phủ 35.664/35.664 địa chỉ, khớp Etherscan 578/579 (khác duy nhất bản ghi GENESIS). FINDINGS_LOG 2026-10-22.
- ✅ Nháp đặc tả risk score R(A,C): [RISK_SCORE.md](RISK_SCORE.md) (4 thành phần, học trọng số, ngưỡng, độ trễ, giao diện `engine/`).
- ✅ Engine risk score (2026-10-22): `python -m address_misuse.engine 0x... --chain bsc --data 0x...`; 1,7 ms/mẫu offline. Chấm thử lộ 4 vấn đề (RISK_SCORE §6, FINDINGS_LOG 2026-10-22). Kế tiếp: sửa các vấn đề đó + lấy tx thô cho mẫu âm.
- ✅ D4: N1, N2 (800 tx), N3 (640 tx), N4 (83 địa chỉ nạp đã kiểm hành vi), N6, N7, N8 (800 tx) — `negatives.py`. ✅ N5 (2026-10-23): 118 contract recovery tại địa chỉ PCD (`negatives n5`; 14 chỉ dựa vào tên → cần D5 xem lại).
- ✅ Bước 2 engine (2026-10-23): lịch sử BSC qua NodeReal, `engine/evaluate.py` (4.364 mẫu, AUC 0,75–1,00 với trọng số 0,25). Rà soát xong, sửa 5 lỗi (FINDINGS_LOG 2026-10-23).
- ✅ D8 chốt (2026-10-23, A + B): train < 2023-02-10 ≤ val < 2023-10-05 ≤ test (phân vị 70/85% dương CA) + tập test ngoài thời gian ≥ 2025-09-01 từ dương mới D6. Quét thêm block 2020–2022 cho âm của train. AUC (trọng số 0,25): ETH train 0,83 / val 0,89 / test 0,90; BSC 0,82 / 0,86 / 0,98.
- 🔄 D6 bước 1 xong: BigQuery (quota nhóm, 118,7 GB) → `data/raw/eth/bq_new_activity.parquet`, 1,26M ứng viên có tx từ 2025-09; 141.348 nhận tx gọi hàm mà không tự gửi. **Đang làm (bước 2, `d6_new.py`, chạy lại được, tự tiếp tục):** `d6_new state` (getCode 202.850 địa chỉ) → `d6_new created` (Etherscan) → `d6_new rules` → dương mới; truy vấn riêng cho 17.971 địa chỉ lộ key; dương mới cần nhãn vàng (D5).
- 🔄 D5: codebook v0.3 ([CODEBOOK.md](CODEBOOK.md)) + `sample_gold.py pilot` → `data/gold/pilot50_*.csv` (50 mẫu, 15 tầng, làm mù, bằng chứng điền sẵn); `sample_gold.py kappa A.csv B.csv`. Pilot: người gán A (bạn của người dùng) xong; người gán B (người dùng) xong 2026-10-23 trong `data/gold/annotator_B.xlsx` (`sample_gold sheet B`, 50/50, `sample_gold check` không lỗi). File A đã về: κ(is_misuse) = 0,615 (chưa đạt 0,8), chờ phân xử và codebook v0.4.

## 2. Chờ người dùng

- ✅ Etherscan API key đã có trong `.env` (gói miễn phí): eth, arb, polygon, sepolia OK; **bsc, op, base không hỗ trợ**.
- ✅ Chốt NodeReal free cho BSC (2026-10-20); OP/Base vẫn chưa có nguồn. Lịch sử cân nhắc: 2026-10-17: đã thử, không có nguồn miễn phí không cần đăng ký nào lấy đủ txlist BSC (Etherscan free, Ankr công khai, Binplorer, RPC công khai đều không được). Còn: Moralis Free (40k CU/ngày, đủ cho mẫu ~2.000 địa chỉ, ~1 tuần) hoặc Etherscan Lite; đang xin Etherscan quyền truy cập học thuật. Khảo sát 2026-10-16: BscScan API đã gộp vào Etherscan V2 (free không có BSC); Etherscan Lite $49/tháng (mọi chain, 5 lệnh/s); NodeReal/BSCTrace Free 10M CU (có `nr_getContractCreationTransaction`, nhưng lịch sử tx giới hạn 100k block/lệnh, BSC đã ~128M block); top 1.000 địa chỉ BSC = ~99% thiệt hại.
- ✅ GCP project `nt547-project` (BigQuery Sandbox), đăng nhập bằng `gcloud auth application-default login` (2026-10-21). `.env` máy này đủ Etherscan, NodeReal, GCP.
- ⏳ (Khuyến nghị) RPC riêng: Alchemy, Infura hoặc QuickNode.
- ⏳ Chọn 2 người gán nhãn.

## 3. Checklist theo PLAN_V2

### Dữ liệu (tuần 1–4)
- 🔄 **D0 Chuẩn bị**
  - ✅ Dọn dự án; bỏ tập 10k; xoá code VeriMisuse cũ.
  - ✅ `.venv`, `requirements.txt`, `pyproject.toml` (cài bằng `pip install -e .`), `.env.example`, `.gitignore`.
  - ✅ Seed: dữ liệu tác giả chuyển thành 14 bảng Parquet và MANIFEST SHA-256 (`address_misuse.seed`). `tests/test_seed.py` khớp Bảng 1, 3, 4 và §6.1 của paper.
  - ✅ Port rule Algorithm 1–3 vào `rules.py` (có `paper_compat` để tái hiện lỗi B1, B2) và `tests/test_rules.py`.
  - ✅ Client Etherscan API V2 trong `etherscan.py`, đã chạy với key thật (3 lệnh/giây).
  - ✅ Symbolic execution chạy được trên Windows: bỏ SIGALRM, đặt deadline theo basic block.
  - ✅ Symbolic execution tái lập: khớp 100% trên các contract chạy xong.
  - ⬜ Test 6 địa chỉ đã biết qua Etherscan (cần key).
- ✅ **D1** Giao dịch thô: ETH qua BigQuery (35.664 địa chỉ); BSC qua NodeReal cho mẫu đánh giá (800 dương + âm).
- 🔄 **D2** Chạy lại rule trên dữ liệu thô và so với CSV tác giả (lệch < 2%). ✅ Pilot 500 ETH (`reproduce_rules.py`): khớp 100% ở snapshot.
  - ℹ️ Kiểm tra độc lập trên toàn bộ ETH (2026-10-22, `d2_eth.py`, BigQuery không có `input`): KEY −0,02%, ADDR 0% (28.886/28.886 tx), cả hai đạt < 2%; NCD/PCD cần `input` nên chưa tính được. Xem FINDINGS_LOG
- 🔄 **D3** Cross-chain
  - ✅ `crosschain.py`: `eth_getCode` song song trên 8 mạng, kèm verdict.
  - ✅ Pilot top 100 NCD mỗi chain (xem FINDINGS_LOG).
  - ✅ Ma trận đầy đủ `address × chain` (`crosschain_matrix.py`): deployer, nonce CREATE, factory, nhãn NCD-XC/PCD-XC, khả năng deploy lại.
  - ✅ Đối chiếu thời điểm deploy với tx đầu tiên (`crosschain_matrix timing`) cho ETH misuse.
  - ✅ Creation trên BSC qua Binplorer (13.472 contract).
  - ✅ Tx đầu tiên trên BSC (NodeReal `nr_getTransactionByAddress`).
- ⬜ **D3b** Đo misuse trên L2 (Arbitrum, Optimism, Polygon) — thêm 2026-10-23, xem PLAN_V2 §D3b. Hiện cross-chain mới là *tín hiệu* (getCode 8 mạng); nạn nhân/loss/nhãn/đánh giá vẫn chỉ ETH + BSC như bài gốc. ✅ `l2_fetch.py` + dry-run (5,97M địa chỉ ứng viên + key lộ): bản `inbound` (bảng receipts, chỉ tx đến) arb 184 GB, op 91 GB, polygon 524 GB; bản có `input` 14,8 TB (không khả thi); lọc theo thời gian gần như không giảm. ✅ Đã duyệt và chạy (2026-10-23): op 91 GB → 835.832 địa chỉ có tx; arb 184 GB → 1.216.944 địa chỉ. ✅ polygon 524 GiB (người dùng duyệt 2026-10-24) → 1.619.294 địa chỉ. Quota tháng 10 đã dùng ≈ 918/1.024 GiB. 🔄 polygon `--focus author`: state xong (NCD 13.608, trong đó Type 4 11.721; PCD 4.634; KEY 4.450); txlist `--max-records 1000` → ✅ rules (2026-10-24): **13.146 NCD dương (88% Type 4), 295 PCD, 4.447 KEY (1.424 có value)**; 13.441/18.229 địa chỉ CA tác giả cũng misuse trên Polygon; 0,8% dương bị cắt txlist (loss cận dưới) — FINDINGS 2026-10-24. 🔄 Bước 2 (`l2_misuse.py`): op lọc còn 162.507 địa chỉ (gọi hàm hoặc key lộ), getCode: 117.595 không có code trên op → đang getCode 7 mạng còn lại; txlist op **tạm dừng**: Blockscout không key chỉ cho 10 lượt rồi chặn nhiều phút, Etherscan free không có OP, Routescan không có OP → ⏳ cần người dùng tạo key miễn phí dev.blockscout.com, đặt `BLOCKSCOUT_API_KEY` trong `.env`; arb: Etherscan free có arb/polygon → ✅ KEY arb: 3.536/3.536 dương theo luật tác giả nhưng 92% chỉ là lệnh sweep value 0 của kẻ tấn công; misuse thật 271 địa chỉ, 12,65 ETH (FINDINGS); ✅ arb NCD/PCD thu hẹp `--focus author` (NCD 1.161 dương theo luật tác giả, 5.857 khi bỏ điều kiện gas; PCD 155; FINDINGS); op `--focus author`: NCD 4.482 (Type 4 3.555), PCD 982 — chờ key Blockscout để tải txlist (key lộ + dương CA của tác giả trên ETH/BSC có tx đến trên arb, ~13,9k dòng): state → txlist → rules đang chạy; luật KEY thêm cột `n_misuse_value_tx`/`value_native` (bỏ tx value 0); ✅ symexec delegate op: 30/30 delegate của ví key lộ thỏa điều kiện ADDR; **3.294/3.405 ví key lộ trên op đang gắn delegate 7702** (FINDINGS) → cần symexec 30 delegate trên code op; NCD 117k để sau, ưu tiên nhóm có code ở mạng khác; arb chờ Etherscan (Blockscout arb chặn 403).
- 🔄 **D4** Tập âm N1–N8.
  - ✅ N7: 18 contract hạ tầng đa chain đã kiểm chứng (`known_multichain.py`).
  - ✅ N1: 400 địa chỉ ngẫu nhiên không bị gắn cờ (200/chain) — `negatives.py n1`.
  - ✅ N6: 5 delegate EIP-7702 hợp lệ (MetaMask, Coinbase, Uniswap Calibur, Simple7702Account, Ambire) — `negatives.py n6`.
  - ✅ N2/N3/N8: quét 400 block ngẫu nhiên/chain (2023-01 → nay) — `negatives.py scan`, `from-scan`.
  - ✅ N4: người gửi tới 6 ví nóng sàn, chỉ giữ 83/400 có hành vi địa chỉ nạp — `negatives.py n4`, `n4-verify`.
  - ⬜ Mở rộng N7 từ dữ liệu. ✅ N5.
- 🔄 **D5** Nhãn vàng ~2.000 mẫu, κ; case study 50–100 ca.
  - 2026-10-24 rà soát D5: mẫu vàng chính phải lấy từ `dataset_v2` SAU khi freeze (đơn vị là mẫu (địa chỉ, `at`), không phải
    địa chỉ). ✅ `sample_gold main` (code + test, chưa chạy): ~600 mẫu phân tầng từ test ∪ out_of_time, có `weight`
    (= cỡ tầng / số rút) để ước lượng precision/recall không lệch, 200 mẫu gán đôi tính κ, bằng chứng theo thời điểm `at`;
    `sheet B --set main [--only-double]`. Cỡ ~600 (không phải ~2.000) vì dataset_v2 chỉ có 42 dương mới và ~450 dương test.
    ✅ Đã chạy (2026-10-25, seed 0): 605 mẫu (D6 42, ADDR 60, KEY 60, NCD 80, PCD 50, N1 40, N2 60, N3 40, N4 30, N5 39, N6 5, N7 19, N8 80),
    200 gán đôi → `data/gold/main_items.csv` (đưa người gán) + `main_key.csv` (nhãn, KHÔNG commit, đã gitignore). Sinh file Excel:
    `sample_gold sheet B --set main`. Chờ annotator_A (pilot, κ) trước khi giao khối lượng lớn.
  - ✅ Codebook v0.3, script lấy mẫu pilot 50 + tính κ; file mẫu đã làm mù (bằng chứng tra cùng một cách cho mọi tầng).
  - ⬜ Pilot 50 mẫu với 2 người gán → chỉnh codebook → gán ~2.000 mẫu (cần D4 xong).
- 🔄 **D6** Cập nhật 2026, EIP-7702 mới, Type 2/3/6. ✅ Bước 1: thống kê tx từ 2025-09 của 4,99M ứng viên ETH (BigQuery 118,7 GB).
- ✅ **D7 tra xong (2026-10-25)**: 4.549 địa chỉ, dương 82,9% / âm 83,9% có mặt trên GitHub nên S_osint nhị phân không phân biệt (FINDINGS). Bước sau: nối ngữ cảnh/số repo vào S_osint, chạy lại metrics. (ghi chú cũ: token GitHub dùng được, 30 lượt code search/phút; `osint_github.py run` chạy nền cho 4.549 địa chỉ của dataset_v2, dương theo thiệt hại trước rồi âm ngẫu nhiên, ~8 giờ, cache `data/raw/osint/github.jsonl`, `summary` để xem tỉ lệ có kết quả theo nhãn; bước sau: nối số file/repo/ngữ cảnh vào S_osint) OSINT GitHub cho top ~3.000 địa chỉ (giúp truy nguồn NCD trên ETH từ testnet cũ).
- 🔄 **D8** Đóng băng Dataset v1. ✅ Mốc chia đã chốt (A + B), `assign_split` không trùng địa chỉ. ✅ `freeze.py`: `data/final/dataset_v1.parquet` + `splits/` + `MANIFEST.json`, QA tự động đạt; [README](../data/final/README.md), [DATASHEET](DATASHEET.md). ⬜ v2: thêm dương mới D6 vào tập ngoài thời gian, N5, nhãn vàng.

### Sau dữ liệu
- 🔄 Module 2: engine và risk score R(A, C) (tuần 5–6). ✅ Nháp đặc tả [RISK_SCORE.md](RISK_SCORE.md). ✅ `src/address_misuse/engine/` (FeatureStore, 4 hàm S, luật cứng, CLI, 11 test), chấm thử 1.181 mẫu. ✅ Sửa 4 vấn đề trong RISK_SCORE §6 (2026-10-23, `engine/prepare.py`). ✅ Bước 2: tập âm N2–N4, N8; lịch sử BSC; `engine/evaluate.py`; rà soát. ⬜ Học trọng số (sau D5, D8).
- 🔄 Module 3: đánh giá P/R/F1/FPR và ROC (tuần 6–7). ✅ `engine/metrics.py` (học `w` không âm trên train, ngưỡng trên val, P/R/F1/FPR + CI bootstrap, theo chain/loại/nhóm âm, tách luật cứng, ROC/PR csv, baseline getCode∧calldata, ablation), chạy thử với nhãn tạm (FINDINGS_LOG). ⬜ Chạy lại với nhãn vàng D5 + dương D6; thêm N8 cho val; GoPlus baseline.
- 🔄 Module 4: wallet-side warning, độ trễ < 150 ms (tuần 7–8). ✅ `wallet/online.py` (chấm online, cache), `wallet/proxy.py` (RPC proxy chặn tx, giải mã tx thô kể cả 7702), `wallet/bench.py` (lạnh p50 156 ms do vòng mạng tới RPC công khai, ấm p99 < 0,2 ms). ✅ `wallet/replay.py`: phát lại tx misuse tập test — BSC cảnh báo 67% tx nhưng chỉ 0,4% giá trị (1 contract PCD chiếm 80% tiền bị sót), ETH 97% tx / 99% giá trị (mẫu nhỏ); báo nhầm N8 ETH 0,33%, BSC 0%. ⬜ demo Anvil fork; quyết định Snap hay proxy (GOALS).
- ⬜ Viết paper, Docker, slide (tuần 9–10).

## 4. Nhật ký (mới nhất ở trên)

- **2026-10-23 — D6 delegates xong**: 482/484 delegate có symexec; điều kiện ADDR của tác giả đúng ở 318 delegate / 52.004 EOA, trong đó 36.041 EOA là MetaMask (ví hợp lệ) → FINDINGS_LOG. Không chạy `rules --only ADDR` riêng: lần `rules` đầy đủ (tự chạy sau `created`) sẽ dùng bảng delegate mới.
- **2026-10-24 — phân tích ADDR/PCD (train/val)**: phát hiện symexec chỉ có ở dương → S_bytecode lệch theo nhãn; đang chạy `engine.prepare contracts` (727 contract) rồi chạy lại Module 3/4. Đề xuất luật cứng `sweeper` (ADDR train/val 0,5% → 17,9%, 0 báo nhầm). FINDINGS.
- **2026-10-24 — replay ETH đủ + arb focus author**: replay ETH test 182 địa chỉ, cảnh báo 93,8% tx / 97,3% giá trị, ADDR 0%; arb NCD/PCD xong (FINDINGS). Sửa tràn int64 trong `replay.summary`.
- **2026-10-24 — commit interim + job mới**: commit 23 file kết quả `data/interim` (đã quét không có chuỗi giống key); 69 test, 38 module import, `freeze qa` đạt. Đang chạy: txlist Etherscan cho 234 dương ETH test → chạy lại replay; arb `--focus author`.
- **2026-10-24 — D3b arb KEY + op delegate**: Blockscout op chặn khi không có key (chờ người dùng tạo key); chuyển sang arb qua Etherscan; KEY arb xong; symexec 172 delegate op xong (FINDINGS).
- **2026-10-23 — D6 luật + OP delegate**: D6 rules (sửa lỗi lấy mẫu): ngẫu nhiên 400/luật → ADDR 1, NCD 3, PCD 1/2 dương mới; ADDR bỏ ví N6 (1.549 EOA) → 38 dương mới, 0,082 ETH (FINDINGS). `l2_misuse delegates --chain op`: 356 delegate, 177 trùng bytecode ETH, symexec 172 đang chạy. txlist op đang chạy.
- **2026-10-23 — D3b + N5 + genesis**: thêm D3b (misuse trên L2) vào PLAN_V2; `l2_fetch dry-run` (bảng chi phí ở dòng D3b, Base không có trên BigQuery công khai). N5 xong: giữ 118 contract (siết tiêu chí: bỏ contract tên "Rescue/Retriever" mà tác giả gán tay là độc hoặc do ví key lộ deploy; FINDINGS). `key_genesis` xong: 1/4.256 ví KEY ETH có genesis (21 ETH, 0,02%).
- **2026-10-23 — Replay + D8**: `wallet/replay.py` (điểm yếu PCD/ADDR, % tiền khác hẳn % tx); `freeze.py` đóng băng Dataset v1, QA đạt; README + DATASHEET. 68 test pass. D6 `created` 85k/107,7k, delegates 190/415, key_genesis 3.000/4.256.
- **2026-10-23 — Module 4 PoC**: online store + proxy + bench; proxy chặn được tx tới ví Truffle lộ key; độ trễ lạnh bị giới hạn bởi RTT ~140 ms tới publicnode từ VN. Tăng symexec delegate lên 5 worker (2 worker quá chậm).
- **2026-10-23 — Module 3 chạy thử**: test F1 0,826 (P 0,966, R 0,721, FPR 0,008), baseline F1 0,418; PCD recall 0,37, N7 FPR 0,16. Nhãn tạm. Song song: `key_genesis` (NodeReal số dư block 0 của 4.256 ví KEY), `d6_new delegates` (symexec 435 bytecode). 63 test pass.
- **2026-10-23 — D6: getCode xong** (202.850: code 107.726, 7702 71.741, none 23.383). `created` lấy bù cho 43,8k contract mới, sau đó tự chạy `rules`. Thêm `d6_new delegates`: điều kiện ADDR đúng như code tác giả (symexec `transfer_all_eth`/`transfer_msg_value` của delegate; `flag` cũ chỉ phủ 13/484 delegate), symexec mọi delegate mới (mỗi bytecode một lần) → `d6_delegates.parquet`; xong thì chạy lại `rules --only ADDR`.
- **2026-10-23 — D5 pilot, người gán B xong**: thêm `sample_gold sheet` (Excel có danh sách chọn + sheet hướng dẫn), `check` (lỗi hình thức), `kappa` đọc .xlsx và chặn khi hai file khác bộ mẫu. File B: 50/50, không lỗi. Chờ file A để tính κ.
- **2026-10-23 — D6 bước 2 (dở dang, tắt máy)**: `d6_new.py` (sàng ứng viên → getCode → creation → luật tác giả). Sơ bộ: ~13% ứng viên CA không có code (NCD); chỉ 2/5.451 EOA 7702 uỷ quyền tới delegate tác giả gắn cờ → danh sách đen cũ, cần phân loại delegate mới. Chạy lại `d6_new state` và `d6_new created` (tự tiếp tục), rồi `d6_new rules`.
- **2026-10-23 — D8 + D6 bước 1**: chốt chia tập A + B; quét 600 block/chain 2020–2022 (NodeReal); chấm lại theo tập; BigQuery quota nhóm: lần 1 bị từ chối (kết quả quá lớn, 0 GB), lần 2 gom theo địa chỉ, 118,7 GB. 57 test pass.
- **2026-10-23 — Bước 2 + rà soát**: `engine.prepare sample/history` (NodeReal cho BSC, 0 lỗi), `negatives scan/from-scan/n4/n4-verify`, `engine/evaluate.py`. Rà soát sửa: lịch sử BigQuery bị cắt xén cho địa chỉ ngoài danh sách truy vấn, thiếu bộ lọc IDM, 7702 trước kích hoạt, `at` của PCD, status trước Byzantium của NodeReal. 56 test pass. Chờ quyết mốc D8.
- **2026-10-23 — Sửa 4 vấn đề của engine**: `engine/prepare.py` (`creation` 258/258, `delegates` symexec 30/30, `history` txlist cho 223 địa chỉ ETH âm); so contract bằng selector; delegate theo thời điểm `at`. 52 test pass. Chấm lại: N1 ETH trung vị 19,6 → 7,1 (FINDINGS_LOG 2026-10-22).
- **2026-10-22 — Engine risk score**: `engine/features.py`, `engine/score.py`, `engine/__main__.py`, `tests/test_engine.py` (50 passed). Chấm thử 1.181 mẫu; phát hiện delegate 7702 của sweeper đã đổi sau snapshot tác giả (0% EOA ADDR còn delegate cũ) — FINDINGS_LOG 2026-10-22.
- **2026-10-22 — Nhận `bq_txs.parquet`**: kiểm tra không trùng khoá, phủ đủ địa chỉ, đối chiếu Etherscan trên 579 địa chỉ pilot (FINDINGS_LOG 2026-10-22).
- **2026-10-21 — `.env` + GCP trên máy này, pilot rule 580**: kiểm tra key (không in giá trị): Etherscan, NodeReal, BigQuery đều OK. Cài `google-cloud-bigquery`, `db-dtypes` vào `.venv`. `bq_fetch dry-run`: 35.718 địa chỉ ETH, 680 GB. `reproduce_rules` với `--n-addr 50 --n-big 30`: snapshot khớp 580/580 (FINDINGS_LOG 2026-10-21).
- **2026-10-21 — Risk score + rule pilot mở rộng**: viết `docs/RISK_SCORE.md` v0.1 (4 thành phần, học trọng số, ngưỡng, độ trễ, giao diện `engine/`). `reproduce_rules` thêm tầng `addr` (EOA ADDR; số dư snapshot từ dữ liệu tác giả, số dư hiện tại qua balancemulti) và `big` (5.000 < n_tx ≤ 50.000), kéo tối đa 100k tx/địa chỉ; mẫu 500 cũ vẫn được chọn y hệt. Chưa chạy vì máy này thiếu `.env`. Nhóm n_tx > 5.000 chỉ chiếm 3,0% loss ETH (trước ghi nhầm là nhóm thiệt hại lớn nhất).
- **2026-10-20 — Chốt NodeReal + Snap**: Moralis không còn gói Free trong luồng đăng ký (bắt $149+); BigQuery không có dataset BSC; Blockscout/Ankr không dùng được. `cmd_timing` dùng NodeReal `nr_getTransactionByAddress` (order asc, maxCount 1) cho BSC; đã thử thật 1 địa chỉ, OK.
- **2026-10-19 — Gộp lại sau khi bạn force-push (`11b88df`)**: lấy toàn bộ bản của bạn (backup: nhánh `backup/main-before-2026-10-19` và stash GitHub Desktop), rồi áp lại phần của mình:
  - `rpc_batch` chờ lùi dần; `BINPLORER_MAX_WAITS` (mặc định 8) để bước Binplorer tự dừng khi mạng lỗi, chạy lại sẽ tiếp tục từ cache.
  - `negatives.py`: N1, N6. Phát hiện `flag` của tác giả = kết quả symexec (FINDINGS_LOG 2026-10-19).
  - `sample_gold.py`: tầng `eoa_7702` / `eoa_7702_other` theo symexec + N6; mọi mẫu được tra `getCode` trực tiếp; symexec bổ sung cho 12 contract (cache `data/raw/gold/symexec_pilot.jsonl`); cột nguồn gốc/thời điểm chỉ điền ở tình huống T4. Pilot sinh lại, 50 mẫu, 15 tầng.
  - CODEBOOK v0.3. Test: 39 passed.
- **2026-10-17 — D3 creation BSC (Binplorer) + timing lại + pilot D5 sinh lại**: origin 13.472 dòng, timing 12.780 địa chỉ, build 49.344 dòng. ETH misuse: deployed_before 17.635 / after 283 / unknown 1.355; redeploy unknown giảm 14.955 → 1.572. Commit `crosschain_matrix.parquet`, `pilot50_items.csv`, `annotator_template.csv` (không commit `pilot50_key.csv`).
- **2026-10-16 — D3 thời gian (ETH misuse)**: bước `timing` mới, 5.132 địa chỉ, ~31 phút qua Etherscan free. 90,9% deployed_before. Phía BSC chờ nguồn dữ liệu.

- **2026-10-16 — Review và gộp commit ce2e398** (pilot rule + D3 origin) với nhánh local `local/d3-matrix-claude`:
  - Review: logic CREATE/RLP và nhãn redeploy đúng. Hai lần quét D3 độc lập cho cùng số NCD-XC.
  - Giữ `crosschain_matrix.py` của bạn. Bỏ bản ma trận của mình vì trùng kết quả.
  - `rpc_batch` giờ chỉ thử lại các phần tử lỗi và chờ lùi dần 2/4/8/16 s.
  - `etherscan.py`: lỗi rate-limit thật sự không còn bị tính là một lần thử (tối đa 30 lần chờ).
  - Đưa sang từ nhánh local: N7 (`known_multichain.py`, viết lại trên `rpc_batch`/`_code_record`, chạy lại 18/18 giống cũ), 3 test mới (tổng 29 pass), whitelist `.gitignore` cho kết quả nhỏ.
  - README: thêm lệnh mới và bảng file. CONTRIBUTING: nhắc cài lại requirements sau khi pull.
- **2026-10-16 — D3 xong** → `data/interim/crosschain_matrix.parquet` (49.344 dòng):
  - Bước RPC cũ treo >1 giờ: publicnode trả `null` cho đa số tx cũ trên arb/polygon nên mỗi lô bị thử lại 5 lần. Đã bỏ hẳn `eth_getTransactionByHash`: phân loại factory bằng `contractFactory` của Etherscan, nonce CREATE tìm cục bộ bằng `create_address(creator, n)` (17.287 cặp, 13 s).
  - Misuse BSC (XC chủ yếu nằm trên ETH, có creation): claimable 11.515 (1.000 BNB), burned 2.377, already_deployed 494, factory 2.114, unknown 815.
  - Misuse ETH: 14.955 unknown vì XC phần lớn nằm trên BSC, mà Etherscan free không có creation cho BSC. Phần tra được: claimable 2.224, burned 1.224. **Cần chốt nguồn dữ liệu BSC** để lấp chỗ này.

- **2026-10-15 — Pilot 500 ETH + D3 (dở, xong ngày 16)**:
  - `reproduce_rules.py` (350 NCD + 100 PCD + 50 KEY, n_tx ≤ 5.000): chế độ snapshot (n_tx tx đầu) **khớp tác giả 500/500 đến từng wei**. Dữ liệu hiện tại: thêm 98 tx misuse ở 20 NCD, 2 NCD đã thành PCD, 24/50 KEY nhận thêm 238 tx.
  - `crosschain_matrix.py code` xong (45.633 địa chỉ × 8 mạng, 0 lỗi). Sơ bộ: NCD-XC = 77% địa chỉ NCD BSC (19% loss), 68% NCD ETH (3% loss); chỉ ~10–13% NCD-XC có value > 0 (còn lại chỉ mất gas).
  - **Việc tiếp theo:** chạy lại `python -X utf8 -m address_misuse.crosschain_matrix origin` (resume từ `data/raw/crosschain/creation.jsonl`, eth + arb gần xong), rồi `... build`; ghi FINDINGS_LOG; commit.
  - Etherscan free = **3 lệnh/giây**; `getcontractcreation` trả kèm bytecode → rất chậm qua mạng nhóm, cần chạy song song (đã sửa).

- **2026-10-15 — Kiểm tra Etherscan key** (`python -m address_misuse.etherscan`): eth, arb, polygon, sepolia OK; bsc, op, base trả "Free API access is not supported for this chain". Kết nối tới `api.etherscan.io` từ máy nhóm có lúc timeout hẳn (lần chạy đầu lỗi cả 7 chain), chạy lại thì được → khi kéo dữ liệu dài cần retry/resume.

- **2026-10-15 — Dựng lại môi trường từ bản clone mới** theo README (Python 3.13):
  - `.venv` + `requirements.txt` + `pip install -e .`; `fetch_author_data`: 61 file nguồn khớp SHA-256 (tải Zenodo ~85 KB/s, ~45 phút; script chưa hỗ trợ tải tiếp khi đứt mạng).
  - `seed`: 14 bảng, số dòng khớp `data/README.md`; MANIFEST chỉ khác `generated_at` (đã hoàn tác) → seed tái tạo y hệt. `pytest`: 21 passed.

- **2026-10-13 — Đưa dự án lên GitHub** (`https://github.com/HLong145/NT547_project`):
  - Không đưa lên git: dữ liệu tác giả (444 MB; tải lại bằng `python -m address_misuse.fetch_author_data`, kiểm tra SHA-256 theo `data/seed/MANIFEST.json`), `data/seed/*.parquet` (tạo lại bằng `seed`), `data/raw/`, `.env`, file PDF paper.
  - Có đưa lên: code, test, docs, MANIFEST và 2 file kết quả nhỏ trong `data/interim/`.
  - README có phần "Bắt đầu sau khi clone". Quy ước nhóm nằm ở `CONTRIBUTING.md`. `CLAUDE.md` chỉ giữ trên máy, không commit (theo yêu cầu người dùng).

- **2026-10-12 — Symexec xong cả 2 lượt** (RAM tổng ≤ 1 GB):
  - 307/344 contract chạy được (trung vị 2,9 s/contract), 37 vượt 850 MB (eth: 9 misuse + 4 proxy; bsc: 17 misuse + 7 proxy). 61 contract hết thời gian mềm.
  - 246 contract chạy trọn vẹn: **khớp 100%**. Gộp cả contract hết thời gian: delegatecall 99,7%, transfer_all_eth 99,0%, transfer_msg_value 99,3%, transfer_input_amount 99,7%.

- **2026-10-12 — Symexec lượt 1 xong** (2 process, giới hạn 400 MB):
  - 278/344 contract chạy được, 66 bị dừng vì vượt RAM (đa số thuộc nhóm `proxy_logic`), 41 contract hết thời gian mềm.
  - Trên 237 contract chạy xong trọn vẹn: **khớp tác giả 100%** cả 4 cờ. Mọi chỗ lệch đều nằm ở contract hết thời gian, và đều là tác giả = 1 / mình = 0 (dừng sớm nên bỏ sót).
  - Lượt chạy lại 66 contract (1 process, 850 MB) đang chạy; nhiều contract `proxy_logic` vẫn vượt 850 MB.
- **2026-10-12** — Thêm [SETUP_GUIDE.md](SETUP_GUIDE.md), hướng dẫn lấy Etherscan key, BigQuery sandbox (đăng nhập bằng gcloud ADC, không cần JSON) và RPC riêng.
  - `etherscan.py`: `PAGE_SIZE` lấy từ `ETHERSCAN_PAGE_SIZE`, mặc định 1000 (giới hạn mới của gói miễn phí).
  - Thêm lệnh `python -m address_misuse.etherscan` để kiểm tra key dùng được trên chain nào.
- **2026-10-12** — Gửi người dùng bản phân tích MetaMask Snap và RPC proxy. **Chờ người dùng chốt.**

- **2026-10-12** — Người dùng yêu cầu symexec dùng **tối đa 1 GB RAM**:
  - Chạy với 2 process, mỗi process ≤ 400 MB (`--workers 2 --max-mem-mb 400`).
  - Sau đó chạy lại riêng các contract lỗi bằng `--retry-failed --workers 1 --max-mem-mb 850`.
  - Đã xong 84/344 trước khi đổi cấu hình.

- **2026-10-12** — Theo dõi RAM khi chạy symexec:
  - Có contract làm một process dùng ~2 GB RAM (máy 15,4 GB, lúc đó còn trống 2,6 GB). Nhiều khả năng đây là lý do lần chạy đầu với 6 process bị chết.
  - Đã thêm chốt chặn: process nào vượt 2,5 GB thì bị kill và ghi trạng thái `oom` (`--max-mem-mb`, dùng psutil).
  - Đã chạy tiếp từ chỗ dừng (74/344 đã xong).

- **2026-10-12**
  - Lần chạy symexec đầu (Pool 6 worker) chết ở 75/344 với exit code 4, không có traceback; nghi một contract làm crash cứng engine.
  - Đã viết lại `reproduce_symexec.py`:
    - mỗi contract chạy trong một process riêng, bị kill nếu quá timeout cộng 60 s;
    - thread có stack 128 MB;
    - ghi jsonl ngay sau từng contract, có resume.
  - Đã chạy lại; kết quả xem §1.
- **2026-10-12** — Tạo GOALS.md và PROGRESS.md (file này) để giữ mạch giữa các phiên.
- **2026-10-12**
  - Bước 3 xong: port code tác giả (etherscan.py, rules.py, symexec).
  - Bước 4 xong: pilot cross-chain. Trên BSC, 36/100 địa chỉ NCD lớn nhất là contract ở chain khác (13% thiệt hại); trên ETH chỉ 2/100.
  - 21 test pass.
- **2026-10-12** — Bước 1–2 xong: seed Parquet khớp các con số trong paper. Viết lại PLAN_V2 theo đúng mục tiêu ban đầu (không chuyển thành benchmark).
- **2026-10-12** — Phân tích thư mục tác giả. Bỏ tập 10k giao dịch (không dùng được). Dọn dự án.

## 5. Lệnh hay dùng

```powershell
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m address_misuse.seed
.venv\Scripts\python.exe -X utf8 -m address_misuse.reproduce_symexec --timeout 120 --sample-misuse 150 --workers 4
.venv\Scripts\python.exe -X utf8 -m address_misuse.reproduce_symexec --summary-only
.venv\Scripts\python.exe -m address_misuse.crosschain <addr> --chain bsc --data 0x...
.venv\Scripts\python.exe -m address_misuse.crosschain_pilot --top 100
```
- **2026-10-24 — Key Blockscout/GitHub**: `BLOCKSCOUT_API_KEY` chỉ chạy trên endpoint PRO `api.blockscout.com/10/api` (endpoint `optimism.blockscout.com/api` vẫn 429); đã đổi trong `l2_misuse.py`, đã chạy `l2_misuse txlist --chain op --focus author --max-records 1000`: dừng ở 1.254/8.869 địa chỉ vì Blockscout PRO hết credit (HTTP 402, 2026-10-25). ⏳ chờ credit reset hoặc bỏ OP khỏi mức misuse.
