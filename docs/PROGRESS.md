# TIẾN ĐỘ DỰ ÁN (cập nhật liên tục)

> **Đọc file này đầu mỗi phiên làm việc mới**, rồi đến [GOALS.md](GOALS.md) và [PLAN_V2.md](PLAN_V2.md).
> Cập nhật sau mỗi bước xong, mỗi lần chạy dài, mỗi quyết định. Phát hiện cho paper → [FINDINGS_LOG.md](FINDINGS_LOG.md).
> Ký hiệu: ✅ xong · 🔄 đang làm · ⏳ chờ người dùng · ⬜ chưa làm

**Cập nhật lần cuối:** 2026-10-15
**Giai đoạn hiện tại:** Tuần 1 — D0 (chuẩn bị dữ liệu và code)

## 1. Đang làm / bước kế tiếp

- ✅ Symexec tái lập xong: khớp tác giả 100% trên 246 contract chạy trọn vẹn (xem nhật ký). Kết quả ở `data/interim/symexec_repro.parquet`.
- ⏳ Chờ người dùng chốt Module 4: Snap (đề xuất) hay RPC proxy.
- ✅ Pilot 500 địa chỉ ETH: snapshot khớp tác giả 500/500 (FINDINGS_LOG 2026-10-15).
- ✅ D3 ma trận cross-chain đầy đủ (FINDINGS_LOG 2026-10-16).
- ✅ D3 thời gian (ETH misuse, 5.132 địa chỉ): 90,9% contract có trước tx đầu tiên (FINDINGS_LOG).
- ⬜ D3 còn: phía BSC (cần nguồn BSC) — đề xuất BSCTrace/NodeReal Free cho creation, Etherscan Lite cho txlist.
- ⬜ Viết bản nháp codebook gán nhãn (D5).

## 2. Chờ người dùng

- ✅ Etherscan API key đã có trong `.env` (gói miễn phí): eth, arb, polygon, sepolia OK; **bsc, op, base không hỗ trợ**.
- ⏳ Chốt cách lấy dữ liệu BSC (và OP/Base). Đã khảo sát 2026-10-16: BscScan API đã gộp vào Etherscan V2 (free không có BSC); Etherscan Lite $49/tháng (mọi chain, 5 lệnh/s); NodeReal/BSCTrace Free 10M CU (có `nr_getContractCreationTransaction`, nhưng lịch sử tx giới hạn 100k block/lệnh, BSC đã ~128M block); top 1.000 địa chỉ BSC = ~99% thiệt hại.
- ⏳ GCP project có bật BigQuery, kèm service-account JSON (để ngoài thư mục dự án; đường dẫn ghi trong `.env`).
- ⏳ (Khuyến nghị) RPC riêng: Alchemy, Infura hoặc QuickNode.
- ⏳ Chọn 2 người gán nhãn.
- ⏳ Chốt Module 4: MetaMask Snap hay RPC proxy (mình đề xuất Snap; proxy chỉ để đo độ trễ).

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
- ⬜ **D1** Giao dịch thô: ETH qua BigQuery, BSC qua Etherscan.
- 🔄 **D2** Chạy lại rule trên dữ liệu thô và so với CSV tác giả (lệch < 2%). ✅ Pilot 500 ETH (`reproduce_rules.py`): khớp 100% ở snapshot.
- 🔄 **D3** Cross-chain
  - ✅ `crosschain.py`: `eth_getCode` song song trên 8 mạng, kèm verdict.
  - ✅ Pilot top 100 NCD mỗi chain (xem FINDINGS_LOG).
  - ✅ Ma trận đầy đủ `address × chain` (`crosschain_matrix.py`): deployer, nonce CREATE, factory, nhãn NCD-XC/PCD-XC, khả năng deploy lại.
  - ✅ Đối chiếu thời điểm deploy với tx đầu tiên (`crosschain_matrix timing`) cho ETH misuse.
  - ⬜ Phía BSC: creation trên BSC (BSCTrace `nr_getContractCreationTransaction`) và tx đầu tiên trên BSC.
- ⬜ **D4** Tập âm N1–N8.
- ⬜ **D5** Nhãn vàng ~2.000 mẫu, κ; case study 50–100 ca.
- ⬜ **D6** Cập nhật 2026, EIP-7702 mới, Type 2/3/6.
- ⬜ **D7** OSINT GitHub cho top ~3.000 địa chỉ (giúp truy nguồn NCD trên ETH từ testnet cũ).
- ⬜ **D8** Đóng băng Dataset v1 (chia theo thời gian, không trùng địa chỉ giữa các tập, QA).

### Sau dữ liệu
- ⬜ Module 2: engine và risk score R(A, C) (tuần 5–6).
- ⬜ Module 3: đánh giá P/R/F1/FPR và ROC (tuần 6–7).
- ⬜ Module 4: wallet-side warning, độ trễ < 150 ms (tuần 7–8).
- ⬜ Viết paper, Docker, slide (tuần 9–10).

## 4. Nhật ký (mới nhất ở trên)

- **2026-10-16 — D3 thời gian (ETH misuse)**: bước `timing` mới, 5.132 địa chỉ, ~31 phút qua Etherscan free. 90,9% deployed_before. Phía BSC chờ nguồn dữ liệu.

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
