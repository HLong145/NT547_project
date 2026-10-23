# PLAN V2 — Kế hoạch thực hiện paper Address Misuse (cross-chain + wallet-side warning)

> **Mục tiêu giữ nguyên** theo đề bài và `requirements.md`: tái lập một phần nghiên cứu Address Misuse (Shao et al., USENIX Sec '26) trên Ethereum/BSC, phân loại CA Misuse và EOA Misuse, xây detector dựa trên rule/pattern giao dịch, kiểm chứng bằng manual audit; **cải tiến**: cross-chain address consistency, risk score và cảnh báo phía ví (wallet-side warning).
> **Tên tạm**: *Characterizing and Mitigating Address Misuse Risks in Cross-Chain EVM Ecosystems*.
> Tài liệu này chỉ thay **lộ trình thực hiện** (thay §6 của `requirements.md`). Ưu tiên số 1 là **hoàn thiện dữ liệu**.
> Ngày lập: 2026-10-12.

---

## 0. Hiện trạng dữ liệu

### 0.1. `data/10000_transaction*.csv` → **đã xoá** (2026-10-12)

Đã kiểm tra trực tiếp (đối chiếu on-chain qua public RPC). Giao dịch có thật, nhưng nhãn không dùng được:

| Vấn đề | Bằng chứng |
|---|---|
| Không rõ nguồn gốc nhãn | 0% địa chỉ `EOA_MISUSE` và chỉ 0,8% địa chỉ `CA_MISUSE` nằm trong danh sách misuse của Shao et al.; không có script hay tiêu chí gán nhãn nào được lưu lại. |
| Nhãn CA_MISUSE sai theo định nghĩa của paper | 269/4.000 là giao dịch **deploy contract** (`to` rỗng); 390/4.000 có input là văn bản (inscription ierc-20, memo sàn) — loại IDM mà paper lọc bỏ; 154 có selector `0x00000000` → ≥16% nhãn dương sai rõ ràng. |
| Nhiễu xung đột | 71 tx_hash trùng, có hash mang 2 nhãn; `clean_dataset.py` chọn nhãn bằng tay. |
| Thiên lệch lấy mẫu | Tỷ lệ 5000/4000/1000 dựng tay; toàn bộ EOA_MISUSE nằm trong ~2 ngày; BENIGN tập trung vào vài router; không lớp nào có tx value = 0 → mô hình học được "lối tắt" theo block/địa chỉ. |
| Phạm vi | Chỉ ETH 01–09/2024: không BSC, không L2, không EIP-7702. |

→ Đã xoá cùng `EVALUATION_REPORT.md` và code/benchmark cũ (VeriMisuse); toàn bộ Module 2–4 sẽ viết lại.

### 0.2. Dữ liệu Zenodo của Shao et al. (`data/Address-Misuse/`) → **nền tảng**

Đã xác minh khớp Bảng 1, 3, 4 của paper. Dùng được ngay cho CA Misuse (NCD/PCD) và EOA Misuse (KEY/ADDR/EIP-7702). Những thiếu sót cần bổ sung **để phục vụ mục tiêu của paper**:

| # | Thiếu sót | Ảnh hưởng tới mục tiêu nào |
|---|---|---|
| G1 | Chỉ có tổng hợp theo địa chỉ, không có giao dịch thô | Detector mức giao dịch, đo độ trễ và replay cho warning |
| G2 | Nhãn RQ1 chỉ là mẫu dương → chỉ tính được Precision | RQ3 cần Recall, F1, **FPR** |
| G3 | Không biết địa chỉ có contract ở chain nào khác | **Cross-chain** (Type 4) |
| G4 | Chỉ ETH + BSC, không có L2 | Requirements yêu cầu Arbitrum/Optimism |
| G5 | Chỉ native coin | Type 3 (token gửi vào chính contract token) |
| G6 | Dữ liệu dừng ~08/2025 | Sweeper EIP-7702 tăng mạnh sau đó |
| G7 | Không có ngữ cảnh nguồn (repo/file) | Thành phần `S_osint` của risk score |
| G8 | Code chưa chạy được (thiếu `api_config.py`, `requirements.txt`; bug `CodeFetcher`; `SIGALRM` không chạy trên Windows; Etherscan API V1) | Tái lập |

---

## 1. Khung paper (giữ theo requirements)

**Đóng góp**
1. Taxonomy hình thức: CA Misuse, EOA Misuse, Cross-Chain Address Misalignment.
2. Dataset có nhãn (ETH, BSC, L2) dùng cho đo lường và đánh giá.
3. Framework phát hiện + `RiskScore ∈ [0,100]` kết hợp on-chain (bytecode/state/lịch sử) và off-chain (OSINT).
4. PoC cảnh báo phía ví (RPC proxy) chặn giao dịch rủi ro trước khi ký, độ trễ thêm < 150 ms.

**Taxonomy & nguồn dữ liệu cho từng loại**

| Type | Tên | Mức ưu tiên | Dữ liệu có sẵn | Phải bổ sung |
|---|---|---|---|---|
| 1 | Gọi hàm tới địa chỉ không có code | Lõi | Shao NCD (26.983 địa chỉ ETH + 21.199 BSC) | Giao dịch thô |
| 2 | Contract "hố đen" (nhận ETH, không rút được) | Phụ | Bytecode trong `codes.zip` + symbolic executor | Rule ngược "không có đường chuyển ETH ra", nhãn tay |
| 3 | Gửi token vào chính contract token | Phụ | — | `tokentx` |
| 4 | Cross-chain misalignment | **Lõi – đóng góp mới** | Gợi ý: 3.711 địa chỉ bị misuse trên cả ETH lẫn BSC; PCD | `eth_getCode` đa chuỗi, deployer/nonce, giao dịch trên L2 |
| 5 | Private key lộ công khai / sweeper / EIP-7702 | Lõi | Shao KEY/ADDR, 99 delegate độc, `eip7702_map` | Cập nhật 2026 |
| 6 | Address poisoning | Phụ (chủ yếu phục vụ warning) | — | Mẫu nhỏ: transfer giá trị 0 / địa chỉ giống nhau |

Type 1, 4, 5 là lõi để trả lời đầy đủ 3 RQ. Type 2, 3, 6 làm ở quy mô nhỏ, chủ yếu để detector và warning bao phủ đủ taxonomy.

**Câu hỏi nghiên cứu** (giữ nguyên)
- **RQ1 – Measurement**: tần suất và thiệt hại của CA/EOA Misuse trên ETH, BSC, L2; phân bố tài sản bị khóa.
- **RQ2 – Root cause & exploit**: CREATE/CREATE2 xuyên chuỗi, thiếu fallback, lộ key; cách attacker khai thác (planted contract, sweeper, EIP-7702).
- **RQ3 – Effectiveness & overhead**: P/R/F1/FPR so với baseline; độ trễ và tài nguyên của warning.

---

## 2. DỮ LIỆU (ưu tiên số 1, tuần 1–4)

### 2.1. Dữ liệu này dùng để làm gì

| Mục đích | Cần gì |
|---|---|
| RQ1 đo lường | Địa chỉ misuse + loss (có sẵn) + cập nhật 2026 + L2 |
| RQ2 nguyên nhân | Deployer, nonce, thời điểm deploy trên từng chain; bytecode contract độc |
| RQ3 detector | Tập dương **và tập âm** có nhãn vàng, chia theo thời gian |
| RQ3 warning | Giao dịch thô (để replay) + tập giao dịch bình thường (để đo cảnh báo sai) |
| Risk score | Đặc trưng cho 4 thành phần `S_bytecode`, `S_cross-chain`, `S_osint`, `S_history` |

### 2.2. Cấu trúc thư mục

```
data/
  seed/      # dữ liệu Zenodo chuyển sang Parquet, giữ nguyên nội dung
  raw/       # dữ liệu tải về (append-only, có manifest + SHA-256, fetched_at)
    eth/ bsc/ arb/ op/ ... {txs, internal, tokentx, creation, code}
  interim/   # kết quả rule, đặc trưng
  gold/      # nhãn tay: annotator_A.csv, annotator_B.csv, adjudicated.csv
  final/     # bảng dùng cho paper + splits/
```

Các bảng chính: `addresses` (chain, address, subtype, code_state, delegate_7702, n_tx, label), `transactions` (hash, block, ts, from, to, value, selector, is_readable, status, rule_hits, label, loss), `crosschain_code` (address × chain → có code? deployer, nonce, block deploy), `contracts` (bytecode_hash, symexec flags, malicious), `gold_labels`.

### 2.3. Các bước

**D0 – Chuẩn bị (tuần 1, 2–3 ngày)**
- Sửa code tác giả: thêm `requirements.txt`; `api_config` đọc key từ `.env`; sửa `CodeFetcher(chain, key)`; thay `SIGALRM` bằng timeout chạy được đa nền tảng; chuyển sang Etherscan **API V2** (`chainid`).
- Chuyển seed sang Parquet (các file `*_simliar.csv` đọc bằng UTF-16).
- Kiểm tra quota API: free tier Etherscan V2 có thể không hỗ trợ BSC/L2. Phương án dự phòng: RPC archive (Ankr/NodeReal/Alchemy) hoặc gói trả phí 1 tháng.
- Test trên các địa chỉ đã biết: `0xC532…4008`, `0x10ED…024E`, `0x580D…375c`, `0x6273…Ef57`, `0x00a3…EA72`, `0xf39F…2266`.

**D1 – Giao dịch thô cho tập dương (tuần 1–2)**
- ETH: Google BigQuery `crypto_ethereum` (transactions, traces, token_transfers, contracts) — upload danh sách địa chỉ rồi JOIN; chạy dry-run để ước lượng chi phí trước.
- BSC: Etherscan V2 / RPC cho ~22 nghìn địa chỉ.
- Địa chỉ quá lớn (>50k tx): cắt theo cửa sổ thời gian và đánh dấu `truncated`.

**D2 – Tái lập rule của tác giả (tuần 2)**
- Chạy Algorithm 1/2/3 trên dữ liệu thô, cắt ở mốc 08/2025 → so với CSV của tác giả (mục tiêu: tổng loss lệch < 2%; nếu lệch thì ghi nguyên nhân).
- Kết quả: nhãn mức giao dịch cho mọi misuse tx. Đây là phần "tái lập subset" mà đề bài yêu cầu.

**D3 – Dữ liệu cross-chain (tuần 2–3)** ← phục vụ Type 4 / `S_cross-chain`
- Với mọi địa chỉ CA Misuse (và mẫu âm): `eth_getCode` trên ETH, BSC, Arbitrum, Optimism, Base, Polygon, Sepolia, Holesky, BSC testnet → ma trận `address × chain`.
- Với địa chỉ có code ở bất kỳ chain nào: lấy deployer, nonce, block deploy, kiểu CREATE hay CREATE2 → giải thích nguyên nhân gốc (RQ2): cùng deployer + cùng nonce trên nhiều chain, hoặc factory CREATE2.
- Đo misuse trên L2: lấy giao dịch tới các địa chỉ là contract trên ETH/BSC nhưng **không có code** trên Arbitrum/Optimism (top theo hoạt động, giới hạn ~5.000 địa chỉ).
- Gắn nhãn: `NCD-XC` (có contract ở chain khác) và `NCD-Other`.

**D4 – Tập âm & hard negatives (tuần 3)** ← cần để tính FPR và tỷ lệ cảnh báo sai

| Loại | Cách lấy | Kiểm tra cho |
|---|---|---|
| N1 Ngẫu nhiên cùng nguồn | Địa chỉ trong `addrs_info` mà rule không gắn cờ | Recall (tìm FN) |
| N2 Gọi contract hợp lệ | Gọi hàm tới contract có code, cùng selector phổ biến | Type 1 |
| N3 Tin nhắn/inscription | Input là văn bản gửi tới EOA | Bộ lọc IDM |
| N4 Ví tự động hợp lệ | Hot wallet sàn, địa chỉ nạp có auto-sweep | Rule sweep |
| N5 Recovery contract chính thức | Ví dụ PancakeSwap Recovery | Symbolic exec |
| N6 EIP-7702 lành tính | Ủy quyền tới smart wallet hợp lệ (MetaMask, Safe, Coinbase…) | Type 5 |
| N7 Cùng địa chỉ, cùng contract trên nhiều chain | Contract deploy nhất quán (Uniswap Permit2, Multicall3, Safe…) | Type 4 – không được báo sai |
| N8 Giao dịch bình thường của người dùng | Mẫu ngẫu nhiên tx thường trên ETH/BSC/L2 | Tỷ lệ cảnh báo sai của warning |

**D5 – Gán nhãn vàng / manual audit (tuần 3–4)**
- Codebook ngắn: định nghĩa 6 type và các bằng chứng bắt buộc (nhãn Etherscan, lịch sử tx, ma trận cross-chain, bytecode đã decompile).
- Mẫu: kiểm tra lại ~150 mẫu RQ1 của tác giả + ~1.000 dương mới (ưu tiên Type 4, Type 5 sau 08/2025) + ~800 âm (N1–N8) → **~2.000 mẫu** (đúng con số trong requirements), cộng 1.629 nhãn kế thừa.
- 2 người gán độc lập → Cohen's κ (mục tiêu ≥ 0,8) → hội ý phân xử. Pilot 50 mẫu trước để chỉnh codebook.
- Riêng mục "manual audit 50–100 ca" trong requirements: chọn 100 ca có thiệt hại lớn nhất và các ca biên, viết case study (phục vụ RQ2).

**D6 – Cập nhật 2026 & mở rộng (tuần 4)**
- Kéo dài dữ liệu tới block mới nhất cho cùng tập địa chỉ; quét giao dịch EIP-7702 (type 4) trên ETH bằng BigQuery → delegate mới, gom cụm theo bytecode.
- Type 3: từ `tokentx`, tìm token gửi vào chính contract token (top ~500 token).
- Type 2: chạy rule "nhận ETH nhưng không có đường chuyển ra" trên bytecode PCD/NCD-XC; gán nhãn tay một mẫu.
- Type 6: mẫu nhỏ các giao dịch poisoning (transfer giá trị 0, địa chỉ trùng 4 ký tự đầu và 4 ký tự cuối) để kiểm tra phần warning.
- Định giá thiệt hại theo giá tại ngày giao dịch (lưu bảng giá trong `raw/prices/`), song song với mức giá cố định của tác giả để so sánh.

**D7 – OSINT cho `S_osint` (tuần 4)**
- Top ~3.000 địa chỉ theo thiệt hại: GitHub code search → repo/file, từ khóa chain đi kèm (`sepolia`, `bsc`, `chainId`, RPC URL), số lần xuất hiện.
- Không thu thập hay lưu private key; chỉ dùng danh sách địa chỉ đã suy ra sẵn trong dữ liệu Zenodo.

**D8 – Đóng băng dữ liệu (cuối tuần 4)**
- Chia tập theo thời gian, **chốt 2026-10-23 (A + B)**. Mốc cũ (train < kích hoạt EIP-7702 ≤ val < 2025-09-01 ≤ test) cho test = 0 mẫu dương vì dữ liệu tác giả dừng ở 07/2025, nên đổi:
  - **A — đánh giá chính** trên dữ liệu tác giả: mốc = phân vị 70% / 85% thời điểm tx đầu tiên của 34.480 dương CA: train < 2023-02-10 ≤ val < 2023-10-05 ≤ test (`config.SPLIT_VAL_TS`, `SPLIT_TEST_TS`). Xét theo `at` của từng mẫu.
  - **B — test ngoài thời gian**: dương mới từ D6 (ứng viên chưa bị gắn cờ, tx từ 2025-09-01, `config.OUT_OF_TIME_TS`) kèm âm cùng giai đoạn. Kiểm tra mô hình học trên dữ liệu cũ có còn đúng với kiểu misuse mới (EIP-7702) không. Truy vấn BigQuery `bq_fetch new-dry-run` / `new-fetch` (~197 GB quota của nhóm, chạy khi được duyệt).
  - Không để địa chỉ trùng giữa các tập (tránh lỗi rò rỉ dữ liệu như tập 10k): địa chỉ thuộc tập của mẫu sớm nhất, mẫu muộn hơn của nó bị bỏ (`engine/evaluate.assign_split`).
- QA tự động: không trùng khóa, checksum địa chỉ, tính lại tổng loss, quét để chắc chắn không có private key.
- Ghi `final/README` và datasheet ngắn; ẩn một phần địa chỉ cá nhân khi trích trong paper.

### 2.4. Rủi ro dữ liệu

| Rủi ro | Giảm thiểu |
|---|---|
| Quota/chi phí API cho BSC và L2 | ETH dùng BigQuery; BSC/L2 giới hạn ở tập dương, mẫu âm và top địa chỉ; cache mọi response |
| Dữ liệu thô lệch với dữ liệu tác giả đã dùng | Ghi nhận chênh lệch như một kết quả tái lập, không ép cho khớp |
| Gán nhãn tốn công | Sinh bằng chứng tự động, pilot trước, lấy mẫu phân tầng |
| Đạo đức | Chỉ đọc dữ liệu thụ động; không ký hay gửi giao dịch nào; không lưu private key |

---

## 3. Detection & Risk Engine (Module 2, tuần 5–6)

- **Bytecode/State analyzer**: `eth_getCode`, nhận diện EIP-7702 (`0xef0100…`), proxy chưa khởi tạo, không có đường rút (tái dùng symbolic executor của tác giả, đã sửa).
- **Cross-chain consistency validator**: truy vấn song song `eth_getCode` trên N chain (có cache); so khớp bytecode/deployer; cờ "có contract ở chain khác nhưng trống ở chain đích".
- **History/sweeper analyzer**: `findSweepTxPair`, delegate 7702 độc, tỷ lệ revert.
- **OSINT**: tra danh sách địa chỉ lộ key và số lần xuất hiện trên GitHub/StackExchange.
- **Risk score** `R(A,C) = 100 · (w1·S_bytecode + w2·S_cross + w3·S_osint + w4·S_history)`: học trọng số `w` bằng logistic regression trên tập **train**, chuẩn hóa về [0,100]; chọn ngưỡng cảnh báo trên **val**; ablation từng thành phần.

## 4. Đánh giá (Module 3, tuần 6–7)

- Chỉ chạy trên tập **test** (theo thời gian, không trùng địa chỉ với train).
- Baseline: rule gốc Shao et al.; heuristic đơn giản (`getCode == 0x ∧ input ≠ 0x`); GoPlus Address Security API; nhãn Etherscan (nếu truy cập được).
- Chỉ số: Precision, Recall, F1, FPR theo từng type và chain; khoảng tin cậy bootstrap; ROC/PR curve của risk score.
- Manual audit các ca FP/FN → phần Discussion.

## 5. Wallet-side warning (Module 4, tuần 7–8)

- **RPC proxy** (FastAPI) đứng giữa MetaMask và RPC thật: chặn `eth_sendTransaction` / `eth_sendRawTransaction` (giải mã tx thô), chạy các kiểm tra và trả về cảnh báo hoặc chặn có giải thích. Thêm `eth_call`/simulation khi cần.
- Các kiểm tra theo type: (1) đích không có code nhưng có calldata; (4) đích có contract ở chain khác; (5) đích nằm trong danh sách lộ key / delegate 7702 độc; (3) token gửi vào chính contract token; (6) địa chỉ giống một địa chỉ trong lịch sử của người dùng; (2) contract hố đen.
- **Đánh giá**:
  - *Replay lịch sử*: phát lại các giao dịch misuse trong tập test, chỉ dùng thông tin có trước thời điểm tx → % giao dịch / % ETH lẽ ra đã được cảnh báo.
  - *Cảnh báo sai*: chạy trên N8 (giao dịch bình thường) → tỷ lệ cảnh báo sai.
  - *Hiệu năng*: p50/p95/p99 độ trễ thêm (mục tiêu < 150 ms), có/không có cache, CPU/RAM.
  - *Demo*: Anvil fork tái hiện ca Aave Kovan 2.580 ETH (CA Misuse) và ca Truffle `0x6273…` (EIP-7702 sweeper) bị chặn trước khi ký.

---

## 6. Lộ trình 10 tuần

| Tuần | Việc | Đầu ra |
|---|---|---|
| 1 | D0, pilot 500 địa chỉ, ước tính chi phí | Pipeline chạy được |
| 1–2 | D1 giao dịch thô, D2 tái lập | Báo cáo tái lập |
| 2–3 | D3 cross-chain | Ma trận address × chain, nhãn Type 4 |
| 3 | D4 tập âm | Tập âm N1–N8 |
| 3–4 | D5 gán nhãn, D6 mở rộng, D7 OSINT | ~2.000 nhãn vàng, κ |
| 4 | D8 đóng băng dữ liệu | **Dataset v1** |
| 5–6 | Module 2: engine + risk score | `src/engine/` + unit test |
| 6–7 | Module 3: đánh giá | Bảng P/R/F1/FPR, ROC |
| 7–8 | Module 4: RPC proxy + replay + latency | PoC + số liệu độ trễ |
| 9–10 | Viết paper, Docker, slide, video | Bản thảo + artifact |

**Mốc quyết định cuối tuần 1**: nếu chi phí/quota cho BSC và L2 quá cao → giữ ETH đầy đủ, BSC/L2 giới hạn ở top địa chỉ và mẫu.

## 7. Việc làm ngay (tuần 1)
1. Tạo GCP project + bật BigQuery; lấy Etherscan API key và kiểm tra những chain được hỗ trợ.
2. Sửa code tác giả (D0) và test trên 6 địa chỉ đã biết.
3. Chuyển seed sang Parquet + manifest.
4. Pilot 500 địa chỉ, so sánh với CSV của tác giả.
5. Viết bản nháp codebook gán nhãn.
