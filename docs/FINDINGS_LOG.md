# Nhật ký phát hiện (dùng khi viết paper)

Ghi lại mọi quan sát có thể đưa vào paper, kèm cách tái tạo. Mới nhất ở trên.

## 2026-10-23 — Tái lập loss KEY bằng BigQuery: phân bổ genesis bị tính là thiệt hại; tràn int64 phí gas

Người gán A tái lập loss KEY (ETH) từ `data/raw/eth/bq_txs.parquet` (BigQuery, 22,4M tx), lệch 2/4.256 địa chỉ. Kiểm tra lại:

- **Phân bổ genesis bị tác giả tính là loss.** `0xf46b6b9c…aae782f6`: tác giả 24,19 ETH, BigQuery 3,29 ETH (tx vào, status 1).
  Etherscan `txlist` trả về bản ghi block 0, `from = GENESIS`, 21,0 ETH (phân bổ presale 2015), và BigQuery
  `transactions` không có. Luật KEY của tác giả (`txs_analyzer.analyze_EOAMisuse_for_KEY_txs`) cộng mọi tx vào có
  `isError == 0` và `from != addr`, nên tính cả bản ghi này. Chủ ví tự chuyển 20,99895 ETH đi ở block 210675,
  vậy đây không phải tiền nạp vào ví lộ key. Paper: loss KEY của tác giả bị thổi phồng ở các ví genesis. Cần đếm số ví
  KEY có bản ghi `GENESIS` (Etherscan, `endblock=0`) và trừ ra.
  Tái tạo: `Etherscan('eth').call('account','txlist',address=…,startblock=0,endblock=700000,sort='asc')`.
- **Tràn int64 khi tính phí:** `gas_price × receipt_gas_used` (cả hai int64 trong parquet) vượt 2^63 ở **41 tx**
  (33 địa chỉ đích): 25 tx thành số âm, **16 tx quay vòng thành số dương sai** (không lộ ra là âm). Đích là ví KEY: 2 tx /
  2 ví (`0x62730609…8bef57` phí thật 14,99 ETH, `0x8ad2f6fc…2371e9` 10,09 ETH); đích là CA misuse: 4 tx. Phí lớn là
  thật (gas price tới ~1,2M gwei), không phải dữ liệu rác. Sửa: nhân bằng số nguyên Python/Decimal cho mọi dòng, không
  vá riêng dòng âm.
- NCD/PCD: `bq_txs` không có cột `input` nên không chạy được luật tác giả; dùng tập con Etherscan
  (`reproduce_rules.py`, đã có cache 2.277 txlist ETH, 2.297 BSC).

## 2026-10-23 — D8 chốt chia tập (A + B); quét block 2020–2022; D6 BigQuery bước 1

**Quyết định D8** (người dùng duyệt, PLAN_V2 D8): mốc cũ cho test = 0 dương (dữ liệu tác giả dừng 07/2025).
- A — đánh giá chính: phân vị 70/85% thời điểm tx đầu tiên của 34.480 dương CA (theo năm: 2020 474, 2021 11.759,
  2022 11.035, 2023 7.351, 2024 3.350, 2025 495) → train < 2023-02-10 ≤ val < 2023-10-05 ≤ test, theo `at` của mẫu.
  Địa chỉ chỉ ở tập của mẫu sớm nhất (`engine/evaluate.assign_split`).
- B — test ngoài thời gian (≥ 2025-09-01): dương mới từ D6 + âm cùng giai đoạn.

**Âm cho giai đoạn train** (tái tạo: `negatives scan --period early` → `negatives from-scan` → `engine.prepare history`):
600 block ngẫu nhiên/chain 2020-01 → 2022-12 qua RPC NodeReal (ETH ~100k tx, BSC 96.049 tx; BSC bắt đầu từ
block 1 = 08/2020). Thêm N8 1.169, N2 800, N3 96 (văn bản tới EOA hiếm trước làn sóng inscription 2023).
Đợt "recent" không đổi (cùng seed).

**Kết quả theo tập** (trọng số 0,25, chưa học; AUC dương vs mọi âm cùng chain; `data/interim/engine_eval.log`):

| chain | train (dương/âm, AUC) | val | test | ngoài thời gian (dương/âm) |
|---|---|---|---|---|
| ETH | 414 / 1.200, 0,827 | 96 / 157, 0,893 | 255 / 761, 0,897 | 60 / 423 |
| BSC | 438 / 1.137, 0,818 | 70 / 113, 0,859 | 225 / 768, 0,975 | 87 / 529 |

Bỏ do trùng địa chỉ giữa tập: ETH 376, BSC 305 mẫu âm (đích phổ biến như USDT xuất hiện ở nhiều giai đoạn).
Không có `at` (không lịch sử): ETH 35 dương / 6 âm, BSC 67 / 6. AUC train thấp hơn test: train có nhiều âm
2020–2022 khó hơn và dương cũ hơn; cần xem lại sau khi học `w` (chưa kết luận).

**D6 bước 1 — BigQuery quota của nhóm** (`bq_fetch new-fetch`, job `eabe747a…`, **tính phí 118,7 GB**):
- Lần đầu lấy từng tx (ước lượng 196,7 GB) bị BigQuery từ chối `responseTooLarge` (> 10 GB kết quả), **0 GB tính
  phí**. Đổi sang gom một dòng thống kê mỗi địa chỉ (tx vào + tx ra), rẻ hơn.
- 4.989.536 ứng viên ETH chưa gắn cờ → 1.258.647 có tx từ 2025-09-01: 747.340 có tx vào (trung vị 3 tx), 360.356
  có tx gọi hàm vào, 1.067.624 có tx gửi đi, 61.502 gửi tx type 4 (EIP-7702). **141.348 nhận tx gọi hàm mà không
  tự gửi tx** (ứng viên NCD/PCD, cần getCode + creation rồi chạy `rules.py`).
- Địa chỉ lộ key (`candidate_pk_addresses`, 17.971) gần như không nằm trong `candidate_addresses` (46 ETH) nên
  chưa có trong truy vấn này → KEY mới cần truy vấn riêng (nhỏ).

## 2026-10-23 — Bước 2: tập âm N2/N3/N4/N8, lịch sử BSC, rà soát toàn bộ quy trình engine

**Dữ liệu mới** (tái tạo: `python -m address_misuse.engine.prepare sample` → `negatives scan --blocks 400` →
`negatives from-scan` → `negatives n4` → `engine.prepare history` → `negatives n4-verify` → `engine.evaluate`):
- Mẫu đánh giá cố định `engine_eval_sample.parquet` (seed 0): mỗi chain NCD 300, PCD 200, KEY 150, ADDR 150.
- Lịch sử BSC qua NodeReal `nr_getTransactionByAddress` cho 800 dương + N1 + N7 BSC (0 lỗi, không địa chỉ rỗng),
  và cho đích của N2/N3/N4/N8 trên cả hai chain (1.000 tx đầu). Đổi sang định dạng txlist Etherscan.
- Quét 400 block ngẫu nhiên mỗi chain (2023-01 → 2026-10; ETH 80.022 tx, BSC 44.088 tx):
  N8 = 1 tx ngẫu nhiên/block (400/chain); N2 = gọi contract bằng 30 selector hay gặp nhất trong tx tới địa chỉ NCD
  (approve, transfer, setApprovalForAll, transferFrom, mint, withdraw…; 400/chain); N3 = input là văn bản gửi tới
  EOA (ETH 400, BSC 240; 88% là inscription tự gửi `data:,{"p":"erc-20",…}`).
- N4: người gửi coin tới 6 ví nóng sàn (Binance 14/15/16, Coinbase 10, Binance BSC 6/7). Etherscan chặn đọc nhãn
  (HTTP 403), Blockscout không có nhãn → kiểm chứng bằng **hành vi**: ≥ 90% tx gửi đi là về hub và mang ≥ 90% coin
  đã nhận. Chỉ **83/400** người gửi đạt (ETH 37, BSC 46); phần lớn người gửi tới ví sàn là người dùng thường. Hub
  Binance 15/16 và Binance BSC 7 gần như không có địa chỉ nạp đạt → nhãn hub có thể sai hoặc không phải đích sweep.

**Kiểm tra nguồn dữ liệu tương đương:**
- BigQuery vs Etherscan, 579 địa chỉ pilot, cùng mốc block: các đặc trưng lịch sử trùng 98,8–100%, `n_sweep` 246 = 246.
- NodeReal vs Etherscan, 29 địa chỉ N1 ETH: `n_tx`, `n_in`, `n_in_call`, `call_senders`, `n_out` trùng 100%.
  Trước Byzantium (block < 4.370.000) NodeReal trả status 0 cho mọi tx; đã đổi sang quy ước của BigQuery
  (lỗi ⇔ dùng hết gas). Còn lệch 3 tx lỗi (Etherscan dùng trace).

**Lỗi tìm thấy khi rà soát (đã sửa):**
1. *BigQuery chỉ chứa tx của 35.664 địa chỉ đã truy vấn.* Địa chỉ khác (router, contract hạ tầng) có trong BigQuery
   một phần (chỉ tx với địa chỉ misuse) và bị lấy làm lịch sử: 30/200 N1 ETH, 14/18 N7. Nay chỉ dùng BigQuery cho
   đúng danh sách `bq_fetch.targets()`, còn lại dùng txlist.
2. *Thiếu bộ lọc IDM* (tin nhắn văn bản) trong S_bytecode: mọi tx gửi chữ tới EOA bị tính T1 = 1. Đã thêm.
3. *EIP-7702 không theo thời gian:* EOA đang ủy quyền hôm nay vẫn bị coi là 7702 (kể cả luật cứng delegate độc)
   khi xét thời điểm trước khi 7702 kích hoạt (ETH 2025-05-07, BSC 2025-03-20). Đã sửa (`EIP7702_ACTIVATION_TS`).
4. *Chọn `at` = tx đầu tiên sai cho PCD:* 87% PCD ETH chưa có code ở tx đầu tiên (contract được tạo sau), nên
   chấm như NCD-XC (S_cross 0,33 → 0,81) — đây là lý do R_at > R của PCD ở lần chấm trước. `engine/evaluate.py`
   chọn ngẫu nhiên **một tx misuse**: NCD = tx gọi hàm, PCD = tx sau khi contract được tạo; dương và âm cùng quy trình.
5. `history_source` khoá theo địa chỉ (lẫn ETH/BSC): nay khoá theo (chain, address).

**Hạn chế còn lại (cần nêu trong paper hoặc quyết định):**
- *KEY ≡ luật cứng:* 100% EOA KEY nằm trong tập lộ key (`candidate_pk_addresses`), ADDR chỉ 0,5–0,8%. Nhóm KEY chỉ
  đo luật cứng, không chứng minh R. Thời điểm lộ key không biết, nên luật này không theo thời gian.
- *Danh sách đen delegate dựng từ tập dương* → 17–22% ADDR dính luật cứng `malicious_delegate`. Phải dựng lại
  chỉ từ train.
- *OSINT:* mọi dương và N1 đều thuộc `candidate_addresses` (S_osint = 0,28), còn đích N2/N8 chỉ 0,10–0,26 (địa chỉ
  phổ biến như USDT cũng có trong code công khai). S_osint vì thế phân biệt một phần do **cách lấy mẫu**: AUC giảm
  0,01–0,17 khi bỏ S_osint. Cần tính OSINT cùng một quy trình cho mọi mẫu (D7).
- *BigQuery không có input:* ở mức địa chỉ chỉ biết "có calldata" (gas > 21.000), không chạy được IDM/T3 trong
  lịch sử; N3 ETH vẫn có S_history 0,22 do đếm tx văn bản là "gọi hàm".
- *Lịch sử hạ tầng bị cắt 1.000 tx đầu* (N6/N7, đích N2/N3/N8); NodeReal trả rỗng với vài contract rất lớn trên BSC.
- *Mốc chia D8 không dùng được:* tx đầu tiên muộn nhất của dương CA là 2025-07-22. Với mốc trong PLAN_V2
  (val từ lúc 7702 kích hoạt, test từ 2025-09-01): train 34.414, val 66, **test 0** địa chỉ có thời gian.
  Cần chọn lại mốc (chờ người dùng).

**Kết quả mô tả** (trọng số 0,25, chưa học, chưa chọn ngưỡng; 4.364 mẫu, `data/interim/engine_eval.log`):
trung vị R — NCD 57,1 (cả hai chain), PCD 31–32, KEY 25–37,5, ADDR 7,1; N1 7,1; N2 14,7–15,0; N3 0; N4 0;
N7 15,2–15,4; N8 1,0 (BSC) / 14,7 (ETH). AUC dương vs từng nhóm âm cùng chain: 0,75–1,00 (ETH: N1 0,89, N2 0,80,
N3 0,90, N4 1,00, N6 0,83, N7 0,75, N8 0,85; BSC: N1 0,89, N2 0,87, N3 1,00, N4 1,00, N7 0,79, N8 0,93).
ADDR gần như không tách được khỏi N1 bằng R (trung vị bằng nhau): thông tin chỉ nằm ở luật cứng và lịch sử.

## 2026-10-22 — Engine risk score chạy thử; delegate EIP-7702 của sweeper đã đổi sau snapshot tác giả

**Chấm thử** `address_misuse.engine` (at = hôm nay, w = 0,25 mỗi thành phần) trên 1.181 mẫu: NCD/PCD/KEY/ADDR mỗi chain + N1, N6, N7. Offline 1,7 ms/mẫu; getCode 8 mạng cho 662 địa chỉ ngoài ma trận mất 3 s. Trung vị R:

| Nhóm | ETH | BSC |
|---|---|---|
| +NCD | 57,1 | 44,6 |
| +PCD | 28,5 | 32,1 |
| +KEY (luật cứng lộ key 100%) | 32,5 | 32,5 |
| +ADDR | 16,9 | 14,6 |
| −N1 | 19,6 | 19,6 |
| −N6 / −N7 | 7,5 / 15,0 | – / 14,6 |

Chưa phải kết quả đánh giá (trọng số chưa hiệu chỉnh, chưa theo thời gian), chỉ để kiểm tra code. Lộ ra các vấn đề cần sửa trước khi đánh giá (RISK_SCORE.md §6).

**Delegate 7702 đã đổi:** getCode hôm nay cho 260 EOA trong `eip7702_delegations` của tác giả (mẫu ở trên):

| Chain | Nhóm | n | Vẫn đang 7702 | Delegate trùng bản tác giả ghi | Delegate hiện tại có trong tập delegate tác giả |
|---|---|---|---|---|---|
| BSC | ADDR | 74 | 100% | 0% | 0% |
| BSC | KEY | 56 | 100% | 26,8% | 42,9% |
| ETH | ADDR | 69 | 98,6% | 0% | 0% |
| ETH | KEY | 61 | 100% | 0% | 8,2% |

- Các EOA vẫn bị ủy quyền nhưng đã chuyển sang delegate khác (13 delegate hiện tại; nhiều nhất `0x0727ca41…` 51 EOA, `0xa19160b1…` 39).
- Hệ quả: danh sách đen delegate tĩnh lỗi thời rất nhanh. Phía ví cần phân tích delegate lạ (symexec / hành vi), không chỉ tra danh sách. Khi đánh giá theo thời gian phải dùng delegate tại thời điểm `at`, không phải delegate hôm nay.

**Sau khi sửa 4 vấn đề (2026-10-23)**, chấm lại cùng 1.181 mẫu (at = hôm nay, 4,0 ms/mẫu): trung vị R của N1 ETH giảm từ 19,6 xuống **7,1** (đã có lịch sử, S_bytecode 0,46 → 0,12); S_cross của N7 về 0; ADDR tăng lên 19,6–21,9 (delegate mới có symexec, S_bytecode 0,3 → 0,5). ADDR BSC (19,6) vẫn trùng N1 BSC (19,6): BSC chưa có lịch sử tx nên S_history = 0 cho mọi mẫu BSC. Chế độ theo thời gian (at = tx đầu tiên tới địa chỉ): NCD ETH giảm từ 57,1 xuống 44,6 vì không còn dùng lịch sử sau thời điểm xét.

**Hash bytecode quá chặt cho N7:** Uniswap V2 Router `0x7a25…488d` có code trên BSC nhưng hash khác ETH (immutable như địa chỉ WETH khác nhau), nên bị tính PCD-XC (R = 22). Cần so tập selector thay vì hash.

## 2026-10-22 — D1 ETH: `bq_txs.parquet` từ BigQuery đầy đủ, khớp Etherscan

File `data/raw/eth/bq_txs.parquet` (bạn chạy `bq_fetch fetch`, 1,49 GB, không có `input`/`hash`). Kiểm tra trên máy này:

- 22.397.803 tx, không trùng khoá `(block_number, transaction_index)`; từ 2015-08-07 đến **2026-10-20** (block 26.234.257).
- Phủ **35.664/35.664** địa chỉ ETH mục tiêu (CA + EOA của tác giả), mọi địa chỉ đều có tx.
- Số tx ≥ `n_tx` của tác giả ở 100% địa chỉ trừ 4, mỗi địa chỉ thiếu đúng 1: đó là bản ghi **GENESIS** (phân bổ ở block 0) mà Etherscan liệt kê như một tx, BigQuery thì không.
- Đối chiếu tập tx với txlist Etherscan của 579 địa chỉ pilot (bỏ 1 bị cắt ở 100k, chỉ xét block ≤ 26.234.257): **578/579 khớp từng tx**; địa chỉ còn lại chỉ khác ở bản ghi GENESIS. Không có tx nào BigQuery có mà Etherscan không có.
- Kết luận: có thể dùng `bq_txs` thay Etherscan cho mọi đặc trưng không cần `input` (S_history, N2–N4, chia thời gian D8) trên toàn bộ ETH.

## 2026-10-21 — Pilot rule mở rộng: EOA ADDR và CA lớn (n_tx > 5.000) cũng khớp tác giả 100%

`python -m address_misuse.reproduce_rules --chain eth --n-ncd 350 --n-pcd 100 --n-key 50 --n-addr 50 --n-big 30` (seed 0, 458 s, kết quả `data/interim/rules_repro_eth.parquet`, log `data/interim/reproduce_rules_2026-10-21.log`). 580 địa chỉ; 500 mẫu pilot cũ được chọn lại y hệt.

| Tầng | Subtype | n | Snapshot khớp chính xác | Loss (ETH) tác giả = mình | Hiện tại khớp chính xác | Lệch loss hiện tại |
|---|---|---|---|---|---|---|
| pilot | NCD | 350 | 100% | 309,460 | 94,3% | +0,00% |
| pilot | PCD | 100 | 100% | 230,343 | 100% | +0,00% |
| pilot | KEY | 50 | 100% | 39,955 | 50,0% | +0,23% |
| addr | ADDR | 50 | 100% | 1,680 | 100% | +0,00% |
| big | NCD | 27 | 100% | 21,384 | 92,6% | +0,05% |
| big | PCD | 3 | 100% | 0,027 | 100% | +0,00% |
| **Tổng** | | **580** | **100%** | **602,850** | | **+0,02%** |

- **Snapshot** = chỉ dùng n_tx đầu tiên như lúc tác giả kéo dữ liệu; **hiện tại** = toàn bộ tx đến hôm nay (KEY lệch nhiều nhất vì sweeper vẫn tiếp tục hoạt động).
- 1 địa chỉ bị cắt ở 100k tx; 1 địa chỉ có n_tx lúc kéo < n_tx của tác giả.
- **Giới hạn của ADDR:** rule ADDR cần "delegate độc", mình coi là thoả vì mọi EOA ADDR đều có trong `eip7702_delegations` của tác giả; số dư snapshot lấy từ dữ liệu tác giả. Nên 100% ở đây xác nhận phần đếm tx/tính loss, **không** xác nhận độc lập việc nhận diện delegate độc (FINDINGS_LOG 2026-10-19: `flag` = symexec).
- Kết luận: rule của Shao et al. tái lập đầy đủ trên ETH cho cả 4 subtype và cả nhóm n_tx lớn.

## 2026-10-20 — D3 timing BSC qua NodeReal (`crosschain_matrix timing`, `build`)

Nguồn: NodeReal MegaNode free, `nr_getTransactionByAddress` (`category=[external]`, `order=asc`, `maxCount=1`), 16.562 địa chỉ BSC trong ~5 phút, 0 lỗi. (Moralis đòi gói $149+, BigQuery không có dataset BSC, Blockscout/Ankr không dùng được.)

| Chain bị misuse | NCD/PCD-XC có timing | deployed_before | deployed_after | unknown |
|---|---|---|---|---|
| BSC | 16.562 | 16.366 (98,8%) | 196 | 753 |
| ETH | 17.918 | 17.635 (98,4%) | 283 | 1.355 |

Khoảng cách (tx đầu − deploy ở chain khác), BSC: trung vị 32 ngày, p10 0, p90 443. Kết luận như ETH: gần như mọi ca NCD/PCD-XC đã có contract ở chain khác trước khi địa chỉ nhận tx đầu tiên, tức cảnh báo cross-chain có thể đã bắn được từ đầu. Lưu ý: tx đầu tiên chỉ tính tx `external` (không tính tx nội bộ); ngày deploy dùng trạng thái hiện tại.

## 2026-10-19 — `flag` delegate 7702 của tác giả là kết quả symexec, không phải nhãn độc; tập âm N1, N6

**`eip7702_delegate_stats.flag` trùng khớp hoàn toàn với symexec** (`symexec_results`, kind = eip7702_delegate):

| flag | Ý nghĩa | Số delegate |
|---|---|---|
| 1 | có ít nhất một đường `transfer_*` | 89/89 |
| 0 | không có đường chuyển tiền | 2 |
| -1 | chưa phân tích | 10 |

- `symexec_results` (kind = eip7702_delegate) là **mọi delegate đã phân tích**, không phải tập delegate độc. Delegate hợp lệ của MetaMask `EIP7702StatelessDeleGator` (`0x63c0…dae32b`) có mặt với flag 1 (BSC, 1 EOA ADDR).
- Mọi 17.326 lần ủy quyền trong dữ liệu tác giả đều đến từ EOA KEY/ADDR, nên dữ liệu tác giả không có EOA 7702 lành tính để làm mẫu âm.
- Hệ quả cho paper: "có đường chuyển tiền" không đủ để kết luận delegate độc (smart wallet nào cũng chuyển được tiền). Phải kết hợp danh sách ví hợp lệ đã kiểm chứng và luồng tiền thực tế. Đây cũng là một nguồn FP cần đo khi đánh giá.

**N6, delegate 7702 hợp lệ** (`python -m address_misuse.negatives n6` → `data/interim/n6_benign_7702_delegates.parquet`): giữ 5/5 ứng viên. Tên contract đã verify được kiểm tra qua Blockscout API (không cần key), và cả 5 đều có code trên ETH.
- MetaMask `EIP7702StatelessDeleGator`
- Coinbase `EIP7702Proxy`
- Uniswap `CaliburEntry`
- `Simple7702Account` (eth-infinitism)
- Ambire `AmbireAccount7702`

**N1, địa chỉ ngẫu nhiên không bị gắn cờ** (`python -m address_misuse.negatives n1 --per-chain 200 --seed 0` → `data/interim/n1_random_unflagged.parquet`): 400 địa chỉ lấy từ `candidate_addresses`, loại mọi địa chỉ có trong `ca_misuse`/`eoa_misuse`.

| Chain | none | code | 7702 |
|---|---|---|---|
| ETH | 174 | 21 | 5 |
| BSC | 140 | 51 | 9 |

14/400 (3,5%) địa chỉ ngẫu nhiên lấy từ code công khai **hiện đang ủy quyền EIP-7702**. Cảnh báo phía ví không thể coi mọi EOA 7702 là đáng ngờ.

**Pilot D5 làm mù lại:** trước đây một số cột bằng chứng chỉ được điền ở vài tầng, nên người gán đoán được tầng:
- `xc_timing` có ở mọi địa chỉ thuộc ma trận misuse;
- `delegate_7702` chỉ có ở EOA của tác giả;
- `symexec_*` chỉ có ở PCD;
- N7 thiếu `xc_nets`.

Bản mới tra `getCode` cho mọi mẫu. Symexec chạy bổ sung cho 12 contract chưa có kết quả của tác giả: 1 bị kill vì OOM, 3 hết timeout 120 s. Cột nguồn gốc/thời điểm chỉ được điền ở tình huống T4. Một mẫu `t4_xc_after` trên ETH nay đã có code ngay trên ETH: trạng thái hiện tại khác với lúc bị misuse.

## 2026-10-17 — D3 bổ sung creation trên BSC qua Binplorer (`crosschain_matrix origin/timing/build`)

Lấy creation cho 13.472 contract trên BSC qua Binplorer `getAddressInfo` (key riêng), sau đó chạy lại timing và build. Phần lớn ETH-NCD-XC có contract nằm trên BSC, nên chỗ "unknown" phía ETH giờ đã được lấp.

**Timing trên ETH misuse** (19.273 địa chỉ XC; trước đây chỉ tra được 5.132):

| Nhãn | deployed_before | deployed_after | unknown |
|---|---|---|---|
| NCD-XC | 17.221 (538,9 ETH, 385.818 tx) | 232 (25,9 ETH) | 1.329 |
| PCD-XC | 414 (482,9 ETH) | 51 (10,3 ETH) | 26 |

- **98,4% (17.635/17.918) ca đã biết thời điểm có contract ở chain khác trước tx đầu tiên trên ETH**, tương đương 91,5% tổng số XC. Riêng contract gốc trên BSC: 13.395/13.486 (99,3%). Kết quả trước (90,9%) đúng là cận dưới.
- deployed_after chủ yếu đến từ sepolia (82/320) và arb (62); khi đó địa chỉ trên ETH bị dùng trước, nên theo codebook các ca này là T1 chứ không phải T4.
- Khoảng cách tx đầu − deploy: trung vị 39 ngày (p10 1, p90 414); 6,9% trong 1 ngày, 23,1% trong 7 ngày, 44,8% trong 30 ngày.
- Còn 1.355 unknown, phần lớn vì contract gốc nằm trên OP/Base/BSC testnet (`no_creation_api`, 1.438 dòng).

**Khả năng deploy lại** phía ETH misuse (trước: unknown 14.955): claimable 11.293 (308,0 ETH), burned 3.112 (205,8 ETH), already_deployed 527 (492,5 ETH), factory có / không có trên ETH 1.172 / 1.597, unknown 1.572.

- **Hạn chế:** timing phía BSC misuse vẫn là unknown, vì chưa có nguồn miễn phí lấy tx đầu tiên trên BSC. Đã thử ngày 2026-10-17:
  - Etherscan free không hỗ trợ BSC.
  - Ankr công khai bắt buộc key.
  - Binplorer `getAddressTransactions` bỏ tx giá trị 0 và không có `input`/`gasUsed`.
  - RPC công khai chặn receipt cũ (cần token archive).

## 2026-10-16 — D3 thời gian: contract ở chain khác có trước lúc misuse không (`crosschain_matrix timing`)

So `first_create_ts` (thời điểm deploy sớm nhất **đã biết** ở mạng khác, từ Etherscan creation) với tx đầu tiên tới địa chỉ trên chain bị misuse (Etherscan `txlist` asc). Chỉ làm được cho **misuse trên ETH** có creation ở arb/polygon/sepolia/eth: 5.132 địa chỉ, 0 lỗi. Misuse trên BSC: chưa có nguồn lịch sử tx BSC miễn phí.

| Nhãn | deployed_before | deployed_after | unknown |
|---|---|---|---|
| NCD-XC | 4.538 (249,1 ETH, 186.678 tx) | 377 (29,9 ETH) | 13.867 |
| PCD-XC | 128 (304,8 ETH) | 89 (10,1 ETH) | 274 |

- **90,9% (4.666/5.132) contract đã tồn tại ở chain khác trước tx đầu tiên trên ETH** → bằng chứng trực tiếp cho Type 4: người dùng dùng một địa chỉ contract có thật của chain khác, không phải địa chỉ ngẫu nhiên.
- Khoảng cách tx đầu − deploy: trung vị 45 ngày (p10 0, p90 441). 8% trong vòng 1 ngày, 21% trong 7 ngày, 38% trong 30 ngày → nhiều ca xảy ra ngay sau khi dự án deploy đa chain (có thể chính đội dự án/người tích hợp gửi nhầm). Cần kiểm tra người gửi tx đầu có trùng deployer không.
- Hạn chế: `first_create_ts` chỉ là mốc sớm nhất **đã biết** (thiếu BSC/OP/Base) nên tỉ lệ deployed_before là **cận dưới**. "tx đầu tiên" là mọi tx tới địa chỉ, không riêng tx misuse (với NCD gần như trùng nhau).

## 2026-10-16 — Tập âm N7 (`python -m address_misuse.known_multichain`)

Có 18 contract hạ tầng hợp lệ deploy cùng địa chỉ trên nhiều chain: các factory CREATE2, Multicall3, Permit2, Safe, EntryPoint 4337, 1inch, 0x, Seaport.
- Cả 18 đều có code trên ≥ 6/8 mạng, và không cái nào nằm trong dữ liệu misuse của tác giả.
- Permit2, 1inch, 0x, Seaport có bytecode **khác nhau** giữa các chain (lưu chainId/immutable trong bytecode). Vì vậy detector không được đòi bytecode giống hệt nhau.
- Đã chạy lại sau khi gộp code (dùng `rpc_batch` + `_code_record`): kết quả giống hệt.
- File kết quả: `data/interim/n7_multichain_contracts.parquet`.
- Danh sách còn nhỏ; cần mở rộng từ dữ liệu, ví dụ lấy các contract được gọi nhiều trên ETH mà cũng có mặt ở chain khác (BigQuery).

## 2026-10-16 — Ma trận cross-chain D3 (`python -m address_misuse.crosschain_matrix all`)

Toàn bộ địa chỉ CA misuse (45.633 địa chỉ, 49.344 cặp (chain, địa chỉ), bỏ trùng bằng giá trị lớn nhất) × 8 mạng, `eth_getCode` block mới nhất, 0 lỗi. Nguồn gốc contract ở mạng khác: Etherscan `getcontractcreation` (gói free: eth/arb/polygon/sepolia), nonce CREATE suy cục bộ từ `create_address(creator, n)`. Kết quả: `data/interim/crosschain_matrix.parquet`.

| Chain bị misuse | Nhãn | Địa chỉ | % địa chỉ | % thiệt hại |
|---|---|---|---|---|
| BSC (21.775, 8.681 BNB) | NCD-XC | 16.819 | 77,2% | 18,9% |
| | NCD-Other | 4.380 | 20,1% | 67,6% |
| | PCD-XC | 496 | 2,3% | 13,0% |
| | PCD-Other | 80 | 0,4% | 0,4% |
| ETH (27.569, 22.738 ETH) | NCD-XC | 18.782 | 68,1% | 3,1% |
| | NCD-Other | 8.201 | 29,7% | 81,5% |
| | PCD-XC | 491 | 1,8% | 2,2% |
| | PCD-Other | 95 | 0,3% | 13,2% |

- **Type 4 phổ biến theo số địa chỉ, nhưng không theo thiệt hại**: đa số địa chỉ CA misuse là contract ở chain khác, nhưng thiệt hại tập trung ở NCD-Other. Phù hợp pilot top-100 (ETH 2/100): ca lớn nhất ít khi là XC. Chỉ ~10–13% NCD-XC có value > 0, còn lại chỉ mất gas.
- Hầu hết chỉ có code ở đúng một mạng khác, chủ yếu ETH ↔ BSC (BSC misuse: eth 13.223; ETH misuse: bsc 13.492). Bytecode rất đa dạng (top 10 chỉ phủ 6–10%).
- Trạng thái hiện tại trên chính chain bị misuse: BSC none 20.951 / code 667 / 7702 157; ETH none 26.536 / code 722 / 7702 311.
- **Khả năng deploy lại ở đúng địa chỉ** (NCD/PCD-XC, so nonce deployer trên chain bị misuse với nonce lúc tạo):

| | BSC misuse | ETH misuse |
|---|---|---|
| claimable (nonce chưa vượt) | 11.515 (1.000 BNB) | 2.224 (63,9 ETH) |
| burned (nonce đã vượt) | 2.377 (469 BNB) | 1.224 (129,7 ETH) |
| already_deployed | 494 (1.049 BNB) | 102 (250 ETH) |
| factory có / không có trên chain misuse | 607 / 1.507 | 220 / 548 |
| unknown | 815 | 14.955 |

  → Trên BSC, phần lớn địa chỉ bị dùng nhầm vẫn có thể được deploy lại bởi đúng chủ contract: đây là hướng giảm thiểu cụ thể (chủ dự án chiếm trước địa chỉ). Đồng thời là rủi ro: ai nắm key deployer có thể deploy contract khác ở địa chỉ người dùng đang gửi nhầm.
- Hạn chế: ETH misuse có 14.955 unknown vì contract tương ứng nằm trên BSC, mà Etherscan free không cấp creation cho BSC/OP/Base. Trạng thái code là hiện tại, chưa đối chiếu với thời điểm misuse. Tìm nonce giới hạn 200.000 (19 ca không tìm thấy).
- **Kiểm tra độc lập:** một lần quét `eth_getCode` thứ hai, do người khác viết code riêng và chạy trên máy khác, cho đúng cùng số NCD-XC: 16.819 (BSC) và 18.782 (ETH). Kiểm tra chéo thêm:
  - 600 địa chỉ ngẫu nhiên trên eth/bsc/polygon: 0 có code, tức RPC không báo nhầm;
  - 50 ca ETH-NCD có code trên BSC, kiểm lại bằng RPC của Binance: khớp 49/50.
- Kỹ thuật: RPC công khai (publicnode) trả `null` cho đa số `eth_getTransactionByHash` tx cũ trên arb/polygon (không đánh chỉ mục tx lịch sử) → không dùng được để lấy nonce; suy cục bộ nhanh hơn (13 s cho 17.287 cặp).

## 2026-10-15 — Pilot tái lập rule trên 500 địa chỉ ETH (`python -m address_misuse.reproduce_rules`)

350 NCD + 100 PCD + 50 KEY (seed 0, n_tx ≤ 5.000), tx lấy lại qua Etherscan V2. Kết quả: `data/interim/rules_repro_eth.parquet`.

- **Chế độ snapshot** (chỉ n_tx tx đầu, như lúc tác giả thu thập): **khớp 500/500 đến từng wei** (tổng 579,759 ETH) → rule port (gồm lỗi B1/B2 qua `paper_compat`) tái lập đúng.
- **Dữ liệu hiện tại**: tổng thiệt hại +0,02%. 20 NCD có thêm 98 tx misuse; 2 NCD đã thành PCD (`0xd392…83fa`, `0xea92…527d`); 24/50 KEY nhận thêm 238 tx. Tổng số tx: NCD 52.254 → 54.572, PCD 37.274 → 60.607.
- ⇒ Misuse vẫn đang tiếp diễn sau thời điểm thu thập của paper; nhãn NCD/PCD thay đổi theo thời gian, nên dataset cần ghi rõ thời điểm.
- Hạn chế: 156/500 lệnh getCode kiểm tra EIP-7702 lỗi do RPC công khai bị dùng chung với D3 (chỉ ảnh hưởng chế độ hiện tại).

## 2026-10-12 — Tái lập symbolic execution (`python -m address_misuse.reproduce_symexec`)

344 contract: tất cả delegate EIP-7702 và logic proxy, cộng mẫu 150 địa chỉ misuse (seed 0). Timeout mềm 120 s; giới hạn RAM 400 MB, lượt chạy lại 850 MB. Kết quả: `data/interim/symexec_repro.parquet`.

- Kết quả cuối: 307/344 chạy được, 37 vượt 850 MB RAM. Trên 246 contract chạy xong trong thời hạn: **khớp 100%** với tác giả ở cả 4 cờ (delegatecall, transfer_all_eth, transfer_msg_value, transfer_input_amount) → engine port sang Windows đúng. Gộp cả contract hết thời gian (n=307): delegatecall 99,7%, transfer_all_eth 99,0%, transfer_msg_value 99,3%, transfer_input_amount 99,7%.
- Lệch chỉ xảy ra ở contract hết thời gian, và luôn theo một chiều: tác giả = 1, mình = 0 (dừng sớm nên bỏ sót). transfer_all_eth lệch 3 contract, transfer_msg_value 2, delegatecall 1, transfer_input_amount 1.
- Chi phí: logic proxy rất tốn RAM (nhiều contract cần > 850 MB). Hạn chế này cần nêu khi dùng symexec trong engine thời gian thực → symexec chỉ chạy offline, còn kết quả thì lưu vào danh sách tính sẵn.

## 2026-10-12 — Pilot cross-chain (`python -m address_misuse.crosschain_pilot --top 100`)

Top 100 địa chỉ NCD theo thiệt hại mỗi chain, `eth_getCode` (block mới nhất) trên 8 mạng: eth, bsc, arb, op, base, polygon, sepolia, bsc_testnet. Kết quả: `data/interim/crosschain_pilot.parquet`.

| Chain bị misuse | Là contract ở ≥ 1 chain khác | Phần thiệt hại | Chain có contract |
|---|---|---|---|
| BSC | 36/100 | 13% | eth 31, bsc_testnet 5, arb 4, polygon 4, op 3, base 2 |
| ETH | 2/100 | ~0% | op/base (`0x4200…0006`, WETH predeploy của OP-stack), bsc (`0x…1004`, system contract BSC) |

- Ví dụ BSC: Uniswap V3 SwapRouter `0xe592…1564` (13.310 tx, 186 BNB), SwapRouter02 `0x68b3…fc45` (8.418 tx, 143 BNB), CryptoPunks `0xb47e…3bbb`, WETH `0xc02a…6cc2`, router testnet `0x9ac6…e5c3`.
- **Bất đối xứng ETH ↔ BSC**: người dùng BSC hay dùng nhầm địa chỉ của Ethereum; còn NCD lớn trên ETH hầu như không là contract trên các chain đang hoạt động → nguồn gốc khả năng cao là **testnet đã ngừng** (Ropsten, Rinkeby, Kovan, Goerli), không truy vấn được bằng RPC. Cần nguồn khác: ngữ cảnh GitHub (D7) hoặc dữ liệu lưu trữ của testnet.
- Hạn chế: trạng thái hiện tại, chưa xét contract được deploy trước/sau thời điểm misuse; mẫu nhỏ.

## 2026-10-12 — Kiểm tra từng ca bằng `python -m address_misuse.crosschain`

- `0x7a25…488d` (Uniswap V2 Router02 của ETH) bị misuse trên **BSC**: 30.124 tx, 669,6 BNB (PCD). Hiện có cùng bytecode 17.944 B trên bsc/arb/op/polygon (đã được deploy về sau).
- `0x10ed…024e` (PancakeSwap Router của BSC) trên ETH: hiện có Recovery contract (6.759 B).
- ⇒ Ca lịch sử nổi tiếng **không** còn thấy được bằng trạng thái hiện tại. Cảnh báo phía ví dùng trạng thái hiện tại là đúng; gán nhãn lịch sử phải dùng block deploy.
- Hardhat #0 `0xf39f…2266`: đang ủy quyền EIP-7702 cho `0x8a67…408a` trên eth/bsc/arb/base/polygon — **khác** delegate `0x0E04…4647` nêu trong paper → danh sách delegate thay đổi nhanh, cần cập nhật định kỳ.
- Độ trễ RPC công khai từ máy nhóm: ~0,9–1,3 s mỗi lệnh, có lúc 8–9 s. Mục tiêu < 150 ms cần cache + RPC riêng + timeout ngắn.

## 2026-10-12 — Chuẩn hoá dữ liệu tác giả (`python -m address_misuse.seed`, `tests/test_seed.py`)

- Mọi con số khớp Bảng 1, 3, 4, §6.1 khi bỏ trùng bằng **giá trị lớn nhất** mỗi địa chỉ giữa hai nguồn.
- Paper ghi địa chỉ ca Aave là `0x580D…375c8`; đúng là `0x580d4fdc4bf8f9b5ae2fb9225d584fed4ad5375c` (PCD, 2 tx, 2.580,0 ETH).
- `eip7702_delegate_stats.flag` không khớp số contract độc trong paper (ETH 48 vs 49, BSC 41 vs 50).
- `symexec_results.self_destruct` trống ở 1.320/1.325 kết quả.
- 0% địa chỉ EOA_MISUSE và 0,8% CA_MISUSE của tập 10k cũ nằm trong dữ liệu tác giả (tập 10k đã bỏ).

## 2026-10-12 — Lỗi trong code tác giả (đã port sang `src/address_misuse/`)

| # | Vị trí gốc | Lỗi | Xử lý |
|---|---|---|---|
| B1 | `txs_analyzer.get_CAMisuse_loss` | `len != 10 or len != 74` luôn đúng → mọi tx selector `0xffffffff` bị bỏ | Giữ mặc định (`paper_compat=True`), có bản sửa |
| B2 | `analyze_EOAMisuse_for_ADDR_txs` | không dừng sau khi khớp → một tx nạp có thể bị cộng loss nhiều lần | như trên |
| B3 | `code_fetcher.worker_for_get_code`, `run_sym.py` | `CodeFetcher(etherscan_api)` truyền key vào tham số `chain` → luôn lỗi | `etherscan.py` |
| B4 | `symbolic_executor.Timeout` | dùng `SIGALRM`, không chạy trên Windows | deadline theo basic block |
| B5 | `txs_fetcher`, `code_fetcher` | Etherscan API V1 / BscScan riêng | API V2 `chainid` |
| B6 | thiếu file | `api_config.py`, `requirements.txt` không được công bố; `analysis.py` rỗng | `.env`, `requirements.txt` |
| N1 | rule NCD | dựa vào `functionName` của Etherscan → dữ liệu BigQuery/RPC không có, cần nguồn chữ ký hàm | ghi chú |
| N2 | rule PCD | loại địa chỉ nếu nó từng gửi tx — sai với EOA đã ủy quyền EIP-7702 | ghi chú |
| N3 | paper vs code | paper: `tx.gas < 30000`; code: `gasUsed <= 30000` | theo code |
