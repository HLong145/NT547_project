# Datasheet — Address Misuse Dataset v1 / v2

Theo khung *Datasheets for Datasets* (Gebru et al., 2021). File và cột: [data/final/README.md](../data/final/README.md).
Phiên bản: v1, đóng băng 2026-10-23 (`data/final/MANIFEST.json` ghi sha256 từng file).
**Các mục 2–7 mô tả v1** (6.429 mẫu); v2 (6.547 mẫu, có N5 và dương D6) khác v1 ở mục 8 và thay thế v1 khi báo cáo số liệu.

## 1. Động cơ

- **Mục đích:** học trọng số và ngưỡng cho risk score R(A, C), đánh giá engine phát hiện address misuse và cảnh báo
  phía ví trên ETH và BSC, theo thời gian (không trộn quá khứ với tương lai).
- **Người tạo:** nhóm đề tài NT547, dựa trên dữ liệu công bố của Shao et al., "Lost in Blockchain: Address Misuse"
  (USENIX Security '26, Zenodo 17984167).
- **Kinh phí:** không có; dùng gói miễn phí của Etherscan / NodeReal / RPC công khai và quota BigQuery của nhóm.

## 2. Thành phần

- **Mỗi mẫu** là một cặp (địa chỉ đích, thời điểm xét `at`) trên một chain, nhãn 1 (misuse) hoặc 0 (bình thường).
  - 2.124 mẫu theo địa chỉ: thời điểm là một tx đi vào chọn ngẫu nhiên (tái lập được theo seed).
  - 4.305 mẫu theo tx: một tx thật, kèm hash, value, selector.
- **Quy mô:** 6.429 mẫu, 4.477 địa chỉ; 1.600 dương (KEY 300, ADDR 300, NCD 600, PCD 400), 4.829 âm.
- **Dương:** lấy mẫu phân tầng từ kết quả của tác giả (`seed/ca_misuse`, `seed/eoa_misuse`). Đây là **nhãn của luật
  tác giả**, chưa phải nhãn người. Tác giả đo precision trên ca đã phát hiện (RQ1); bộ nhãn vàng của nhóm (D5, 2 người
  gán, κ) đang làm.
- **Âm:** 7 nhóm N1–N4, N6–N8 (bảng trong README).
  - N5 (contract recovery chính thức, ví dụ PancakeSwap Recovery) **chưa có**.
  - Âm được kiểm tra không trùng dương của tác giả và không trùng địa chỉ suy ra từ key lộ.
- **Tập:**
  - train < 2023-02-10 ≤ val < 2023-10-05 ≤ test;
  - tập ngoài thời gian ≥ 2025-09-01;
  - một địa chỉ chỉ thuộc một tập;
  - 681 mẫu âm `excluded` (địa chỉ đã có ở tập sớm hơn, phần lớn là contract phổ biến như USDT);
  - 114 mẫu `no_time` (không có tx đi vào nào, không dùng để học hay đánh giá).
- **Thông tin cá nhân:** chỉ có địa chỉ và tx công khai trên chain, không có tên, email hay private key. Một số địa
  chỉ là ví cá nhân bị mất tiền; khi trích trong paper phải rút gọn (`0xabcd…1234`).
- **Không có:** private key, mnemonic, API key (QA quét chuỗi 64 hex và từ khoá bí mật).

## 3. Thu thập

| Phần | Nguồn | Ghi chú |
|---|---|---|
| Dương, loss | Dữ liệu Zenodo của tác giả → `seed/` | Lấy max giữa nguồn github/stackexchange như paper |
| Lịch sử tx ETH | v1: BigQuery `crypto_ethereum` (không có input). v2: txlist Etherscan cho mọi mẫu (có input) | Cửa sổ 1.000 tx trước `at` |
| Lịch sử tx BSC, quét block | NodeReal, Etherscan | Có input |
| Code, ngày tạo contract | `eth_getCode` 8 mạng, Etherscan `getcontractcreation` | Có cache trong `data/raw/` |
| Âm N2, N3, N8 | Quét block ngẫu nhiên 2020–2026 | 1 tx ngẫu nhiên mỗi block cho N8 |

- **Khoảng thời gian:** `at` từ 2016-08 đến 2026-10.
- **Đạo đức:** chỉ đọc dữ liệu thụ động. Không ký hay gửi giao dịch, không dùng key lộ.

## 4. Tiền xử lý và nhãn

- **Địa chỉ:** chữ thường, kèm cột EIP-55.
- **wei:** lưu dạng chuỗi.
- **Thời điểm `at`:**
  - NCD: chỉ chọn tx gọi hàm;
  - PCD: v1 chọn tx sau khi contract được tạo (sai, xem FINDINGS 2026-10-24 rà soát lần 2); v2 chọn tx gọi hàm
    TRƯỚC khi contract được tạo, đúng Rule 2 của tác giả;
  - N5 (v2): chỉ chọn tx sau khi contract recovery được tạo;
  - không có tx nào → `no_time`.
- **Lỗi đã biết trong loss của tác giả** (giữ nguyên số liệu tác giả, ghi chú riêng):
  - KEY trên ETH tính cả phân bổ genesis vào loss (cột `key_genesis_wei`);
  - phí gas tràn int64 ở 41 tx;
  - chi tiết trong `docs/FINDINGS_LOG.md`.
- **QA tự động:** `python -X utf8 -m address_misuse.freeze qa`. Lần chạy khi đóng băng: ĐẠT, 0 cảnh báo.

## 5. Cách dùng

- **Nên dùng cho:** học và chọn ngưỡng trên train/val, báo cáo trên test và ngoài thời gian. Chỉ dùng thông tin
  trước `at` (engine `FeatureStore.features(at=…)` đã tuân theo).
- **Không nên dùng cho:**
  - ước lượng tỉ lệ misuse ngoài thực tế, vì dương và âm được lấy mẫu theo nhóm chứ không theo tỉ lệ tự nhiên;
  - quy kết lỗi cho chủ ví cụ thể.
- **Lệch đã biết:**
  - v1: ETH thiếu input (BigQuery) nên IDM / T3 chỉ áp dụng trên BSC; v2 dùng txlist có input cho cả hai chain;
  - val nhỏ (75 tx N8), nên ngưỡng chọn trên val còn thô;
  - danh sách key lộ và OSINT không có mốc thời gian, nên coi như đã biết trước `at`.

## 6. Phân phối

- Chia sẻ cùng code của đề tài.
- Dữ liệu gốc của tác giả theo giấy phép Zenodo của họ.
- Dữ liệu thô (`data/raw/`) không phân phối, vì có thể tải lại bằng script và có cache.

## 7. Bảo trì

- **v1 cố định.** Mọi thay đổi tạo v2 với `sample_id` mới và MANIFEST mới.
- **Dự kiến cho v2:**
  - thêm dương mới từ D6 (sau 2025-09) vào tập ngoài thời gian;
  - thêm N5;
  - thêm nhãn vàng D5;
  - thêm đặc trưng OSINT từ D7;
  - lấy txlist ETH có input cho dương test.

## 8. Dataset v2 (khác v1)

Dựng bằng `python -X utf8 -m address_misuse.freeze` → `data/final/dataset_v2.parquet`, `splits_v2/`,
`MANIFEST_v2.json`. Cùng mốc chia tập, cùng QA, cộng các kiểm tra mới bên dưới.

- **Âm N5:** 118 contract recovery tại địa chỉ PCD (ETH 58, BSC 60). Chọn theo nhãn thủ công của tác giả (benign) hoặc
  theo tên đã verify, và loại trường hợp người deploy có key lộ.
  - 42 địa chỉ trong số này nằm trong mẫu dương PCD của v1 → chuyển sang âm N5. Đây là lỗi gắn cờ của tool tác giả.
  - QA ghi số này (`n5_flagged_by_author`) thay vì báo lỗi.
  - 14 mẫu chỉ dựa vào tên → `needs_review`.
- **Dương mới D6:** ETH, phát hiện bằng luật của nhóm trên dữ liệu từ 2025-09 (ADDR 38 qua EIP-7702, NCD 3, PCD 1).
  - `at` chỉ chọn trong tx từ 2025-09-01, nên thuộc tập ngoài thời gian. Trong cột `split` các mẫu này vẫn mang giá trị
    `test` (vì `at` ≥ 2023-10-05), tức `test` và `out_of_time` giao nhau. Báo kết quả theo `test_in_time`
    (`splits_v2/test_in_time.csv`, không trùng) và `out_of_time`, không báo `test` gộp.
  - Loss là phần misuse mới (`cost_wei_new`).
  - Tất cả có `needs_review`: luật của nhóm, chưa có nhãn vàng.
- **`key_value0`:** mẫu KEY mà tác giả không thấy đồng nào được gửi tới, chỉ có tx value 0.
  - Ở v1 có 140/163 KEY BSC và 18/159 KEY ETH như vậy, gần như tất cả sau EIP-7702.
  - Nên báo kết quả KEY cả có và không có nhóm này.
- **Lịch sử tx cho engine (không phải cột của dataset, nhưng ảnh hưởng số đánh giá):**
  - dương và âm cùng nguồn (txlist có input);
  - mọi mẫu chỉ xét 1.000 tx gần nhất trước `at`.
