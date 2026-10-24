# Dataset — Address Misuse (v1 đóng băng D8, v2 đang dựng)

> **v2** (`dataset_v2.parquet`, `splits_v2/`, `MANIFEST_v2.json`; `python -X utf8 -m address_misuse.freeze`) khác v1:
> - thêm âm **N5**: contract recovery chính thức tại địa chỉ PCD; những địa chỉ này bị bỏ khỏi dương PCD của tác giả,
>   vì tool tác giả gắn cờ nhầm;
> - thêm dương mới **D6**: ETH, luật của nhóm, `at` ≥ 2025-09-01;
> - thêm cột `label_source` (`author_rule` / `d6_rule` / `negative_group`);
> - thêm cột `key_value0`: KEY mà không có đồng nào được gửi tới, chỉ tx value 0;
> - thêm cột `needs_review`: dương D6 và N5 chỉ dựa vào tên, cần nhãn vàng D5;
> - lịch sử tx của engine: cùng nguồn cho dương và âm, 1.000 tx gần nhất trước `at`.
>
> `sample_id` của v2 là `v2-…`, không so khớp với v1. Phần dưới mô tả v1; v1 vẫn kiểm được bằng
> `python -X utf8 -m address_misuse.freeze qa --version v1`.


Bộ mẫu dùng để học trọng số, chọn ngưỡng và đánh giá engine cảnh báo (Module 2–4). Tạo lại và kiểm tra:

```
python -X utf8 -m address_misuse.freeze        # dựng lại + QA + ghi file
python -X utf8 -m address_misuse.freeze qa     # chỉ QA trên file đã có
```

Datasheet đầy đủ (mục đích, cách thu thập, hạn chế, đạo đức): [docs/DATASHEET.md](../../docs/DATASHEET.md).

## File

| File | Nội dung |
|---|---|
| `dataset_v1.parquet` | 6.429 mẫu, 4.477 địa chỉ (ETH + BSC), mọi cột bên dưới |
| `splits/train.csv`, `val.csv`, `test.csv` | Mẫu của từng tập (cột rút gọn) |
| `splits/out_of_time.csv` | Mẫu có `at` ≥ 2025-09-01 (tập test thứ hai) |
| `MANIFEST.json` | Mốc chia tập, số mẫu theo tập/chain/nhóm, kết quả QA, sha256 từng file |

## Cột

| Cột | Ý nghĩa |
|---|---|
| `sample_id` | `v1-00000`… (ổn định trong phiên bản v1) |
| `kind` | `address`: mẫu theo địa chỉ, thời điểm xét là một tx đi vào chọn ngẫu nhiên; `tx`: mẫu theo một tx thật |
| `grp` | Nhóm: dương `+KEY`, `+ADDR`, `+NCD`, `+PCD`; âm `-N1`…`-N8` (bảng dưới) |
| `subtype` | Loại misuse của mẫu dương (rỗng với âm) |
| `chain`, `address` | `eth`/`bsc`; địa chỉ đích, chữ thường |
| `address_checksum` | Cùng địa chỉ, dạng EIP-55 |
| `label` | 1 = misuse, 0 = bình thường |
| `at`, `at_utc` | Thời điểm xét (unix, UTC). Engine chỉ được dùng thông tin **trước** `at` |
| `split` | `train` / `val` / `test`; `excluded` = địa chỉ đã có ở tập sớm hơn; `no_time` = không có tx nào (không dùng) |
| `out_of_time` | `at` ≥ 2025-09-01 |
| `tx_hash`, `block_number`, `value_wei`, `selector` | Chỉ với `kind = tx` |
| `author_source`, `n_misuse_tx`, `loss_wei`, `loss_native` | Với dương: số liệu của tác giả (max giữa github/stackexchange như paper) |
| `key_genesis_wei` | KEY trên ETH: phân bổ genesis bị tác giả tính nhầm vào loss (khi `key_genesis` đã chạy xong) |

Giá trị wei lưu dạng chuỗi (vượt int64).

## Chia tập

Theo `at`: **train < 2023-02-10 ≤ val < 2023-10-05 ≤ test**, cộng tập **ngoài thời gian ≥ 2025-09-01**. Mốc là
phân vị 70/85% thời điểm tx đầu tiên của 34.480 dương CA. Một địa chỉ chỉ ở một tập (tập của mẫu sớm nhất).

| Tập | ETH (dương / âm) | BSC (dương / âm) |
|---|---|---|
| train | 414 / 1.200 | 438 / 1.137 |
| val | 96 / 157 | 70 / 113 |
| test | 255 / 761 | 225 / 768 |
| ngoài thời gian | 60 / 266 | 87 / 371 |

## Nhóm âm

| Nhóm | Nội dung |
|---|---|
| N1 | Địa chỉ ứng viên ngẫu nhiên mà tác giả không gắn cờ |
| N2 | Tx gọi contract bình thường |
| N3 | Tx gửi văn bản tới EOA (input là chữ đọc được) |
| N4 | Địa chỉ nạp tiền của sàn |
| N6 | Delegate EIP-7702 của ví hợp lệ |
| N7 | Contract đa chuỗi hợp lệ |
| N8 | Tx ngẫu nhiên trong block (nền bình thường, dùng đo báo nhầm) |

N5: contract recovery chính thức (PancakeSwap Recovery…) tại địa chỉ PCD. Chỉ có ở v2.

## QA tự động (lần chạy gần nhất: ĐẠT)

Khoá không trùng; địa chỉ đúng dạng + checksum khớp; nhãn khớp nhóm, không địa chỉ nào hai nhãn; không mẫu âm nào là
dương của tác giả hay địa chỉ suy ra từ key lộ; không địa chỉ nào ở hai tập; `split` khớp `at`; loss không âm và tính
lại khớp seed; không ô nào giống private key (chuỗi 64 hex ngoài cột hash) hay chứa từ khoá bí mật.
