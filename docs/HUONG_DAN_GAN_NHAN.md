# Hướng dẫn gán nhãn (pilot 50 mẫu)

Tóm tắt một trang cho người gán nhãn. Định nghĩa đầy đủ và các ca khó: [CODEBOOK.md](CODEBOOK.md) (đọc §3, §4, §5 trước khi bắt đầu).

## Mục đích

Detector cần "đáp án do người chấm" để đo độ chính xác. Hai người gán **độc lập**, rồi đo mức đồng thuận bằng Cohen's κ (mục tiêu κ ≥ 0,8). Pilot 50 mẫu dùng để tìm chỗ codebook còn mơ hồ trước khi gán ~2.000 mẫu.

## Chuẩn bị

1. Mở `data/gold/pilot50_items.csv` (50 địa chỉ kèm bằng chứng) để xem.
2. Copy `data/gold/annotator_template.csv` thành `annotator_A.csv` (người thứ hai: `annotator_B.csv`) và điền vào file này.
3. **Không** mở `pilot50_key.csv` (đáp án ẩn). **Không** trao đổi với người gán kia cho tới khi cả hai nộp xong.

## Một mẫu = một cặp (chain, địa chỉ)

Câu hỏi: *người dùng gửi giao dịch tới địa chỉ này, trên chain này, có bị dùng sai không, và loại nào?* Chỉ xét chain ghi trong mẫu.

## Quy trình cho mỗi mẫu

1. Nhìn cột `code_<chain của mẫu>` trong `pilot50_items.csv`:
   - `none` (không có code) → bước 2.
   - `code` (có contract) → bước 3.
   - `7702` hoặc ví thường → bước 4.
2. **Không có code.** Mở `explorer_url`, xem các tx tới địa chỉ. Có lời gọi hàm (Method có tên hàm, Input Data dài) không?
   - Không: chỉ chuyển tiền thường, xem bước 4.
   - Có, và `xc_timing = deployed_before` (`xc_nets` không rỗng) → **T4**, ghi `xc_chain`.
   - Có, và `xc_timing = deployed_after` → **T1**, ghi note.
   - Có, và không có contract ở chain khác (hoặc `xc_timing = -` mà mở explorer chain kia vẫn không thấy) → **T1**.
   - `xc_timing = -` nhưng mạng khác có code: mở explorer mạng đó xem tx tạo contract; vẫn không biết thì **T4** với `confidence = low`.
3. **Có contract.** Đúng contract người dùng định gọi và gọi đúng hàm → âm (`is_misuse = 0`, `type = NONE`). Contract hạ tầng deploy cùng địa chỉ trên nhiều chain (Multicall, Permit2, Safe…) cũng là âm. Contract giữ tiền, `symexec_*` toàn `False` (không có đường rút) → **T2**.
4. **Ví EOA.** Key lộ công khai, hoặc tiền bị rút gần như ngay lập tức về ví lạ, hoặc delegate 7702 độc → **T5**. Ví thường, ví sàn, smart wallet hợp lệ (7702 hợp lệ) → âm.
5. Điền `confidence`, `evidence`, `note` (xem dưới).

## Các cột phải điền

| Cột | Giá trị |
|---|---|
| `is_misuse` | `1` / `0` / `?` (`?` tối đa ~10% số mẫu, chỉ khi thiếu bằng chứng) |
| `type` | `T1`…`T6`, hoặc `NONE` nếu `is_misuse = 0` |
| `subtype` | `NCD` / `PCD` / `KEY` / `ADDR` / `7702` / `-` |
| `xc_chain` | chỉ với T4: chain có contract gốc; còn lại `-` |
| `malicious` | `1` có bên thứ ba chủ động khai thác, `0` không, `-` không áp dụng |
| `confidence` | `high` / `medium` / `low` |
| `evidence` | ví dụ `code, timing, tx, symexec` |
| `note` | **bắt buộc** khi `confidence = low`, `is_misuse = ?` hoặc gặp ca khó §5 |

Viết đúng giá trị (chữ thường, `T1`, `NONE`, không thêm dấu cách). Không đổi tên cột, không đảo thứ tự dòng. Lưu **CSV UTF-8**.

## Cách đọc bằng chứng

- `-` nghĩa là không tra được hoặc không áp dụng, **không** suy ra gì từ ô đó.
- Trạng thái code là **hiện tại**, không phải lúc giao dịch. Khi kết luận phụ thuộc thời điểm (T4, PCD), xem `first_tx_date` hoặc mở explorer.
- Số giao dịch và thiệt hại của tác giả không có trong file; tự xem trên explorer.

## Ví dụ giả lập (không phải mẫu thật trong pilot)

| Tình huống | Điền |
|---|---|
| `code_bsc = none`, `xc_nets = eth`, `xc_timing = deployed_before`, tx gọi hàm `swap` | `1, T4, NCD, eth, 0, high, "code, timing, tx"` |
| `code_eth = none`, `xc_nets = -`, tx gọi hàm `transfer` | `1, T1, NCD, -, 0, high, "code, tx"` |
| `code = code` ở cả eth và bsc, `same_code_elsewhere = True`, gọi đúng hàm | `0, NONE, -, -, -, high, code` + note "contract hạ tầng đa chain" |

## Kỳ vọng

- ~3–6 phút/mẫu lúc đầu, về sau ~1–2 phút. 50 mẫu mất khoảng 2–3 giờ, nên chia 2 buổi.
- Bất đồng giữa hai người là bình thường; pilot sinh ra để tìm chúng. Không hiếm khi κ vòng đầu < 0,8, khi đó họp, chốt đáp án chung và sửa codebook.
- Chưa chắc thì chọn phía nghiêng hơn và để `confidence = low` kèm note, thay vì dùng `?`.

## Sau khi cả hai nộp xong

```bash
.venv/Scripts/python.exe -X utf8 -m address_misuse.sample_gold kappa data/gold/annotator_A.csv data/gold/annotator_B.csv
```

Liệt kê các mẫu bất đồng, họp phân xử vào `adjudicated.csv`, sửa codebook, ghi vào §9.

## An toàn và đạo đức

- Chỉ phân tích thụ động trên explorer. **Không** dùng private key lộ công khai để ký hay chuyển tài sản.
- Không đưa địa chỉ đầy đủ ra ngoài nhóm; khi trích thì ẩn bớt (`0x1234…abcd`).
