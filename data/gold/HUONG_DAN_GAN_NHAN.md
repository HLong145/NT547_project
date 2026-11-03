# Hướng dẫn gán nhãn 200 mẫu (CODEBOOK v0.6.4)

Tài liệu này tóm tắt cách làm. Khi có chỗ nào khác với `docs/CODEBOOK.md`, **CODEBOOK là bản đúng**.

## 1. Cần có

| File | Ghi chú |
|---|---|
| `annotator_main_official_<A|B>.xlsx` | File gán của bạn, 200 dòng. Chỉ điền các cột tô vàng |
| `docs/CODEBOOK.md` v0.6.4 | Quy tắc đầy đủ. Đọc kỹ §3, §4.1, §5 (ca 7, 13) và mục "Thay đổi v0.6.3, v0.6.4" ở cuối |
| `delegate_lookup.csv` bản cuối | 96 dòng: 82 `forwarder_sweeper`, 8 `unknown`, 6 `legit_wallet`. Bản cũ hơn thì bỏ |
| Trình duyệt | Etherscan / BscScan theo link trong file |

## 2. Quy tắc làm mù

- Làm **một mình**. Không bàn mẫu nào với người gán kia cho tới khi cả hai nộp file.
- Không mở các file `*_key.csv`, `dataset_v2.parquet`, `engine_eval.parquet`, file của người kia, và không đọc GOLD_PROTOCOL / PROGRESS / FINDINGS_LOG.
- Không tra nhãn của tác giả paper hay kết quả detector.

## 3. Các ô phải điền (cột vàng)

| Cột | Giá trị |
|---|---|
| `is_misuse` | `1` / `0` / `?` (`?` chỉ khi không mở được explorer, tối đa 10% số mẫu) |
| `type` | `T1`–`T6` hoặc `NONE` (khi `is_misuse = 0`) |
| `subtype` | `NCD` / `PCD` (T1, T4), `KEY` / `ADDR` / `7702` (T5), `-` (T2, T3, T6, mẫu âm) |
| `xc_chain` | Chỉ với T4: chain có contract gốc. Còn lại `-` |
| `malicious` | `1` thấy tiền về ví bên thứ ba; `0` đã kiểm và không có; `?` chưa thấy; `-` mẫu âm |
| `confidence` | `high` chỉ khi đã mở `tx_url`; chỉ dựa vào cột trong file thì tối đa `medium` |
| `evidence` | Nguồn đã dùng, ví dụ `tx, code, history, delegate, xc, timing` |
| `note` | **Bắt buộc** khi `low`, `?` hoặc ca khó. Delegate thì ghi **đủ 42 ký tự** địa chỉ |

Dùng danh sách chọn trong ô, đừng gõ tay để tránh sai chính tả.

## 4. Quy trình mỗi mẫu (CODEBOOK §4.1)

**Bước 0.** Mở `tx_url`, ghi nhận: Status, From, To, Value, Method, token / NFT chuyển trong tx.

**Bước A.** Xem `code_at_event`:
- `none` → B; `code` / `destroyed` → C; `7702` → D.
- `unknown` mà `delegate_7702 = -` → tự xem trên explorer địa chỉ có code trước tx không.
- `unknown` mà có `delegate_7702` → mở tab **Authorizations**: lúc tx đang ủy quyền tới delegate X nào thì xét theo X (bước D); không có thì là EOA thường (D2).

**Bước B (không có code trước tx).**
- Không gọi hàm (`calldata_kind` là `-`, `text`, `short`, hoặc 32 byte không giải mã được) → sang D.
- Gọi hàm: `subtype = PCD` nếu `own_create_time` có giá trị, ngược lại `NCD`.
- `xc_timing`: `before` → **T4** (`xc_chain = origin_net`); `after` hoặc `-` → **T1**; `unknown` → tự tra giờ tạo ở chain kia (không ra → T4, `low`).

**Bước C (có code trước tx).**
- `transfer`/`transferFrom` gửi token vào chính contract token đó, tx thành công → **T3**.
- Gọi đúng hàm của contract hợp lệ → **NONE**.
- **T2** khi đủ 3 điều kiện: tx thành công, contract không phải thứ định gọi, tiền không quay lại. Thiếu một điều kiện → NONE.

**Bước D (EOA, kể cả 7702).**
1. Có delegate lúc tx → tra `delegate_lookup.csv` (`final_class`):
   - `forwarder_sweeper` → **T5/7702**, kể cả khi tx chỉ chuyển dust; trừ khi ví đích có nhãn sàn → NONE.
   - `legit_wallet` → NONE, trừ khi có ≥ 2 lần rút nhanh → T5/KEY.
   - `unknown`, **hoặc delegate không có trong bảng** → xét tx: tài sản bị chuyển ra ví lạ mà không nhận lại gì → T5/7702; không thấy → D2.
   - Ủy quyền ghi `invalid_nonce` hoặc bị tx khác chiếm trước trong cùng block → **không** có hiệu lực, xét delegate đang có hiệu lực lúc tx.
2. **Đếm rút nhanh** trong **toàn bộ lịch sử**, mở **cả ba tab** Transactions, Token Transfers, NFT Transfers:
   - Một lần rút nhanh = tiền vào, rồi ≤ 10 phút sau ≥ 90% khoản đó (cộng gas, không vượt khoản vào) ra **ví lạ**, và trong tx rút **không nhận lại** tài sản nào (swap, mint, stake thì không tính).
   - Ví có nhãn sàn / custodian không phải ví lạ. Ví không nhãn, hoặc nhãn router / bridge vẫn là ví lạ (dùng thì `low`, note ca 7b/7c/7d).
   - ≥ 2 lần → **T5/KEY**, `malicious = 1`; đúng 1 lần → NONE, `low`, note "1 lần rút nhanh"; 0 lần → bước 3.
3. Đủ 3 dấu hiệu address poisoning (ca 18) → T6. Còn lại → **NONE**.

**Phân vân:** làm đủ các bước mà vẫn không chứng minh được misuse → `0`, `low`, ghi note. Ưu tiên T4 > T1, T5 > T6.

## 5. Lỗi hay gặp (rút ra từ 50 mẫu đầu)

1. Thiếu tab **Token Transfers** hoặc **NFT Transfers** khi đếm rút nhanh.
2. Tính swap / mint / stake là rút nhanh (địa chỉ có nhận lại tài sản).
3. Quên cộng phí gas, hoặc tính lượng ra lớn hơn khoản vào.
4. Bỏ qua lịch sử vì tx mẫu rỗng hoặc fail: **luôn** đếm lịch sử.
5. Dùng delegate **hôm nay** thay vì delegate **lúc tx**.
6. Coi ủy quyền `invalid_nonce` là có hiệu lực.
7. Lấy dust (< 0,000001 coin) làm bằng chứng cho delegate `unknown`.

## 6. Nộp file

- Lưu đúng định dạng `.xlsx`, giữ nguyên tên file, không thêm / xoá / đổi thứ tự dòng hay cột.
- Không cần làm một lần cho xong: có thể chia làm nhiều lần ngồi (gợi ý, không bắt buộc: khoảng 40 mẫu mỗi lần để đỡ mệt, đỡ sai); nhớ lưu file sau mỗi lần.
- Xong 200 dòng thì gửi file cho người điều phối.
