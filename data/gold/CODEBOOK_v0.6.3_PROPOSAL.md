# Đề xuất sửa CODEBOOK v0.6.2 → v0.6.3 (đã duyệt 2026-10-30 và áp dụng vào docs/CODEBOOK.md; giữ làm hồ sơ)

Ngày 2026-10-30. Nguồn: 7 mẫu bất đồng ở cổng κ 50 mẫu đầu ([ARBITRATION_gate50.md](ARBITRATION_gate50.md)). `docs/CODEBOOK.md` giữ nguyên v0.6.2 cho tới khi A và B đồng ý. Các sửa chỉ **làm rõ** chữ, không đổi mẫu, khoá hay định nghĩa T1–T7.

| # | Vấn đề | Mẫu | Sửa đề xuất |
|---|---|---|---|
| A1 | Rút nhanh mà tx có nhận lại tài sản (swap, mint, stake, deposit nhận token/ETH lại, bridge nhận LP) bị tính là "rút". Ca 7d (router vẫn tính) đang ép ví giao dịch DeFi thành KEY. | G068, G157 | Một lần rút nhanh chỉ tính khi (i) khoản ra ≤ khoản vào (cho phép phí gas, xem A2) và (ii) trong tx rút ví **không** nhận lại tài sản nào (coin, token, NFT). Ngược lại là giao dịch, không tính. Ca 7d giữ nguyên cho trường hợp ví chỉ gửi đi mà không nhận lại. |
| A2 | Ngưỡng 90% tính trên số gửi đi, không cộng phí gas nên quét sạch số dư bị tính 85%. | G110 | Lượng rút = giá trị gửi đi + phí gas của chính tx rút (nếu là coin gốc). Dùng lượng này so ngưỡng ≥ 90% khoản vào. |
| A3 | "Chuyển tiền/token" chưa nói NFT. | G173 | Coin, token ERC-20 và NFT (ERC-721/1155) đều là tài sản ở bước C. |
| A4 | Bước D2 đếm lịch sử rút nhanh chỉ khi tx mẫu có chuyển gì; B bỏ qua lịch sử khi tx mẫu rỗng hoặc fail. | G033, G184 | Viết rõ: D2 **luôn** đếm cả lịch sử của địa chỉ, kể cả khi tx mẫu không chuyển gì hoặc fail; đủ ≥ 2 lần rút nhanh theo A1/A2 thì KEY T5. |
| A5 | "Không có trong bảng delegate" mơ hồ. | G177 | Delegate không có trong `delegate_lookup.csv` = `unknown` (ca 13c). Người gán phải dùng đúng bản `delegate_lookup.csv` cuối (sha256 `952f068d…ecdf5`). |

## Việc cần làm nếu chấp thuận
1. A và B (và người điều phối) thống nhất nhãn cuối cho 7 mẫu ở ARBITRATION_gate50.md.
2. Viết v0.6.3 vào `docs/CODEBOOK.md`, ghi hash mới vào FINDINGS_LOG, gắn tag mới; A ký duyệt (không cho A xem GOLD_PROTOCOL.md hay ngưỡng 0,70).
3. Đảm bảo A có `delegate_lookup.csv` cuối.
4. A và B gán lại 50 dòng đầu theo v0.6.3, độc lập. 50 mẫu giữ nhãn phân xử làm nhãn vàng, **không** vào κ chính thức.
5. Gán tiếp 150 dòng còn lại (đây mới là κ chính thức), rồi phần gán đơn của B.

## Lưu ý trung thực (đưa vào paper)
- Các sửa này rút ra từ chính 7 bất đồng, nên codebook được tinh chỉnh sau khi thấy dữ liệu; 150 mẫu còn lại là phần chưa dùng để sửa.
- A1 làm giảm số KEY do ca 7d; phải chạy lại phân tích độ nhạy (ca 7) sau khi áp dụng.
- Tôi (người điều phối) soạn đề xuất dựa trên kiểm chứng chuỗi, không dùng nhãn của tác giả.
