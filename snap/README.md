# Address Misuse Guard: MetaMask Snap (Module 4)

Cảnh báo **trước khi ký**: khi MetaMask mở màn hình xác nhận giao dịch, Snap (`onTransaction`) gửi `to`, `value`, `data`,
chain và delegate EIP-7702 (nếu có) tới Risk Engine cục bộ, rồi hiển thị điểm R, loại misuse và lý do.
`warn`/`block` được trả với `severity: critical`, nên MetaMask bắt người dùng xác nhận thêm một lần.

Snap chỉ hiển thị; toàn bộ việc chấm là engine Python của Module 2–3 (`address_misuse.wallet.api` → `OnlineStore.check`),
nên kết quả trong ví trùng với số liệu đánh giá trong paper.

## Chạy

```bash
# 1. Risk Engine (thư mục gốc dự án)
PYTHONPATH=src .venv/Scripts/python.exe -X utf8 -m address_misuse.wallet.api --port 8711

# 2. Build và phục vụ Snap (thư mục snap/)
npm install
npm run build
npm run serve          # http://localhost:8080 (chỉ phục vụ manifest + bundle, không có trang cài)

# 3. Trang cài (cửa sổ khác, thư mục snap/)
python -m http.server 8000 --bind 127.0.0.1
```

Mở `http://localhost:8000/install.html` bằng trình duyệt có **MetaMask Flask**, bấm "Cài Snap" (Snap ID cố định
`local:http://localhost:8080`). Sau đó tạo một giao dịch
bất kỳ (ví dụ gửi tới `0x6273…ef57`, ví Truffle lộ key) để thấy cảnh báo, rồi **bấm Reject**.

## Hành vi

| Trường hợp | Hiển thị |
|---|---|
| engine trả `block` / `warn` | Banner đỏ / vàng, `severity: critical` |
| engine trả `ok` | Banner xanh, không chặn |
| engine không chạy, lỗi, quá 3 s | Báo "chưa được kiểm tra" (fail-open, không chặn) |
| chain ngoài 8 mạng hỗ trợ | Báo không kiểm tra |

Chain hỗ trợ: eth, bsc, arb, op, base, polygon, sepolia, bsc_testnet (`src/engine.ts`, khớp `config.NETWORKS`).

## Test

```bash
npm test               # 7 test: map chain, dựng yêu cầu, onTransaction với engine giả trên 127.0.0.1:8711
```

Test `onTransaction` cần bản build mới nhất (`npm run build`) và cổng 8711 còn trống.

## Hạn chế

- Cần MetaMask Flask (Snap cục bộ không cài được trên MetaMask thường khi chưa phát hành lên npm và được duyệt).
- Engine phải chạy trên cùng máy (127.0.0.1). Bản phát hành thật cần engine có HTTPS hoặc đưa bảng tra vào Snap.
- Snap không có lịch sử giao dịch online (S_history = 0), nên dùng `w`/`τ` học lại không có history (Module 3, ablation).
