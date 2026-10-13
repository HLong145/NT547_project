# Hướng dẫn lấy API key / tài khoản (làm một lần)

> Mọi key chỉ dán vào file `.env` ở thư mục gốc (tạo bằng `copy .env.example .env`). **Không** dán key vào chat, code hay tài liệu.

## 1. Etherscan API key (gấp nhất)

1. Vào https://etherscan.io/register → đăng ký → xác nhận email.
2. Đăng nhập → góc phải bấm tên tài khoản → **API Keys** (hoặc https://etherscan.io/myapikey) → **Add** → đặt tên `address-misuse` → copy key.
3. Mở `.env`, điền: `ETHERSCAN_API_KEY=<key>` (giữ `ETHERSCAN_PAGE_SIZE=1000` nếu là gói miễn phí).
4. Kiểm tra key dùng được trên chain nào:
   ```powershell
   .venv\Scripts\python.exe -X utf8 -m address_misuse.etherscan
   ```
   Kết quả dạng `eth OK (block …)` / `bsc LỖI: …`. Gửi lại kết quả này (không gửi key).

**Lưu ý gói miễn phí (2026):** một key dùng cho mọi chain qua API V2, khoảng 3–5 lệnh/giây. Từ 07/2026 mỗi lệnh trả tối đa 1.000 bản ghi. Theo một số nguồn, **BSC, Base và Optimism có thể không có trong gói miễn phí**. Nếu BSC báo lỗi, có 3 hướng:
- (a) Mua gói Lite của Etherscan 1 tháng, đủ cho đợt kéo dữ liệu BSC.
- (b) Lấy giao dịch BSC qua RPC riêng hoặc nhà cung cấp khác (chậm hơn).
- (c) Giữ ETH đầy đủ, còn BSC giới hạn ở top địa chỉ và một mẫu. Đây là mốc quyết định cuối tuần 1 trong PLAN_V2.

## 2. Google Cloud + BigQuery (dữ liệu ETH số lượng lớn)

Khuyến nghị: **BigQuery sandbox** — không cần thẻ, miễn phí 1 TB truy vấn/tháng và 10 GB lưu trữ (bảng tự hết hạn sau 60 ngày; không ảnh hưởng vì dữ liệu lấy về sẽ lưu thành Parquet trên máy).

1. Vào https://console.cloud.google.com → đăng nhập Google → **Select a project → New project** → tên `address-misuse` → ghi lại **Project ID** (dạng `address-misuse-123456`).
2. Vào https://console.cloud.google.com/bigquery → chọn project vừa tạo → sandbox tự bật (thấy chữ "SANDBOX" trên đầu).
3. Cài **Google Cloud CLI** cho Windows: https://cloud.google.com/sdk/docs/install → mở PowerShell mới:
   ```powershell
   gcloud auth application-default login
   gcloud config set project <PROJECT_ID>
   gcloud auth application-default set-quota-project <PROJECT_ID>
   ```
   Cách này đăng nhập qua trình duyệt, **không cần tải file JSON key** (an toàn hơn service account).
4. Trong `.env`: `GCP_PROJECT_ID=<PROJECT_ID>`; để trống `GOOGLE_APPLICATION_CREDENTIALS`.

Chi phí: bảng `bigquery-public-data.crypto_ethereum` rất lớn. Mọi truy vấn sẽ được **dry-run trước** để xem số GB quét, chỉ chọn cột cần thiết và lọc theo danh sách địa chỉ/khoảng thời gian, để nằm trong 1 TB miễn phí.

## 3. RPC riêng (nên có — phục vụ cross-chain và đo độ trễ < 150 ms)

RPC công khai đo được ~1 s/lệnh, có lúc 8–9 s → không đạt mục tiêu. Gói miễn phí của các nhà cung cấp là đủ (chỉ cần `eth_getCode`).

1. Đăng ký **Alchemy** (https://dashboard.alchemy.com) → **Create new app** → chọn các mạng: Ethereum, Arbitrum, OP Mainnet, Base, Polygon, BNB Smart Chain (nếu có), Ethereum Sepolia.
2. Mỗi mạng có một URL HTTPS dạng `https://eth-mainnet.g.alchemy.com/v2/<key>` → dán vào `.env`:
   ```
   RPC_ETH=https://eth-mainnet.g.alchemy.com/v2/...
   RPC_ARB=...
   RPC_OP=...
   RPC_BASE=...
   RPC_POLYGON=...
   RPC_SEPOLIA=...
   RPC_BSC=...
   ```
3. Nếu Alchemy không có BSC / BSC testnet: dùng QuickNode, NodeReal hoặc Ankr (đều có gói miễn phí) cho `RPC_BSC`, `RPC_BSC_TESTNET`.
4. Mạng nào để trống sẽ tự dùng RPC công khai mặc định.
5. Kiểm tra: `.venv\Scripts\python.exe -X utf8 -m address_misuse.crosschain 0x7a250d5630b4cf539739df2c5dacb4c659f2488d --chain bsc --data 0x7ff36ab5` — cột ms phải giảm rõ so với trước.

URL RPC chứa key → cũng chỉ để trong `.env`.
