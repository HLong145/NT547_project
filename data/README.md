# Dữ liệu

| Thư mục | Nội dung | Ai ghi | Sửa tay? |
|---|---|---|---|
| `Address-Misuse/` | Dữ liệu + code gốc của Shao et al. (Zenodo 17984167) | — | **Không bao giờ** |
| `seed/` | Bảng Parquet chuẩn hoá từ `Address-Misuse/` + `MANIFEST.json` | `python -m address_misuse.seed` | Không — chạy lại script |
| `raw/` | Dữ liệu tải từ Etherscan/BigQuery/RPC (giao dịch, code, giá) | script fetch (D1, D3, D5) | Không — chỉ thêm, không sửa |
| `interim/` | Kết quả trung gian: rule, đặc trưng, ma trận cross-chain | script phân tích | Không |
| `gold/` | Nhãn người gán: `annotator_A.csv`, `annotator_B.csv`, `adjudicated.csv` | người gán nhãn | **Có** (chỉ ở đây) |
| `final/` | Bảng dùng cho paper + `splits/` | script đóng băng (D8) | Không |

## Bảng trong `seed/`

| Bảng | Số dòng | Nội dung |
|---|---:|---|
| `candidate_addresses` | 7.580.130 | Địa chỉ ứng viên lấy từ GitHub/StackExchange có giao dịch trên ETH/BSC: `n_tx`, `balance_wei` |
| `candidate_pk_addresses` | 17.971 | Địa chỉ suy ra từ private key bị lộ (**không có key**) |
| `github_repos` | 63.004 | Danh sách repo GitHub tác giả đã quét |
| `ca_misuse` | 50.944 | CA Misuse, `subtype` = NCD/PCD, số giao dịch misuse, loss (wei + `cost_native`) |
| `eoa_misuse` | 26.715 | EOA Misuse, `subtype` = KEY/ADDR (KEY gồm cả dòng loss = 0) |
| `rq1_labels` | 1.463 | Nhãn tay của tác giả — **chỉ trên ca đã phát hiện** (1 = TP, 0 = FP) |
| `rq3_contract_labels` | 166 | Contract PCD: kết quả tool so với nhãn tay (đủ TP/FP/TN/FN) |
| `rq3_pcd_patterns` | 1.162 | Contract tại địa chỉ PCD: `malicious`, `pattern` |
| `eip7702_delegations` | 17.326 | EOA → contract được ủy quyền EIP-7702 |
| `eip7702_delegate_stats` | 101 | Mỗi delegate: số EOA ủy quyền, `flag` thô của tác giả |
| `proxy_map` | 144 | Proxy → logic contract |
| `clones` | 316 | Contract độc → số bản clone chính xác (theo Etherscan) |
| `bytecode` | 26.575 | Bytecode: `kind` = misuse_address / eip7702_delegate / proxy_logic |
| `symexec_results` | 1.325 | Kết quả symbolic execution của tác giả |

`tests/test_seed.py` kiểm tra các bảng khớp Bảng 1, 3, 4 và §6.1 của paper.

## Lưu ý khi dùng

- **Bỏ trùng**: một địa chỉ có thể xuất hiện ở cả `github` lẫn `stackexchange` với giá trị loss hơi khác nhau (do tải dữ liệu ở thời điểm khác nhau). Paper lấy **giá trị lớn nhất** cho mỗi `(chain, address)`.
- `eoa_misuse` loại KEY: lọc `cost_native > 0` để ra số "instances" như Bảng 3.
- `eip7702_delegate_stats.flag` (1/0/-1) **không** tương ứng với số contract độc trong paper (ETH 48 vs 49, BSC 41 vs 50) → không dùng làm nhãn độc hại.
  - `flag` chính là kết quả symexec: 1 = có đường chuyển tiền, 0 = không có, -1 = chưa phân tích.
  - `symexec_results` (kind = eip7702_delegate) là **mọi delegate đã phân tích**, không phải tập delegate độc. Ví dụ delegate hợp lệ của MetaMask (`EIP7702StatelessDeleGator`) cũng có mặt, với flag 1.
  - Nhãn độc hại phải tự gán. Ví hợp lệ đã kiểm chứng nằm trong `data/interim/n6_benign_7702_delegates.parquet`.
- `symexec_results.self_destruct` gần như luôn rỗng (1.320/1.325): bản code tác giả dùng khi chạy chưa ghi trường này.
- Giá trị wei lưu dạng chuỗi vì vượt giới hạn int64.
