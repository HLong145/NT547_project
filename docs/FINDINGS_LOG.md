# Nhật ký phát hiện (dùng khi viết paper)

Ghi lại mọi quan sát có thể đưa vào paper, kèm cách tái tạo. Mới nhất ở trên.

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
