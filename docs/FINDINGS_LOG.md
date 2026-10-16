# Nhật ký phát hiện (dùng khi viết paper)

Ghi lại mọi quan sát có thể đưa vào paper, kèm cách tái tạo. Mới nhất ở trên.

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
