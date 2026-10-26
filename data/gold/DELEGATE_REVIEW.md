# Bảng rà soát delegate EIP-7702 (cho A và B)

Mỗi người rà **độc lập**, không hỏi nhau. Mục tiêu: xác nhận hoặc phản đối lớp đã điền sẵn cho từng delegate, trước khi gán nhãn.

## Cách làm (khoảng 15 phút)

Mỗi người rà trên **bản sao riêng**, không xem bản của người kia. Phải rà xong **trước khi** có file Excel để gán: file gán chỉ được tạo khi bảng đã rà đủ.

1. Người điều phối tạo bản sao: `python -m address_misuse.sample_gold delegate-copy A` → `data/gold/delegate_review_A.csv` (B: `delegate-copy B`). Bản sao chỉ có cột của bạn (`class_A`, `note_A` hoặc `class_B`, `note_B`), không có cột của người kia.
2. Mở bản sao của bạn (Excel hoặc trình soạn CSV, giữ mã hoá UTF-8).
3. Với mỗi dòng, mở link ở cột `explorer_url`, vào tab **Contract**: xem mã nguồn nếu đã verify, hoặc bytecode/nhãn nếu chưa. **Tự kết luận trước**, rồi mới so với `final_class`.
4. Điền cột của bạn:
   - `class_X` = `ok` nếu đồng ý với `final_class`;
   - hoặc một lớp khác (`legit_wallet` / `forwarder_sweeper` / `unknown`) nếu phản đối, **kèm lý do ở `note_X`** (cột của bạn).
   - **Ô trống = chưa rà**, không phải đồng ý.
5. Không sửa `final_class`, `source`, `note` (đó là của người điều phối; sửa thì lệnh gộp sẽ từ chối).
6. Xong, kiểm bản của bạn: `python -m address_misuse.sample_gold check-delegates data/gold/delegate_review_A.csv --who A` phải báo "đã rà đủ". Gửi file cho người điều phối.
7. Người điều phối gộp: `sample_gold merge-delegates data/gold/delegate_review_A.csv data/gold/delegate_review_B.csv`, rồi `sample_gold check-delegates` phải báo 0 lỗi (lệnh thoát mã 1 nếu còn lỗi).
8. Giải quyết phản đối (trên `delegate_lookup.csv` đã gộp): ba người bàn. Nếu đổi lớp, người điều phối sửa `final_class`, ghi lý do vào `note`, và xoá `class_A`, `class_B` của dòng đó; **cả hai** người rà xem lại và ghi `ok`. Nếu giữ lớp cũ, người phản đối ghi lại `ok` (giữ lý do cũ ở `note_X`).
9. Chỉ khi mọi ô `class_A`, `class_B` là `ok` (hoặc đúng `final_class`) thì `sample_gold check-delegates --strict` báo 0 lỗi; `sheet --set main` dùng đúng cổng này, nên trước đó không tạo được file gán.

**Lưu ý về neo (anchoring):** cột "Lớp điền sẵn", "Bằng chứng" và "Ghi chú" dưới đây là **lý do của người điều phối**. Chúng có ích để tìm nhanh chỗ cần xem, nhưng dễ làm bạn đồng ý theo. Hãy mở explorer và tự kết luận trước khi đọc chúng.

`n_items` = số mẫu có delegate này **hôm nay**. Với một số mẫu, delegate hôm nay được tạo sau tx (cột `code_at_event = unknown` trong file mẫu); các mẫu đó không dùng thẳng bảng này (CODEBOOK bước A), trừ khi tab Authorizations cho thấy lúc tx đã ủy quyền tới một delegate trong bảng.

Ba lớp: **forwarder_sweeper** (contract chỉ chuyển tiền nhận được tới một ví đích cố định, hoặc rút hết token); **legit_wallet** (ví thông minh thật: MetaMask, Safe, Coinbase, TokenPocket…; chủ ví tự điều khiển tiền); **unknown** (không đủ bằng chứng; khi đó gán theo giao dịch thực tế, CODEBOOK ca 13).

Lưu ý: tên contract có thể **giả** (ví dụ `MetaMaskSwapRouter` chỉ là forwarder 20 dòng). Hãy đọc mã, đừng tin tên.

## Danh sách

| # | Chain | Delegate | Số mẫu | Lớp điền sẵn | Bằng chứng | Ghi chú |
|---|---|---|---|---|---|---|
| 1 | bsc | [`0x9db96924…96d8`](https://bscscan.com/address/0x9db96924a0b0b9a83fe2368b29539561a9c696d8) | 59 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | verified source (Etherscan V2 getsourcecode) | Forwarder, cùng mã nguồn với bản ETH |
| 2 | eth | [`0x0727ca41…6786`](https://etherscan.io/address/0x0727ca41efc85f75cef26ee48f825893b4836786) | 28 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | verified source (Etherscan V2 getsourcecode) | Forwarder: receive() chuyển msg.value tới destination đặt một lần |
| 3 | eth | [`0x8a67b502…408a`](https://etherscan.io/address/0x8a67b5020ee254ef48e3b6a04927f39baf7e408a) | 26 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Chưa verify; không selector, rẽ nhánh theo CHAINID, có địa chỉ USDT cứng và nhiều lệnh CALL: mẫu sweeper cứng |
| 4 | bsc | [`0x1c3630c5…763c`](https://bscscan.com/address/0x1c3630c594effaac3e9aea562ee26a65b171763c) | 24 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Cùng mẫu rẽ nhánh CHAINID như 0x8a67, 564 byte |
| 5 | eth | [`0x88cf071b…8d46`](https://etherscan.io/address/0x88cf071b4bf5facab6712070a671f71282188d46) | 24 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | verified source (Etherscan V2 getsourcecode) | Tên 'MetaMaskSwapRouter' nhưng mã chỉ là forwarder 20 dòng (configureSwapRoute_mm); giả tên MetaMask, không phải ví của MetaMask |
| 6 | bsc | [`0xa19160b1…79df`](https://bscscan.com/address/0xa19160b1b01396da5fb72927c033fd71c62d79df) | 22 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | verified source (Etherscan V2 getsourcecode) | 'MetaMaskSwapRouter' giả tên, cùng mẫu forwarder |
| 7 | eth | [`0x8332a5c2…77f0`](https://etherscan.io/address/0x8332a5c2f00ab7e20c53210be2192aea7bdc77f0) | 20 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Chưa verify; cùng selector destination()/initialize(address) với Forwarder, 1071 byte |
| 8 | bsc | [`0x86e41575…77ca`](https://bscscan.com/address/0x86e415756170ef48e0e9052b8a8a7bd4783a77ca) | 18 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Chưa verify; cùng bytecode với eth 0x8332 |
| 9 | bsc | [`0x8a67b502…408a`](https://bscscan.com/address/0x8a67b5020ee254ef48e3b6a04927f39baf7e408a) | 6 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Cùng bytecode với eth 0x8a67 |
| 10 | eth | [`0x0e04736a…4647`](https://etherscan.io/address/0x0e04736a85433445ef602d07946671685ec94647) | 1 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Cùng mẫu rẽ nhánh CHAINID + USDT cứng như 0x8a67 |
| 11 | bsc | [`0xe2eca7d2…ad78`](https://bscscan.com/address/0xe2eca7d2a8a9ad6e99cae8ec85640298953ead78) | 1 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | bytecode (eth_getCode), unverified | Chưa verify; cùng selector Forwarder, 1045 byte |
| 12 | eth | [`0x3c3d7188…1931`](https://etherscan.io/address/0x3c3d718877a7d95857e1ae74b3963bddefb81931) | 1 | Forwarder/sweeper (chuyển tiền gửi vào ví đích) | verified source (Etherscan V2 getsourcecode) | Porwarder: forwarder không có cờ initialized |
| 13 | bsc | [`0xcc0c946e…f17b`](https://bscscan.com/address/0xcc0c946eecf01a4bc76bc333ea74ceb04756f17b) | 2 | Ví hợp lệ | verified source (Etherscan V2 getsourcecode) | TokenPocketSimple7702Account (ví TokenPocket, mẫu ERC-4337) |
| 14 | bsc | [`0xe6cae83b…555b`](https://bscscan.com/address/0xe6cae83bde06e4c305530e199d7217f42808555b) | 1 | Ví hợp lệ | verified source (Etherscan V2 getsourcecode) | Simple7702Account (mẫu tham chiếu ERC-4337) |
| 15 | eth | [`0x63c0c19a…e32b`](https://etherscan.io/address/0x63c0c19a282a1b52b07dd5a65b58948a07dae32b) | 1 | Ví hợp lệ | verified source (Etherscan V2 getsourcecode) | EIP7702StatelessDeleGator (MetaMask Delegator) |
| 16 | eth | [`0x2c6f0179…571d`](https://etherscan.io/address/0x2c6f01799fa9db1e7f2797e5ba892b72b865571d) | 6 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 17 | eth | [`0x8773a286…533f`](https://etherscan.io/address/0x8773a2868e4e113381ec94c463d51479fb9a533f) | 3 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 18 | eth | [`0x005c44ab…020d`](https://etherscan.io/address/0x005c44ab6c89be55669b2b6b9c0b0e76bed7020d) | 3 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 19 | eth | [`0x8d190c8a…25aa`](https://etherscan.io/address/0x8d190c8a8efccf17e912c5a41238637b21b225aa) | 2 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 20 | eth | [`0x1ee2581d…2492`](https://etherscan.io/address/0x1ee2581d34819de3d77715c758d8d0c525332492) | 2 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 21 | eth | [`0xd75ba5e1…a6ba`](https://etherscan.io/address/0xd75ba5e163fa5dd3b764f6d5c21210de3832a6ba) | 2 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 22 | eth | [`0x233faf90…76d2`](https://etherscan.io/address/0x233faf9050f93a36b7cc7567be3db21c998376d2) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 23 | eth | [`0x143b4129…bc46`](https://etherscan.io/address/0x143b41298cb0a6a83b3ab532aaafbbae3078bc46) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 24 | eth | [`0x0366b55f…60d1`](https://etherscan.io/address/0x0366b55f948a688888ca6e029ad0831f6ec260d1) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 25 | bsc | [`0xda92e8b5…3f18`](https://bscscan.com/address/0xda92e8b5dfcaaa07d665362d05616b2b828a3f18) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 26 | eth | [`0x399fbfea…96f4`](https://etherscan.io/address/0x399fbfea9fce84e57976c5c57d6ce7725a7f96f4) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 27 | eth | [`0x2e0b711a…3977`](https://etherscan.io/address/0x2e0b711a853a526a912492033352390da9833977) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 28 | eth | [`0x6d797ad6…23e0`](https://etherscan.io/address/0x6d797ad6b0c925171255e7af94b5c2af16c423e0) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 29 | eth | [`0x47e747f5…ea5e`](https://etherscan.io/address/0x47e747f5e8cb5819c966292dd969d989ae9dea5e) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 30 | eth | [`0x2f4a1219…1780`](https://etherscan.io/address/0x2f4a12190e7e7d7a0555432b9dd9446448a31780) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 31 | eth | [`0xc3a0a6c4…7747`](https://etherscan.io/address/0xc3a0a6c4eda3a36db743cb9393db54b6e0597747) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 32 | eth | [`0xe52d4de5…2257`](https://etherscan.io/address/0xe52d4de5ad7e057660f02894a958f9ad01862257) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |
| 33 | eth | [`0xf4b2569a…1c4d`](https://etherscan.io/address/0xf4b2569a806c1f4d1be0cebc3f0475a3d17a1c4d) | 1 | Chưa rõ | không có nguồn verify; chỉ thấy bytecode lớn nhiều selector (kiểu ví thông minh?) | Quyết định theo tx thực tế (CODEBOOK ca 13c) |

Bằng chứng 'bytecode, unverified' nghĩa là contract chưa verify mã nguồn; lớp điền sẵn dựa trên selector và opcode (có CALL + CALLVALUE, ghi đích vào storage hoặc địa chỉ token viết cứng). Hãy tự kiểm tra nếu muốn.

Bảng này tạo từ `delegate_lookup.csv`; nếu hai nơi lệch nhau thì `delegate_lookup.csv` là bản đúng.
