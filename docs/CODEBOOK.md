# Codebook gán nhãn vàng (D5)

Bản v0.6.3 (2026-10-30; sửa v0.6.2 sau cổng κ 50 mẫu đầu, xem mục "Thay đổi v0.6.3" cuối file). **Tài liệu này chỉ dành cho người gán nhãn.** Thiết kế mẫu, quy trình phân xử, cách báo kết quả và hạn chế nằm ở [GOLD_PROTOCOL.md](GOLD_PROTOCOL.md). Người gán **không đọc** GOLD_PROTOCOL.md trước khi gán xong (nó có thông tin làm mất tính mù).

Chưa gán mẫu chính cho tới khi người gán A xác nhận bản này. Taxonomy theo [requirements.md](requirements.md) §3.1.

---

## 1. Đơn vị gán nhãn

**Một mẫu = một giao dịch (tx) cho sẵn tới một địa chỉ trên một chain.** Mỗi dòng có `chain`, `address`, `tx_hash` và `tx_url` (mở thẳng tx). Câu hỏi: *"Tx này của người dùng tới địa chỉ này có phải misuse không, và thuộc loại nào?"*

- Nhãn áp cho **tx cho sẵn**, không cho cả địa chỉ.
- "**Trước tx**" nghĩa là trước tx này theo thứ tự trên chuỗi: block nhỏ hơn, hoặc cùng block nhưng vị trí trong block nhỏ hơn. Không dùng "ngày" hay "tx đầu tiên".
- So sánh **giữa hai chain** (T4): dùng giờ UTC đến từng giây. Cùng một giây thì coi là **không** trước (xem ca 17).
- Với địa chỉ là EOA (KEY / ADDR / 7702) được dùng **toàn bộ lịch sử** của địa chỉ, kể cả sau tx, để nhận ra sweeper. Nhãn vẫn là của tx cho sẵn.
- Chỉ xét **chain ghi trong mẫu**. Cùng địa chỉ trên chain khác là chuyện khác.
- **Pilot** (đã xong, không có `tx_hash`): gán theo tx điển hình tới địa chỉ. Chỉ còn dùng làm ví dụ ở §4.2.

## 2. Các trường phải điền

| Cột | Giá trị | Ý nghĩa |
|---|---|---|
| `is_misuse` | `1` / `0` / `?` | `?` chỉ khi không mở được explorer; mỗi người không quá 10% số mẫu của mình |
| `type` | `T1` … `T6` / `NONE` | **Một** type chính (ưu tiên ở §4). `NONE` khi `is_misuse = 0` |
| `subtype` | `NCD` / `PCD` / `KEY` / `ADDR` / `7702` / `-` | Theo định nghĩa ở §3. T2, T3, T6 và mẫu âm ghi `-` |
| `xc_chain` | tên chain / `-` | Chỉ dùng với T4: chain có contract gốc |
| `malicious` | `1` / `0` / `?` / `-` | `1` = đã thấy tiền về ví bên thứ ba; `0` = đã kiểm tra và không có (hố đen, tiền nằm yên); `?` = chưa thấy nhưng có dấu hiệu; `-` = mẫu âm |
| `confidence` | `high` / `medium` / `low` | Mức chắc chắn của chính bạn |
| `evidence` | danh sách ngắn | Bằng chứng đã dùng, ví dụ `code, tx, timing, xc, delegate, history` |
| `note` | văn bản | Bắt buộc khi `confidence = low`, `is_misuse = ?`, hoặc mẫu là ca khó ở §5 |

**Cam kết mù:** trong lúc gán, **không** mở `data/gold/*_key.csv`, `data/final/dataset_v2.parquet`, `data/interim/engine_eval.parquet`, file của người gán kia, và **không** đọc GOLD_PROTOCOL.md, FINDINGS_LOG.md hay PROGRESS.md. Không tra nhãn của tác giả hay kết quả detector. Các file này nằm trong repo nên cam kết dựa vào tự giác.

## 3. Định nghĩa

### 3.1. Gọi hàm hay không (`calldata_kind`)

CA misuse (T1, T4) chỉ xét khi tx **gọi hàm**. Cột `calldata_kind`:

| Giá trị | Nghĩa | Có phải gọi hàm? |
|---|---|---|
| `call` | Có ≥ 4 byte calldata, không đọc được thành văn bản | Có, trừ ca 10 (`calldata_len = 32` mà Method không giải mã được) |
| `-` | Không có calldata (chuyển coin thuần) | **Không bao giờ** |
| `text` | Calldata đọc được thành văn bản (tin nhắn, inscription). Ví dụ `selector = 0x64617461` là chữ ASCII "data" (inscription `data:...`) | Không |
| `short` | 1–3 byte calldata | Không |
| `unknown` | Không tra được tx | Tự xem Input Data trên `tx_url` |

Cột `selector` = 4 byte đầu của calldata, kể cả khi là văn bản. Đừng đọc `selector` một mình: luôn xem `calldata_kind`. Cột `calldata_len` = số byte calldata; lời gọi hàm chuẩn có 4 + 32·k byte (4, 36, 68, …), còn **đúng 32 byte** là một từ dữ liệu (ví dụ event topic), xem ca 10.

### 3.2. CA misuse: người dùng tương tác với địa chỉ *như thể* đó là contract

- **NCD (No Code at Destination):** ngay trước tx, địa chỉ **không có code** trên chain này, tx **gọi hàm** (§3.1), và về sau **không** có contract nào được tạo ở địa chỉ này trên chain này. Type **T1** (hoặc T4).
- **PCD (Premature Call), theo tác giả:** ngay trước tx địa chỉ **chưa có code**, tx **gọi hàm**, và một contract được tạo ở địa chỉ này trên chain này **sau** tx. Nghĩa là gọi trước khi deploy. Cũng là **T1** (hoặc T4) với `subtype = PCD`, **không** phải T2.
  - Cách đọc cột: `code_at_event = none` **và** `own_create_time` có giá trị → contract được tạo sau tx → PCD. `own_create_time = -` → NCD.
- **Tx lỗi (`tx_status = fail`) vẫn tính** cho NCD/PCD: người dùng vẫn gọi nhầm và mất gas (ca 8).

### 3.3. T2, T3: địa chỉ có code ngay trước tx

- **T2 (hố đen):** tx **thành công** gửi coin/token vào contract **không phải thứ người dùng định gọi** (contract không có hàm nhận, hoặc gọi hàm không có trong contract), và tiền không quay lại người dùng. Ba điều kiện ở §4.1 bước C. Cờ `symexec_*` chỉ là gợi ý.
- **T3 (gửi token vào chính contract token):** tx gọi `transfer(to, amount)` (selector `0xa9059cbb`) hoặc `transferFrom(from, to, amount)` (`0x23b872dd`) tới contract token, với **`to` bằng chính địa chỉ contract token đó**, và tx thành công. Trên explorer: tab "ERC-20 Tokens Transferred" của tx cho thấy token đi **vào** chính contract token. Theo requirements.md §3.1 ("Token Self-Transfer Sink"). Luật của tác giả không có type này.

### 3.4. EOA misuse: người dùng gửi tài sản tới ví họ không kiểm soát an toàn

- **Một lần rút nhanh:** một lần tiền (coin, token hoặc NFT) **vào** địa chỉ, rồi trong **≤ 10 phút** có tx **ra** chuyển **≥ 90%** khoản đó (cùng tài sản) tới một **ví lạ**, và thỏa hai điều kiện thêm (v0.6.3): (i) **lượng ra** = giá trị gửi đi **cộng phí gas của chính tx rút** (nếu là coin gốc) phải ≥ 90% khoản vào, và không vượt quá khoản vào; (ii) trong tx rút, địa chỉ **không nhận lại tài sản nào** (coin, token ERC-20, NFT ERC-721/1155). Có nhận lại (swap, mint, stake, deposit nhận LP / token) là giao dịch của chủ ví, **không** tính là rút. Bridge gửi đi mà không nhận lại gì trên chain này vẫn tính. *Ví lạ* = không phải người gửi khoản vào, và không phải ví có **nhãn** sàn / custodian trên explorer (ca 7a). Ví nhận **không có nhãn** vẫn là ví lạ, kể cả khi nghi là ví gom của sàn (ca 7b, 7c). Ví có nhãn **router / bridge** cũng vẫn là ví lạ (ca 7d), vì kẻ trộm hay đổi tiền qua đó.
- **KEY:** ví có private key đã lộ. File mẫu **không** cho biết ví có lộ key hay không. Gán **T5/KEY khi thấy ≥ 2 lần rút nhanh** (hai khoản vào khác nhau, xét cả lịch sử, ví lạ có thể khác nhau). Chỉ thấy **1 lần** → `NONE`, `confidence = low`, note "1 lần rút nhanh". Không thấy lần nào → không phải KEY.
- **ADDR:** người dùng gửi tới một địa chỉ ví công khai (trong tài liệu, code mẫu) không phải của họ, và tiền bị rút về ví lạ. Chỉ chọn `ADDR` (thay vì `KEY`) khi explorer ghi rõ đó là ví ví dụ công khai; cả hai đều là T5.
- **7702:** EOA đã ủy quyền EIP-7702 (code bắt đầu `0xef0100…`) tới một delegate. Tiền gửi tới bị delegate xử lý. Dùng **bảng tra delegate** (ca 13).

### 3.5. Taxonomy 6 type

| Type | Tên | Điều kiện cần (đều phải thỏa) |
|---|---|---|
| **T1** | Gọi hàm tới địa chỉ không có code | Ngay trước tx địa chỉ không có code trên chain này; `calldata_kind = call`; **không** có contract cùng địa chỉ ở chain khác được tạo trước tx. `subtype` = NCD / PCD |
| **T2** | Hố đen | Ngay trước tx địa chỉ có code; tx thành công; contract không phải thứ người dùng định gọi; tiền không quay lại. `subtype = -` |
| **T3** | Gửi token vào chính contract token | `transfer`/`transferFrom` tới contract token với người nhận = chính contract đó; tx thành công. `subtype = -` |
| **T4** | Cross-chain misalignment | Như T1, **và** cùng địa chỉ có contract ở chain khác được tạo **trước** tx (ghi `xc_chain`) |
| **T5** | Key lộ / sweeper / EIP-7702 độc | KEY (≥ 2 lần rút nhanh), ADDR bị rút, hoặc 7702 tới delegate sweeper |
| **T6** | Address poisoning | Định nghĩa vận hành ở ca 18. Hiếm; chỉ gán khi đủ cả ba dấu hiệu |

Mẫu **âm** (`is_misuse = 0`, `type = NONE`): contract hợp lệ được gọi đúng; contract deploy cùng địa chỉ trên nhiều chain kể cả chain này; 7702 tới ví thông minh hợp lệ; địa chỉ nạp của sàn tự gom về ví có nhãn sàn trên explorer (ca 7a); tin nhắn/inscription gửi tới EOA; giao dịch thường.

## 4. Quy trình

### 4.1. Từng bước (làm đúng thứ tự)

**Bước 0.** Mở `tx_url`. Ghi nhận: Status, From, To, Value, Method, token chuyển trong tx.

**Bước A. Trạng thái code ngay trước tx (`code_at_event`).**
- `none` → **B**.
- `code` hoặc `destroyed` → **C**. (`destroyed` = có code lúc tx, nay đã tự huỷ.)
- `7702` → **D**.
- `unknown`: xem cột `delegate_7702` trước, rồi theo đúng **một** trong hai dòng dưới.
- `unknown` (không có `delegate_7702`, tức `-`) → mở explorer của địa chỉ, xem tx tạo contract (Contract Creator) và so với tx theo §1. Có code trước tx → C; không → B; EOA không code → D; vẫn không biết → `?` nếu là điểm quyết định, ghi note.
- `unknown` **và** `delegate_7702` có giá trị: delegate hôm nay được tạo **sau** tx, nên lúc tx địa chỉ là EOA thường **hoặc** đang ủy quyền cho một delegate **khác** (đổi ủy quyền sau đó). Mở tab Authorizations: không có ủy quyền nào còn hiệu lực lúc tx → **D2** (EOA thường; không dùng bảng delegate); có ủy quyền tới delegate X lúc tx → **D** với delegate X: X có trong bảng delegate thì dùng `final_class` của X, không có thì xét như `unknown` (ca 13c). Ghi **địa chỉ đầy đủ** của delegate X (0x + 40 ký tự, không viết tắt) vào note. Không xem được → `?`, ghi note.

**Bước B. Không có code ngay trước tx.**
1. `calldata_kind` khác `call` (`-`, `text`, `short`) → không phải CA misuse → **D** (xét như chuyển tiền tới EOA). `calldata_kind = unknown` (không tra được tx): mở `tx_url`, xem Input Data, rồi xét như trên.
2. `calldata_kind = call` nhưng `calldata_len = 32` và Method trên trang tx là mã thô `0x…` (ca 10) → **D**.
3. Còn lại là gọi hàm. `subtype`: `PCD` nếu `own_create_time` có giá trị, ngược lại `NCD`.
4. Chain khác (`xc_timing`):
   - `before` → **T4**, `xc_chain = origin_net`.
   - `after` → **T1**, note "xc after".
   - `unknown` → mở `explorer_url_xc`, tìm tx tạo contract trên chain đó, so giờ với `at_time`. Tạo trước → T4; sau → T1; vẫn không biết → **T4, `confidence = low`**.
   - `-` (không có contract ở chain khác) → **T1**.
5. `malicious`: `1` nếu thấy tiền của tx này về ví bên thứ ba (ví dụ contract PCD rút khoản đó đi); `0` nếu tiền kẹt/không có tiền (chỉ mất gas); `?` nếu chưa rõ.

**Bước C. Có code ngay trước tx.**
1. **T3:** `selector` là `0xa9059cbb` hoặc `0x23b872dd`, người nhận trong calldata (tab "ERC-20 Tokens Transferred" hoặc phần Input đã giải mã) **bằng chính `address`**, tx thành công → **T3**, `malicious = 0` (token kẹt trong contract) trừ khi thấy contract có hàm rút token về ví lạ và đã rút (`1`).
2. Contract là thứ người dùng định gọi và tx gọi đúng hàm (Method giải mã ra tên hàm có thật: approve, transfer tới người khác, swap, deposit…) → **NONE**. Token / proxy / LP / router gọi đúng hàm → NONE.
3. **T2** khi đủ cả 3: (i) `tx_status = success`; (ii) contract không phải thứ định gọi: gửi coin vào contract không có hàm nhận, hoặc Method hiện selector thô `0x…` trên contract đã verify; (iii) tiền không quay lại người dùng (nằm yên: `malicious = 0`; ra ví lạ: `1`; code có đường rút nhưng chưa thấy rút: `?`).
4. Thiếu điều kiện nào → **NONE**. Tx lỗi (`fail`) tới địa chỉ có code → NONE.

**Bước D. EOA (kể cả 7702 và chuyển tiền thường từ bước B).**
1. `code_at_event = 7702` (có `delegate_7702`): tra delegate trong `data/gold/delegate_lookup.csv` và theo **ca 13**. Mở tab Authorizations của địa chỉ: nếu ủy quyền tới delegate này xảy ra **sau** tx thì lúc tx địa chỉ là EOA thường → làm tiếp D2. Với `forwarder_sweeper`: xem ví đích mà forwarder chuyển tiền tới; nếu ví đích có **nhãn** sàn / custodian trên explorer (ca 7a) → **NONE** (địa chỉ nạp của sàn), không phải T5.
2. Mở tab Transactions (và Token Transfers) của địa chỉ, đếm số **lần rút nhanh** (§3.4) trong toàn lịch sử. **Luôn đếm cả lịch sử**, kể cả khi tx mẫu không chuyển gì hoặc bị `fail` (v0.6.3):
   - Trước khi đếm, xét ví nhận của từng lần rút theo **ca 7**: chỉ lần rút về ví có **nhãn** sàn / custodian trên explorer (7a) là **không** tính. Rút về ví không nhãn (7b, 7c) hoặc ví có nhãn router / bridge (7d) **vẫn tính**; nếu kết luận T5 có dùng lần rút như vậy thì `confidence = low`, note "ca 7b", "ca 7c" hoặc "ca 7d".
   - ≥ 2 lần → **T5/KEY**, `malicious = 1`. (`ADDR` thay cho `KEY` nếu explorer ghi rõ là ví ví dụ công khai.)
   - đúng 1 lần → **NONE**, `confidence = low`, note "1 lần rút nhanh".
   - 0 lần → tiếp D3.
3. Có đủ dấu hiệu address poisoning (ca 18) → **T6**.
4. Còn lại (ví thường, sàn, ví thông minh hợp lệ, inscription) → **NONE**.
5. Tiền bị chuyển nhanh nhưng **về ví có nhãn sàn / custodian** (ca 7a) → NONE.

**Bước E. Điền ô.** Mẫu âm: `type = NONE`, `subtype = xc_chain = malicious = -`. `confidence = high` chỉ khi đã mở `tx_url`; chỉ dựa vào cột bằng chứng thì tối đa `medium`. `evidence` ghi đủ nguồn đã dùng. `note` bắt buộc khi `low`, `?` hoặc ca khó.

**Mặc định khi phân vân:** làm đủ các bước mà vẫn không chứng minh được misuse → `is_misuse = 0`, `confidence = low`, ghi note. Chỉ dùng `?` khi không mở được explorer.

**Ưu tiên khi thỏa nhiều type:** T4 > T1; T5 > T6. T2/T3 chỉ ở nhánh có code. Type phụ ghi trong `note`.

### 4.2. Ví dụ từ pilot (đã chốt)

| Mẫu | Quan sát | Nhãn chuẩn |
|---|---|---|
| P008, P010, P032, P025 | token / LP / proxy được gọi đúng hàm, tx thành công | `0`, NONE (cờ symexec không đổi nhãn) |
| P002 | contract đa chain cùng bytecode, gọi đúng hàm swap | `0`, NONE |
| P005 | 167 tx vào, 164 tx lỗi; proxy `submit()` đúng | `0`, NONE (tx lỗi tới contract có code không mất tiền) |
| P024 | gửi 0,02 ETH kèm calldata khi chưa có code; contract cài sau rồi rút đúng khoản đó về ví lạ | `1`, T1/PCD, `malicious = 1` |
| P012 | không có cặp vào-ra ≤ 10 phút về ví lạ | `0`, NONE, `medium` |
| P038 | 7702 tới Forwarder; 1,49 ETH vào, 1,43 ETH ra ví lạ | `1`, T5/7702, `malicious = 1`, high |
| P034 | 7702 tới forwarder; chỉ có tx 0 ETH, chưa thấy rút | `1`, T5/7702, `malicious = ?`, medium |
| P009 | calldata chỉ là event topic `0xddf252ad…` tới EOA | `0`, NONE (ca 10) |
| P036 | chain này không code; code chỉ ở bsc_testnet, không tra được giờ tạo | `1`, T4, `confidence = low` (ca 12) |

## 5. Ca khó

1. **Contract ở chain khác tạo SAU tx** (`xc_timing = after`): **không** gán T4 (người dùng không thể copy từ chain kia). Gán T1, note "xc after".
2. **Không biết giờ tạo ở chain khác** (`xc_timing = unknown`): mở explorer chain đó. Vẫn không biết → T4, `confidence = low`.
3. **Cùng contract trên mọi chain, kể cả chain này** (Multicall3, Permit2, Safe, EntryPoint…): **âm**, trừ khi tx thật sự sai hàm (khi đó theo bước C).
4. **Địa chỉ hệ thống / precompile** (`0x000…000X`, predeploy OP-stack `0x4200…`, system contract BSC `0x…1000`): thường âm. Gọi hàm tới predeploy của chain *khác* (ví dụ `0x4200…0006` trên ETH, chain này không có code) → T4.
5. **Người gửi là chính deployer** (đội dự án gửi nhầm chain): vẫn T4. Note `self-misuse`.
6. **7702 tới ví thông minh hợp lệ** (MetaMask Delegator, Safe, Coinbase…) và chủ ví vẫn rút tiền bình thường: **âm**. Nếu thấy ≥ 2 lần rút nhanh về ví lạ thì vẫn T5/KEY (sweeper rút bằng chính key).
7. **Ví sàn / địa chỉ nạp auto-sweep** (địa chỉ nạp của sàn tự gom tiền về ví nóng, nhìn giống sweeper). Ví gom của kẻ trộm cũng nhận từ nhiều nạn nhân và cũng chuyển tiếp sang sàn để rút tiền mặt, nên **chỉ nhãn trên explorer** mới loại được một lần rút. Với ví nhận của từng lần rút nhanh, chỉ dùng thông tin thấy trên explorer:
    - (a) Ví nhận **chính nó** có **nhãn sàn / custodian** trên explorer (ví dụ "Binance 14", "Binance: Hot Wallet 6", "Coinbase 10") → lần rút này **không** tính. Nếu mọi lần rút đều như vậy → địa chỉ nạp của sàn → **NONE**, `confidence = high`.
    - (b) Ví nhận **không có nhãn**, ≥ 90% tx ra của địa chỉ này đều về **một** ví nhận đó, và ví nhận chuyển tiếp phần lớn tiền tới một ví sàn có nhãn → **vẫn tính** là rút nhanh (có thể là ví gom của sàn, cũng có thể là kẻ trộm đổi ra tiền). Nếu nhãn T5 dựa vào lần rút này: `confidence = low`, note "ca 7b".
    - (c) Ví nhận không nhãn và nhận từ rất nhiều địa chỉ khác (hàng chục trở lên) theo cùng mẫu hình "vào rồi ra hết về nó", không thấy liên kết sàn → **vẫn tính** là rút nhanh (mẫu hình này chính là ví gom của sweeper bot). Nếu nhãn T5 dựa vào lần rút này: `confidence = low`, note "ca 7c".
    - (d) Ví nhận có nhãn **router / bridge / DEX** (ví dụ "1inch Router", "Stargate Bridge"), không phải nhãn sàn / custodian → **vẫn tính** là rút nhanh (kẻ trộm hay đổi hoặc chuyển chain qua đó để rút tiền). **Trừ khi** tx đó địa chỉ nhận lại tài sản (swap, mint…): khi đó không phải rút nhanh (§3.4, v0.6.3). Nếu nhãn T5 dựa vào lần rút này: `confidence = low`, note "ca 7d".
    - Ví nhận không thỏa (a) → lần rút đó tính là rút nhanh (bước D2). Ghi "ca 7b" / "ca 7c" / "ca 7d" vào note mỗi khi nhãn T5 có dùng lần rút loại (b) / (c) / (d).
8. **Tx chỉ mất gas** (value = 0) hoặc **tx lỗi** tới địa chỉ không có code mà có gọi hàm: vẫn T1/T4.
9. **Vừa có contract tạo sau tx trên chain này vừa có contract ở chain khác** (PCD-XC): theo bước B4 với `xc_timing`; `subtype = PCD`.
10. **Calldata là văn bản hoặc một từ dữ liệu 32 byte.** `calldata_kind = text` → không phải gọi hàm. `calldata_kind = call` và `calldata_len = 32`: mở `tx_url`, xem dòng Method: hiện **tên hàm** giải mã được → coi là gọi hàm (bước B3); hiện **mã thô** `0x…` → không phải gọi hàm (event topic hay dữ liệu, ví dụ `0xddf252ad…`) → bước D. Không có dấu hiệu ở bước D → âm.
11. **Contract xuất hiện SAU tx:** nhánh B (T1/T4, PCD), kể cả khi contract cài sau rút đúng khoản đó (P024).
12. **Testnet làm chain gốc cho T4:** có tính. Ghi `xc_chain` là tên testnet; không tra được giờ tạo → `confidence = low`.
13. **7702: bảng tra delegate.** `data/gold/delegate_lookup.csv` có sẵn `final_class` và `source` do người điều phối điền từ bằng chứng khách quan (mã nguồn đã verify, hoặc bytecode). Ba lớp: `legit_wallet` / `forwarder_sweeper` / `unknown`. **Bắt buộc trước khi gán mẫu nào**, A và B mỗi người rà trên **bản sao riêng** (`data/gold/delegate_review_A.csv` / `..._B.csv`, chỉ có cột của mình; hướng dẫn ở `data/gold/DELEGATE_REVIEW.md`): tự mở `explorer_url` của từng delegate rồi điền `class_X`: `ok` = đã xem và đồng ý; tên lớp khác (`legit_wallet` / `forwarder_sweeper` / `unknown`) kèm lý do ở `note_X` của mình = phản đối. Cột `note` là lý do của người điều phối, không sửa. **Ô trống = chưa rà**, không phải đồng ý. Phản đối thì ba người thống nhất lại trên bảng chung `delegate_lookup.csv` (sau khi gộp): người điều phối sửa `final_class` (ghi lý do vào `note`) và xoá `class_A`, `class_B` của dòng đó, rồi **cả hai** người rà ghi lại `ok`; hoặc người phản đối rút lại bằng cách ghi `ok`. File Excel để gán **chỉ được tạo** khi mọi dòng của cả hai người là `ok` (hoặc đúng `final_class`), tức `sample_gold check-delegates --strict` báo 0 lỗi; `sheet` dùng đúng cổng này. Đừng chỉ đọc lại `source`: tự xem mã nguồn hoặc bytecode. Khi gán, dùng `final_class`:
    - (a) `legit_wallet` → NONE, trừ khi thấy ≥ 2 lần rút nhanh về ví lạ (ca 6: T5/KEY).
    - (b) `forwarder_sweeper` → T5/7702, **trừ khi** ví đích của forwarder có nhãn sàn / custodian trên explorer (ca 7a) → NONE (forwarder có ví đích cố định cũng là cách sàn làm địa chỉ nạp). Ví đích không nhãn → vẫn T5/7702. `malicious = 1` nếu thấy tiền của tx này (hoặc của địa chỉ) bị chuyển ra ví lạ, `?` nếu chưa thấy (khi đó `confidence` tối đa `medium`).
    - (c) `unknown` → theo tx thực tế: thấy tài sản (coin, token hoặc NFT) bị chuyển ra ví lạ trong tx mẫu mà không nhận lại gì → T5/7702, `malicious = 1`; không thấy trong tx mẫu thì làm bước D2: ≥ 2 lần rút nhanh trong lịch sử → T5/KEY; còn lại → NONE, `confidence = low`. **Delegate không có trong bảng = `unknown`.** Dùng đúng bản `delegate_lookup.csv` cuối (A và B phải cùng một bản).
    - Ủy quyền xảy ra sau tx → bỏ qua delegate, theo bước D2.
14. **ADDR không bị rút:** không type nào áp dụng → âm, `confidence = low`.
15. **Cách ghi ô:** mẫu âm ghi `subtype`, `xc_chain`, `malicious` là `-`.
16. **Không dùng trạng thái hiện tại thay cho lúc tx.** Cột `code_<chain>` là hôm nay. Với chain này dùng `code_at_event`; với chain khác dùng `xc_timing`.
17. **Cùng giây giữa hai chain** (`at_time` = `xc_create_time`): coi là **không** trước, nên `xc_timing = after` → T1. Cùng block trên cùng chain: cột `code_at_event` đã so theo vị trí trong block.
18. **T6 (address poisoning), định nghĩa vận hành:** cần đủ cả ba: (i) địa chỉ này trùng ≥ 4 ký tự hex đầu và ≥ 4 ký tự hex cuối (sau `0x`) với một địa chỉ mà **người gửi tx** đã giao dịch thật trước đó; (ii) trước tx có tx mồi từ địa chỉ này (hoặc liên quan) tới người gửi: chuyển giá trị 0 hoặc token giả; (iii) tx cho sẵn là người gửi chuyển tiền thật tới địa chỉ giả. Thiếu một → không T6. T5 ưu tiên hơn T6.
19. **Chuyển coin thuần tới địa chỉ có code** (`calldata_kind = -`, `code_at_event = code`): người dùng không gọi hàm; xét T2 theo bước C3 (contract có nhận coin không, tiền có kẹt không). Contract nhận coin bình thường (WETH deposit, ví đa chữ ký) → NONE.

## 6. Bằng chứng có sẵn trong file mẫu

Mọi cột dưới đây được tính **cùng một cách cho mọi mẫu**. Ô `-` nghĩa là không áp dụng hoặc không tra được; **không** suy ra gì từ việc ô trống.

| Cột | Nghĩa |
|---|---|
| `at_time` | Giờ UTC của tx cho sẵn (đến giây) |
| `tx_hash`, `tx_url` | Tx cần xét; `tx_url` mở thẳng tx |
| `tx_status` | `success` / `fail` |
| `selector` | 4 byte đầu calldata (`-` nếu < 4 byte). Đọc cùng `calldata_kind` |
| `calldata_kind` | `call` / `-` / `text` / `short` / `unknown` (§3.1; `unknown` = không tra được tx, xem `tx_url`) |
| `calldata_len` | Số byte calldata (0 = chuyển coin thuần); đúng 32 → ca 10 |
| `value_native` | Số coin gốc (ETH/BNB) gửi kèm tx |
| `code_at_event` | Code của địa chỉ **ngay trước tx** trên chain này: `none` / `code` / `destroyed` (có lúc tx, nay mất) / `7702` / `unknown`. Tính từ tx tạo contract (block, vị trí trong block) so với tx. `7702` = hôm nay là ủy quyền 7702, tx sau ngày EIP-7702 có hiệu lực trên chain, và contract delegate hôm nay đã được tạo trước tx; **thời điểm ủy quyền không được kiểm**, xem bước D1. Hôm nay là 7702 mà tx trước ngày EIP-7702 có hiệu lực → `none`; delegate hôm nay tạo sau tx → `unknown` (xem bước A) |
| `own_create_time`, `creator` | Giờ UTC và địa chỉ tạo contract ở địa chỉ này **trên chain này**, nếu có. `code_at_event = none` mà ô này có giá trị → contract tạo **sau** tx (PCD) |
| `code_<chain>` | Code **hôm nay** trên 8 mạng: `none` / `code` / `7702` |
| `xc_nets` | Các mạng khác hôm nay có code ở cùng địa chỉ |
| `same_code_elsewhere` | Bytecode hôm nay ở chain này trùng với một mạng khác |
| `delegate_7702` | Delegate đọc từ code `0xef0100…` hôm nay; phân loại ở `delegate_lookup.csv` (ca 13). Có giá trị cả khi `code_at_event` là `none` hoặc `unknown`: khi đó delegate hôm nay **không** phải delegate lúc tx, không dùng thẳng bảng delegate (bước A) |
| `xc_timing` | Có giá trị khi `xc_nets` khác `-` và `code_at_event` không phải `code`/`7702`. `before` = có contract ở mạng khác tạo trước tx; `after` = mọi contract ở mạng khác tạo sau (hoặc cùng giây); `unknown` = không tra được giờ tạo ở ít nhất một mạng và không mạng nào là `before` |
| `xc_create_time`, `origin_net`, `deployer` | Giờ tạo sớm nhất đã biết ở mạng khác, mạng đó, và người tạo |
| `symexec_*` | Symbolic execution trên code hôm nay ở chain này (timeout, `False` có thể là chưa tìm hết đường). Chỉ gợi ý, không đủ để gán |
| `explorer_url`, `explorer_url_xc` | Trang địa chỉ trên explorer của chain này / của mạng khác liên quan |

Số giao dịch và thiệt hại cố ý **không** có trong file: tự mở explorer.

## 7. Cách dùng file Excel

- Chỉ điền các cột màu vàng ở sheet `Gan_nhan`. Giữ nguyên tên sheet.
- Làm file `double` trước. File `single` chỉ làm khi người điều phối báo.
- Mỗi phiên tối đa khoảng 40 mẫu, nghỉ giữa các phiên.
- Gán độc lập, không trao đổi với người gán kia về mẫu cụ thể cho tới buổi phân xử.
- Xong thì chạy `sample_gold check <file>` (lỗi hình thức) rồi báo người điều phối.

## 8. Đạo đức và an toàn

- Chỉ phân tích thụ động. **Không** dùng private key lộ công khai để ký hay chuyển tài sản, kể cả để "giải cứu".
- Không đưa địa chỉ đầy đủ vào paper, slide hay chat. Khi trích thì ẩn bớt, ví dụ `0x1234…abcd`.
- File trong `data/gold/` chỉ dùng nội bộ nhóm.

Lịch sử thay đổi của codebook: [GOLD_PROTOCOL.md](GOLD_PROTOCOL.md) §8 (đọc sau khi gán xong).

---

## Thay đổi v0.6.3 (2026-10-30)

Làm rõ chữ sau cổng κ 50 mẫu đầu (7 bất đồng); không đổi định nghĩa T1–T7. Mẫu nào đã gán theo v0.6.2 thì gán lại theo bản này.

1. **Rút nhanh phải không nhận lại tài sản** (§3.4, ca 7d): swap, mint, stake, deposit nhận token / LP / NFT lại trong cùng tx không tính. Ví giao dịch DeFi hay NFT chuyển 90–98% khoản vào tới router rồi nhận token lại thì **không** phải KEY.
2. **Cộng phí gas** vào lượng ra khi so ngưỡng 90%, và lượng ra không được vượt khoản vào.
3. **NFT** (ERC-721/1155) là tài sản như coin và token.
4. **Bước D2 luôn đếm cả lịch sử**, kể cả khi tx mẫu không chuyển gì hoặc `fail`.
5. **Delegate không có trong bảng = `unknown`** (ca 13c), dùng đúng bản `delegate_lookup.csv` cuối.
