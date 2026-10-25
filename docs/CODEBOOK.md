# Codebook gán nhãn vàng (D5)

Bản v0.5 (2026-10-26), sửa sau pilot 50 mẫu (κ(is_misuse) = 0,615) và sau đợt soát toàn bộ quy trình. **Chưa gán mẫu chính cho tới khi người gán A xác nhận bản này.** Dùng cho 2 người gán nhãn độc lập. Mục tiêu: Cohen's κ ≥ 0,8 (báo kèm CI, xem §7).

Taxonomy theo [requirements.md](requirements.md) §3.1 và [PLAN_V2.md](PLAN_V2.md) §1. Kế hoạch mẫu theo PLAN_V2 D5.

---

## 1. Đơn vị gán nhãn

**Mẫu chính: một mẫu = một địa chỉ (chain, address) tại thời điểm `at_date`, kèm giao dịch cho sẵn (`tx_hash`, `tx_url`).** Câu hỏi: *"Giao dịch này của người dùng tới địa chỉ này có phải là misuse không, và thuộc loại nào?"*

- Nhãn áp cho **giao dịch cho sẵn**. Với địa chỉ là EOA (KEY / ADDR / 7702) được dùng **toàn bộ lịch sử** của địa chỉ, kể cả sau `at_date`, để nhận ra sweeper; nhãn vẫn là của giao dịch tại `at_date`.
- **Pilot** (50 mẫu, không có `tx_hash`): gán theo giao dịch điển hình tới địa chỉ; có ≥ 1 tx misuse rõ ràng thì gán misuse và ghi chú.
- Chỉ xét **chain ghi trong mẫu**. Cùng địa chỉ trên chain khác là một mẫu khác.
- Chỉ số engine báo **theo địa chỉ** (chính) và theo dòng (phụ), xem §7.7.

## 2. Các trường phải điền

| Cột | Giá trị | Ý nghĩa |
|---|---|---|
| `is_misuse` | `1` / `0` / `?` | `?` chỉ dùng khi không mở được explorer; mỗi người không quá 10% số mẫu |
| `type` | `T1` … `T6` / `NONE` | **Một** type chính (thứ tự ưu tiên ở §4). `NONE` khi `is_misuse = 0` |
| `subtype` | `NCD` / `PCD` / `KEY` / `ADDR` / `7702` / `-` | Theo định nghĩa của Shao et al. (§3), giúp đối chiếu với tác giả. T2 thường là `-` |
| `xc_chain` | tên chain / `-` | Chỉ dùng với T4: chain nơi contract gốc tồn tại |
| `malicious` | `1` / `0` / `?` / `-` | Tiền có về tay bên thứ ba không. `1` = đã thấy tiền về ví bên thứ ba; `0` = đã kiểm tra và không có (hố đen, tiền nằm yên); `?` = chưa thấy nhưng có dấu hiệu; `-` = mẫu âm |
| `confidence` | `high` / `medium` / `low` | Mức chắc chắn của chính người gán |
| `evidence` | danh sách ngắn | Bằng chứng đã dùng, ví dụ `code, timing, tx, symexec, label` |
| `note` | văn bản | Bắt buộc khi `confidence = low`, `is_misuse = ?`, hoặc mẫu rơi vào ca khó ở §5 |

**Không** tra cứu nhãn của tác giả, kết quả detector hay mẫu đó thuộc tầng nào. File mẫu đã làm mù tầng, nhưng vẫn **không** hoàn toàn mù (xem §10.3).

## 3. Định nghĩa

### CA Misuse: người dùng tương tác với địa chỉ *như thể* đó là contract

- **NCD (No Code at Destination):** tại thời điểm tx, địa chỉ đích **không có code** và về sau **không** có contract nào được tạo ở địa chỉ này trên chain này (hoặc không tra được). Tx có calldata gọi hàm (selector 4 byte), hoặc gửi tiền theo cách chỉ hợp lý với contract. Type **T1** (hoặc T4, xem dưới).
- **PCD (Premature Call to Deployed contract), theo tác giả (luật `R2_PREMATURE_CALL`):** tại thời điểm tx địa chỉ **chưa có code**, nhưng một contract được tạo ở địa chỉ này trên chain này **sau** tx. Nghĩa là người dùng gọi **trước khi deploy**. Cũng là type **T1** (hoặc T4) với `subtype = PCD`; **không** phải T2.
  - Phân biệt NCD và PCD: `own_create_date` > `at_date` → PCD; contract chưa bao giờ xuất hiện → NCD.
  - Hệ quả: gần như mọi mẫu PCD đều có `code_at_event = none` (kiểm tra trên dữ liệu: 50/50 mẫu `+PCD`).

### EOA Misuse: người dùng gửi tài sản tới ví mà họ không kiểm soát được an toàn

- **KEY:** ví có private key **đã lộ công khai**. File mẫu **không** cho biết ví có nằm trong danh sách lộ key hay không (cột đó làm lộ nhãn). Người gán nhận ra KEY qua tx: tiền vào rồi bị rút trong **≤ 10 phút** về một ví lạ (không phải người gửi, không phải ví sàn / router / bridge), thấy **ít nhất 2 lần** về cùng ví đó. Thấy 1 lần thì vẫn gán nhưng `confidence` tối đa `medium`. Khi gán dương thì `malicious = 1`. Ví lộ key nhưng chưa bị rút thì **không thể gán** (hạn chế, §10.3).
- **ADDR:** người dùng gửi tới một địa chỉ ví công khai (ví dụ trong tài liệu hay code mẫu) **không phải của họ**, và tiền bị rút về ví lạ.
- **7702:** EOA đã ủy quyền EIP-7702 (code bắt đầu `0xef0100…`) tới một delegate. Tiền gửi tới bị delegate xử lý, thường là delegate sweeper. Dùng **bảng tra delegate** (§5 ca 13).

### Taxonomy 6 type

| Type | Tên | Điều kiện cần (đều phải thỏa) |
|---|---|---|
| **T1** | Gọi hàm tới địa chỉ không có code (NCD hoặc PCD của tác giả) | Tại `at` địa chỉ **không có code** trên chain này; tx có calldata hàm thật; **không** có bằng chứng contract cùng địa chỉ ở chain khác tồn tại **trước** tx. `subtype` = NCD hoặc PCD (§3) |
| **T2** | Hố đen: gửi tới contract có code mà người dùng không định gọi | Tại `at` địa chỉ **có code**, tx **thành công** (`Status: Success`) gửi coin/token vào contract không nhận hoặc gọi hàm không tồn tại, và tiền không quay lại người dùng. `subtype = -`. Hố đen: `malicious = 0`; có đường rút về ví lạ đã thấy: `1`; chưa thấy rút nhưng code có đường rút: `?`. Cờ symexec **chỉ là gợi ý, không đủ để gán**. Contract được gọi đúng hàm (token, proxy, LP) là **âm**. **Khác định nghĩa PCD của tác giả** (§3): hiếm trong dữ liệu, báo riêng |
| **T3** | Gửi token vào chính contract token | `tokentx` có `to == contractAddress` của chính token đó |
| **T4** | Cross-chain misalignment | NCD hoặc PCD trên chain này **và** cùng địa chỉ có code ở chain khác, deploy **trước** tx đầu tiên tới địa chỉ trên chain này (`deployed_before`) |
| **T5** | Key lộ / sweeper / EIP-7702 độc | KEY hoặc 7702 với delegate độc. ADDR cũng gán T5 nếu tiền bị sweeper rút |
| **T6** | Address poisoning | Địa chỉ gần giống địa chỉ người dùng hay dùng (trùng 4 ký tự đầu và 4 ký tự cuối), có transfer giá trị 0 hoặc token giả để mồi |

Mẫu **âm** (`is_misuse = 0`, `type = NONE`) gồm:
- Contract hợp lệ được gọi đúng.
- Contract deploy nhất quán cùng địa chỉ trên nhiều chain (N7).
- Ủy quyền EIP-7702 tới smart wallet hợp lệ (N6).
- Ví tự động hợp lệ như hot wallet sàn hay địa chỉ nạp (N4).
- Tin nhắn/inscription gửi tới EOA (N3).
- Giao dịch thường của người dùng.

## 4. Cây quyết định

```
1. Địa chỉ có code trên CHAIN NÀY tại thời điểm tx (code_at_event)?
   ├─ Không ──► 2
   └─ Có ──► 4
2. Tx có calldata gọi hàm / hành vi chỉ hợp lý với contract?
   ├─ Không: tx chuyển tiền thường tới EOA, hoặc calldata chỉ là event topic / văn bản (§5 ca 10) ──► 5 (xét EOA misuse)
   └─ Có ──► 3
3. Cùng địa chỉ có code ở chain khác, deploy TRƯỚC tx đầu tiên trên chain này?
   ├─ Có ──► T4 (ghi xc_chain; subtype NCD / PCD theo §3)
   ├─ Có nhưng deploy SAU ──► T1 (ghi note "xc deployed_after")
   ├─ Có ở chain khác nhưng sau khi mở explorer vẫn không biết ngày tạo ──► T4, confidence = low
   └─ Không có contract ở chain khác ──► T1 (subtype NCD / PCD theo §3)
4. Code trên chain này tại `at` có phải là contract người dùng định gọi?
   ├─ Có, và tx gọi đúng hàm ──► NONE (âm)
   ├─ Là EIP-7702 delegation (0xef0100…) ──► 5
   └─ Không: tx tại `at` thành công và tiền bị giữ/chuyển đi? (tx lỗi `Fail` thì không mất tiền)
        ├─ Có ──► T2 (subtype -; malicious = 0 hố đen / 1 rút về ví lạ / ? chưa thấy rút)
        └─ Không ──► NONE
5. EOA: tiền bị rút ≤ 10 phút về ví lạ (≥ 2 lần) / delegate độc theo bảng tra?
   ├─ Có ──► T5 (subtype KEY / ADDR / 7702; `malicious` = 1 / ? theo §3)
   ├─ Địa chỉ giống địa chỉ quen thuộc + tx mồi giá trị 0 ──► T6
   └─ Không (ví thường, sàn, smart wallet hợp lệ) ──► NONE (âm)
```

Thứ tự ưu tiên khi thỏa nhiều type: **T4 > T1**; **T5 > T6**; **T2** áp dụng độc lập với phía EOA. Type phụ, nếu có, ghi trong `note`.

### 4.1. Quy trình từng bước (làm đúng thứ tự, mỗi bước có bằng chứng bắt buộc)

**Định nghĩa dùng chung (không tự diễn giải khác):**
- *Tx tại `at`*: mẫu chính cho sẵn `tx_hash`. Pilot không có `tx_hash`: mở `explorer_url`, tab Transactions, chọn tx gần nhất tới địa chỉ trước hoặc đúng `first_tx_date` / ngày xét.
- *Thành công*: trang tx có `Status: Success`. `Fail` thì tiền không chuyển, không mất tiền (trừ gas) → coi như không có misuse về tiền, trừ NCD/PCD (ca khó 8: tx lỗi hay thành công đều tính nếu địa chỉ không có code).
- *Gọi đúng hàm*: contract đã verify, `Method` của tx được giải mã ra tên hàm có thật (approve, transfer, swap, submit…).
- *Ví lạ*: ví nhận tiền KHÔNG phải người gửi, KHÔNG phải ví sàn / router / bridge có nhãn trên explorer.
- *Rút nhanh*: tiền ra khỏi địa chỉ trong **≤ 10 phút** sau khi vào.
- *Mặc định khi phân vân*: sau khi làm đủ các bước vẫn không chứng minh được misuse → `is_misuse = 0`, `confidence = low`, ghi `note`. Chỉ dùng `?` khi **không mở được explorer** (tối đa 10% số mẫu).

**Bước A. Địa chỉ có code tại `at` không?** (`code_at_event` ở mẫu chính; pilot: nếu `own_create_date` / ngày tạo contract sau tx thì tại `at` là không có code.)
- Không có code → **Bước B**.
- Có code, là 7702 (`0xef0100…`) → **Bước D**.
- Có code → **Bước C**.

**Bước B. Không có code tại `at` (NCD hoặc PCD).** Tx có calldata hàm thật (selector 4 byte, không phải event topic hay văn bản) hoặc gửi coin theo kiểu chỉ hợp với contract?
- Không → coi như chuyển tiền thường tới EOA → **Bước D** (xét KEY/ADDR/7702).
- Có → cùng địa chỉ có code ở chain khác, tạo **trước** tx đầu tiên ở chain này → **T4** (ghi `xc_chain`); tạo sau → **T1** (note "xc deployed_after"); có contract ở chain khác nhưng sau khi mở explorer của chain đó vẫn không biết ngày tạo → **T4, `confidence = low`**; không có contract nào ở chain khác → **T1**.
- `subtype` (cho T1 và T4): `PCD` nếu `own_create_date` > `at_date` (contract được tạo trên chain này sau tx), ngược lại `NCD`.

**Bước C. Có code tại `at` (hố đen, T2).** Chỉ gán T2 khi đủ **cả 3 điều kiện**:
1. Tx tại `at` thành công;
2. Contract không phải thứ người dùng định gọi: tx gửi coin vào contract không có hàm nhận coin, hoặc gọi hàm không có trong contract (`Method` hiện selector thô `0x…` trên contract đã verify);
3. Tiền không quay lại người dùng: nằm yên trong contract (hố đen, `malicious = 0`), hoặc đi ra ví lạ (`malicious = 1`), hoặc code có đường rút nhưng chưa thấy rút (`malicious = ?`).
Thiếu một điều kiện → `NONE`. Token, proxy, LP, router được gọi đúng hàm → `NONE`. Cờ `symexec_*` chỉ để gợi ý chỗ cần xem, **không bao giờ đủ để gán một mình**.

**Bước D. EOA.**
- Mở tab Transactions của chính địa chỉ. Thấy **≥ 2 lần** tiền vào rồi ra trong **≤ 10 phút** về cùng một ví lạ → **T5 / KEY**, `is_misuse = 1`, `malicious = 1`. Chỉ thấy 1 lần → như trên nhưng `confidence` tối đa `medium`. Không thấy lần nào → không phải KEY (xét tiếp các dòng dưới).
- `subtype`: `KEY` là mặc định cho mẫu hình rút nhanh. `ADDR` chỉ khi explorer ghi rõ đó là ví công khai dùng làm ví dụ. Hai subtype này cùng là T5 nên không ảnh hưởng κ của `type`.
- Địa chỉ đang là 7702 (`delegate_7702` có giá trị): tra delegate trong `delegate_lookup.csv` rồi xem ca khó 13.
- Tiền gửi tới ví công khai không phải của người gửi (ví trong tài liệu mẫu) và bị rút về ví lạ → T5/ADDR. Không thấy rút → `NONE`, `confidence = low`.
- Địa chỉ giống địa chỉ quen + tx mồi giá trị 0 → **T6**.
- Còn lại (ví thường, sàn, smart wallet hợp lệ) → `NONE`.

**Bước E. Điền ô.** Mẫu âm: `type = NONE`, `subtype = xc_chain = malicious = -`. `confidence = high` chỉ khi đã mở explorer xem tx tại `at`; chỉ dựa vào cột bằng chứng thì tối đa `medium`. `evidence` ghi đủ nguồn đã dùng (`code`, `tx`, `timing`, `symexec`, `label`). `note` bắt buộc khi `confidence = low`, `?`, hoặc ca khó §5.

**Ví dụ từ pilot (đã chốt, dùng làm chuẩn):**

| Mẫu | Quan sát | Nhãn chuẩn |
|---|---|---|
| P008, P010, P032, P025 | token / LP / proxy được gọi đúng hàm (`approve`, `transfer`), tx thành công | `0`, NONE (cờ symexec "không có đường rút" **không** đổi nhãn) |
| P002 | contract đa chain cùng bytecode, tx gọi đúng hàm swap | `0`, NONE |
| P005 | 167 tx vào, 164 tx lỗi, 0 tx ra; proxy `submit()` đúng | `0`, NONE (tx lỗi không mất tiền) |
| P024 | tx gửi 0,02 ETH khi chưa có code; contract cài sau rồi rút đúng khoản đó về ví lạ | `1`, **T1/PCD** (contract xuất hiện sau tx), `malicious = 1` (v0.4 gán T2/PCD; v0.5 sửa theo định nghĩa PCD của tác giả) |
| P012 | 7 tx vào, 33 tx ra chủ yếu vào router Uniswap, không có cặp vào-ra ≤ 10 phút về ví lạ | `0`, NONE, `confidence = medium` (không thấy mẫu hình rút nhanh) |
| P038 | 7702 tới Forwarder; 1,49 ETH vào, 1,43 ETH ra về ví lạ | `1`, T5/7702, `malicious = 1`, high |
| P034 | 7702 tới forwarder; 3 tx vào đều 0 ETH, chưa thấy rút | `1`, T5/7702, `malicious = ?`, medium |
| P009 | calldata chỉ là event topic `0xddf252ad…` tới EOA | `0`, NONE (ca khó 10) |
| P036 | eth không code; code chỉ ở bsc_testnet, không tra được ngày tạo | `1`, T4, `confidence = low` (ca khó 12) |

## 5. Ca khó (đọc kỹ trước khi gán)

1. **Contract ở chain khác deploy SAU tx đầu tiên** (`xc_timing = deployed_after`): **không** gán T4. Người dùng khi đó không thể copy từ chain kia. Gán T1, ghi note.
2. **Không biết thời điểm deploy ở chain khác** (`xc_timing = unknown`): mở explorer của chain đó để xem tx tạo contract. Nếu vẫn không biết thì gán T4 với `confidence = low`. (Quy tắc này là duy nhất, §4 bước 3 và §4.1 bước B áp dụng như vậy.)
3. **Cùng địa chỉ, cùng contract trên mọi chain, kể cả chain này** (Multicall3, Permit2, Safe, EntryPoint…): là **âm** (N7), trừ khi tx thật sự sai hàm.
4. **Địa chỉ hệ thống / precompile** (`0x000…000X`, predeploy của OP-stack `0x4200…`, system contract của BSC `0x…1000`): thường là âm. Tx gửi nhầm tới predeploy của chain *khác* (ví dụ WETH OP `0x4200…0006` trên ETH) thì gán T4.
5. **Người gửi tx đầu tiên là chính deployer** (đội dự án gửi nhầm chain): vẫn là T4. Ghi note `self-misuse`.
6. **EOA ủy quyền 7702 cho smart wallet hợp lệ** (MetaMask Delegator, Safe, Coinbase…) và chủ ví vẫn rút tiền bình thường: **âm** (N6). Phải xem tiền thực tế đi đâu, **không** suy ra từ cờ symexec (cột này đã bỏ khỏi mẫu chính vì True ở mọi mẫu 7702). Nếu EOA đã lộ key (KEY) thì vẫn là T5/KEY, dù delegate là ví hợp lệ. Lúc đó sweeper rút bằng chính key.
7. **Ví sàn hay địa chỉ nạp có auto-sweep**: tiền bị chuyển đi nhanh nhưng **về ví tổng của sàn**, nên là âm (N4). Sweeper độc thì chuyển về ví lạ và thường trả gas cao.
8. **Tx chỉ mất gas** (value = 0) tới NCD/PCD: vẫn là misuse (T1/T4). Thiệt hại nhỏ không làm đổi nhãn.
9. **Một địa chỉ vừa có contract xuất hiện sau tx vừa có contract ở chain khác** (PCD-XC): gán T4 nếu contract ở chain khác deploy **trước** tx (subtype PCD); gán T1/PCD nếu contract ở chain khác deploy sau hoặc không có. Ghi `xc_chain` trong note.
10. **Calldata là văn bản** (UTF-8 đọc được) hoặc **event topic** (ví dụ `0xddf252ad…`) gửi tới EOA: không phải gọi hàm. Xét như chuyển tiền thường và đi tiếp bước 5 (KEY/ADDR/7702). Không có dấu hiệu nào ở bước 5 thì là âm (N3).
11. **Contract xuất hiện SAU tx** (lúc tx địa chỉ chưa có code): theo nhánh NCD/PCD (T1/T4 với subtype PCD), kể cả khi kẻ cài contract rồi rút đúng khoản đó (P024: T1/PCD, `malicious = 1`).
12. **Testnet** làm chain gốc cho T4: có tính (khớp 8 mạng của `crosschain_matrix`); ghi `xc_chain` là tên testnet, không tra được ngày tạo thì `confidence = low`. Paper báo T4 có và không có testnet.
13. **EOA 7702: bảng tra delegate.** Trước khi gán, A và B **cùng phân loại từng delegate** trong `data/gold/delegate_lookup.csv` (mỗi người điền cột riêng `class_A` / `class_B` từ mã nguồn đã verify hoặc nhãn trên explorer, không dùng symexec; bất đồng thì thống nhất vào `final_class` và ghi `source`). Ba lớp: `legit_wallet` / `forwarder_sweeper` / `unknown`. Quy tắc: (a) `legit_wallet` → NONE, trừ khi thấy tiền bị rút về ví lạ (khi đó theo KEY, ca 6); (b) `forwarder_sweeper` → T5/7702, `malicious = 1` nếu thấy rút, `?` nếu chưa (`confidence` tối đa `medium`); (c) `unknown` → quyết định theo tx thực tế: thấy rút → T5/7702, `malicious = 1`; không thấy → NONE, `confidence = low`. Vì nhiều mẫu dùng chung một delegate, phân loại delegate gần như quyết định nhãn 7702: bắt buộc nêu ở §10.3 và tính CI κ theo cụm delegate. Vừa lộ key vừa bị gắn delegate: theo ca 6 (KEY nếu delegate hợp lệ), nếu delegate là sweeper thì subtype `7702` kèm note "KEY?".
14. **ADDR không có sweep:** không có type nào áp dụng nếu không thấy tiền bị rút về ví lạ → âm, `confidence = low`.
15. **Cách ghi ô:** mẫu âm ghi `subtype`, `xc_chain`, `malicious` là `-`. `confidence = high` chỉ khi đã mở explorer xem tx tại `at`; chỉ dựa vào cột bằng chứng thì tối đa `medium`.
16. **Đơn vị và thời gian:** xem §1. Nhãn là của tx cho sẵn tại `at_date`; chỉ với EOA mới được dùng lịch sử sau `at_date` để nhận ra sweeper. Với địa chỉ có code, **không** dùng trạng thái code hiện tại để thay cho `code_at_event`.

## 6. Bằng chứng có sẵn trong file mẫu

Mỗi mẫu có sẵn các cột sau (không cần tự tra, trừ khi muốn kiểm tra thêm):

| Cột | Nguồn |
|---|---|
| `at_date`, `tx_hash`, `tx_url`, `selector`, `value_native` | Giao dịch cần xét (mẫu chính). `selector = -` là chuyển coin thuần, không calldata. `tx_url` mở thẳng giao dịch trên explorer |
| `code_at_event`, `own_create_date` | Trạng thái code **lúc `at_date`** (`none` / `code` / `7702`) và ngày contract được tạo trên chain này. Dùng cho NCD / PCD / T4 |
| `code_<chain>`, `xc_nets`, `same_code_elsewhere` | `eth_getCode` **hiện tại** trên 8 mạng, tra cùng một cách cho **mọi** mẫu: `none` / `code` / `7702`; `xc_nets` = các mạng khác có code; `same_code_elsewhere` = bytecode ở chain này trùng với một mạng khác |
| `deployer`, `create_kind`, `origin_net`, `first_create_date` | Etherscan / Binplorer `getcontractcreation`. Chỉ điền khi chain này **không** có code mà mạng khác có (tình huống T4) |
| `first_tx_date`, `xc_timing` | tx đầu tiên tới địa chỉ trên chain này (Etherscan) |
| `symexec_*` | Symbolic execution trên code ở chain này (`transfer_all_eth`, `delegatecall`, …): kết quả của tác giả, thiếu thì nhóm tự chạy cùng engine (timeout 120 s, nên `False` có thể là chưa tìm hết đường). Chỉ gợi ý, không đủ để gán |
| `delegate_7702` | Delegate đọc từ code `0xef0100…` hiện tại trên chain này; phân loại ở `delegate_lookup.csv` (ca 13) |
| `explorer_url`, `explorer_url_xc` | Link Etherscan/BscScan… để tự kiểm tra tx và code |

**Đã bỏ khỏi mẫu chính (v0.5):** `redeploy` (không giải thích được, điền ~20% ở dương và ~1% ở âm nên làm lộ nhãn), `delegate_symexec_transfer` (True ở cả 264 mẫu 7702, là đặc trưng của engine), `delegate_known_wallet` (rỗng ở mọi mẫu; thay bằng bảng tra delegate). Pilot vẫn giữ nguyên các cột cũ.

Ô ghi `-` nghĩa là **không tra được hoặc không áp dụng**; không suy ra gì từ việc ô đó trống. Số giao dịch và thiệt hại của tác giả cố ý **không** đưa vào file: tự mở `explorer_url` / `tx_url`.

Các cột `code_<chain>` là trạng thái **hiện tại**, không phải lúc tx. Khi kết luận phụ thuộc vào thời điểm (T4, NCD/PCD), dùng `code_at_event` / `own_create_date` hoặc mở explorer.

## 7. Quy trình (tiền đăng ký, chốt TRƯỚC khi gán mẫu chính)

1. **Pilot 50 mẫu** (`data/gold/pilot50_items.csv`): đã gán độc lập, κ(`is_misuse`) = 0,615, κ(`type`) = 0,823. Đây chỉ là mốc "trước khi sửa codebook", **không** phải κ chính thức. Con số 0,951 tính lại sau khi đã biết bất đồng **không được báo**.
2. **Không có pilot 2** (quyết định 2026-10-25).
3. **Bảng tra delegate:** A và B cùng điền `delegate_lookup.csv` (ca 13) trước khi gán mẫu nào.
4. **Gán 200 mẫu gán đôi TRƯỚC, cả A và B** (file `annotator_main_double_<A|B>.xlsx`), mỗi người gán độc lập. Chưa ai gán mẫu "single" cho tới khi xong bước này và kiểm cổng:
   - **Cổng sau 50 mẫu gán đôi đầu** (50 mẫu có `item_id` nhỏ nhất trong tập gán đôi): tính κ(`is_misuse`). Cổng này là **chẩn đoán**, không phải phép thử thống kê: với n = 50 thì κ ≈ 0,85 vẫn có khoảng 27% khả năng rơi dưới 0,8, nên cổng đặt ở **κ < 0,70** (dưới ngưỡng này là hỏng hệ thống). κ ≥ 0,70 thì gán tiếp 150 mẫu gán đôi còn lại.
   - Nếu κ < 0,70: dừng, họp phân xử, sửa codebook (tăng phiên bản), gán lại 50 mẫu đó. κ của 50 mẫu đã dùng để sửa codebook chỉ là **κ hiệu chỉnh** (không báo như κ chính thức); thay chúng bằng 50 mẫu "single" có `double_extra_rank` nhỏ nhất (cột này nằm trong `main_key.csv`, thứ tự cố định từ trước), để có đủ 200 mẫu gán đôi sau khi chốt codebook.
   - **κ chính thức** = κ(`is_misuse`) của các mẫu gán đôi gán SAU khi chốt codebook, báo kèm CI (bootstrap theo cụm delegate/deployer), PABAK, Gwet AC1, % đồng ý, κ khi bỏ `?` và κ trên **tập khó** (§7.8). Báo dù thấp hơn 0,8: không điều chỉnh để đạt ngưỡng.
5. **Phân xử:** A và B họp, mỗi mẫu bất đồng thống nhất một nhãn cuối (`gold_adj`), ghi lý do; nếu không thống nhất thì nhãn `?` (báo ở kịch bản "tính 0" và "tính 1"). Nhãn cuối (`gold_eval.final_gold`): mẫu gán đôi = nhãn phân xử; mẫu gán đơn = nhãn của B. Có cột `gold_source`.
6. **Gán 558 mẫu "single"** (file `annotator_main_single_B.xlsx`) chỉ sau bước 4–5. B gán một mình phần lớn mẫu (74%), nên **sai số gán đơn** được ước lượng từ tỉ lệ B khác nhãn phân xử trên 200 mẫu gán đôi và báo trong paper.
7. **Thiết kế mẫu (tiền đăng ký; `sample_gold.py`, hash ở FINDINGS_LOG):**
   - Khung: test ∪ out_of_time của `dataset_v2` (bỏ `excluded`), 2.010 dòng / 1.680 địa chỉ. Đơn vị lấy mẫu là địa chỉ; mỗi địa chỉ thuộc đúng một tầng (tầng đầu tiên có địa chỉ đó). `n_rows` = số dòng của địa chỉ trong **toàn khung** (Σ = 2.010). Dòng đại diện là dòng engine gắn cờ nếu có.
   - Dương (mọi tầng `+`, 442 địa chỉ) và âm bị engine gắn cờ (luật cứng hoặc R ≥ τ_warn = 63,0; 3 mẫu N8): **lấy hết** (điều tra toàn bộ, trọng số 1). Âm không cờ: mẫu ngẫu nhiên đơn giản trong từng ô (tầng × chain), chia đều eth/bsc. Lô 1 = 758 mẫu (442 dương + 316 âm), 200 mẫu gán đôi.
   - Một file duy nhất cho lô 1, dương và âm xáo lẫn. Người thiết kế (B) biết thiết kế này nên phải ghi vào hạn chế (§10.3).
   - Trọng số: `w_addr` = cỡ ô / số địa chỉ đã gán trong ô; `w_row` = `w_addr` × số dòng của địa chỉ trong khung. Tính lại theo số mẫu đã gán thực tế (`gold_eval.gold_weights`).
   - **Lô 2 (tuỳ thời gian):** danh sách 922 âm dự phòng đã xáo cố định (`main_reserve_key.csv`), chia lô 50 mẫu; trong từng ô là tiếp nối thứ tự xáo của lô 1 nên tập đã gán của ô luôn là mẫu ngẫu nhiên đơn giản; giữa các ô xen kẽ theo tỉ lệ cỡ ô. **Chỉ dừng ở ranh giới lô, theo ngân sách hoặc hạn chót, không theo kết quả engine.** Lô 2 toàn mẫu âm nên mất tính mù: **mỗi lô 50 mẫu âm trộn thêm ~12 mẫu dương lấy lại từ lô 1 (đổi mã, người gán không biết là gán lại)**. Các mẫu lấy lại này đo độ nhất quán của chính người gán và **không** tính vào ước lượng. Nên giao lô 2 cho người chưa xem thiết kế (A).
8. **Quy tắc báo (tiền đăng ký):**
   - (a) **Chỉ số chính theo địa chỉ** (`gold_eval.evaluate(unit='addr')`); theo dòng (`unit='row'`) báo phụ để so với các số đã có. Cỡ mẫu hiệu dụng theo dòng chỉ cỡ vài chục vì một địa chỉ có nhiều dòng.
   - (b) Báo chỉ số engine **hai lần**: đầy đủ, và bỏ tầng KEY/ADDR (`exclude_strata`), vì nhãn KEY/ADDR dựa vào mẫu hình rút nhanh trùng luật `sweeper` của engine.
   - (c) Ô 0 sự kiện: cận Jeffreys (chính), Clopper–Pearson (bảo thủ) cho số dương ẩn. Ô điều tra toàn bộ không lấy lại mẫu khi bootstrap.
   - (d) Dấu `?` báo ba kịch bản: tính 0, tính 1, bỏ mẫu.
   - (e) Không chọn thêm tầng để gán sau khi đã xem chỉ số engine theo nhãn vàng.
   - (f) **Tập khó:** mẫu mà luật cơ học tham chiếu (`is_misuse = 1` nếu `code_at_event = none` và `selector ≠ -`, hoặc có `delegate_7702`; còn lại 0) khác nhãn cuối. Báo κ(A, B) trên tập khó và κ của luật cơ học với nhãn cuối, để người đọc thấy phần κ nào chỉ là hệ quả của cột bằng chứng.
   - (g) **Chọn case study theo luật, không chọn tay:** 5 ca TP có R cao nhất, 5 ca FP và 5 ca FN rút ngẫu nhiên (seed 0) từ danh sách đầy đủ; khi trích địa chỉ thì ẩn bớt (§8).
   - (h) Báo riêng "silver" (nhãn luật của tác giả trên toàn dataset) và `key_sweep` (đo tự động); **không** cộng vào số nhãn vàng.
9. **Đăng ký trước (preregistration):** trước khi gán, ghi sha256 của: `docs/CODEBOOK.md`, `src/address_misuse/gold_eval.py`, `src/address_misuse/engine/` (evaluate), `data/interim/engine_eval.parquet`, `data/interim/engine_metrics.json` (τ_warn = 63,0), `data/gold/main_items.csv`, `main_key.csv`, `main_reserve_key.csv` vào FINDINGS_LOG và gắn git tag `prereg-gold-v0.5`. Mọi thay đổi sau tag phải ghi là sai lệch so với đăng ký.

## 8. Đạo đức, an toàn và cam kết

- Chỉ phân tích thụ động. **Không** dùng private key lộ công khai để ký hay chuyển tài sản, kể cả để "giải cứu".
- Không đưa địa chỉ cá nhân đầy đủ vào paper, slide hay chat. Khi trích thì ẩn bớt, ví dụ `0x1234…abcd`.
- File trong `data/gold/` chứa địa chỉ đầy đủ, chỉ dùng nội bộ nhóm.
- **Cam kết mù:** trong lúc gán, người gán **không mở** `main_key.csv`, `main_reserve_key.csv`, `data/final/dataset_v2.parquet`, `data/interim/engine_eval.parquet` (các file nối được với nhãn), cũng không mở file của người gán kia. Các file này nằm trong repo nên cam kết dựa vào tự giác; ghi vào §10.3.

## 9. Lịch sử thay đổi

- **v0.1 (2026-10-16):** bản nháp đầu, trước pilot.
- **v0.2 (2026-10-19):** bỏ các cột `n_tx`, `n_misuse_tx`, `cost_native` khỏi file mẫu (làm lộ nhãn: chỉ có ở mẫu thuộc dữ liệu tác giả); ô không tra được ghi `-` thay vì để trống.
- **v0.3 (2026-10-19):** bỏ cột `delegate_flag`, thay bằng `delegate_symexec_transfer` và `delegate_known_wallet`; tầng `neg_n6_7702_benign` đổi thành `eoa_7702_other`; bổ sung ca khó 6; mọi cột code/delegate tra trực tiếp cho mọi mẫu.
- **v0.4 (2026-10-25):** T2 cần tx thành công và sai ý định; KEY gán dương theo tx rút nhanh; `malicious` có 4 giá trị; ca khó 10–15; bỏ điều kiện `delegate_known_wallet = -` làm bằng chứng độc.
- **v0.4.1 (2026-10-25):** thêm §4.1; **không** có cột danh sách khoá lộ (làm lộ nhãn 60/60 mẫu KEY).
- **Thiết kế mẫu (2026-10-25, không đổi quy tắc gán):** lấy hết dương và âm bị engine gắn cờ, âm lấy mẫu có trọng số theo (tầng, chain) và theo dòng, danh sách âm dự phòng cho lô 2.
- **v0.5 (2026-10-26), sau đợt soát của advisor:**
  - PCD **đổi theo tác giả**: gọi trước khi contract được deploy (`R2_PREMATURE_CALL`); là type T1/T4 với subtype PCD, không còn là T2. T2 chỉ còn là hố đen (code tại `at`). P024 đổi từ T2/PCD sang T1/PCD.
  - Đơn vị và thời gian: nhãn là của tx cho sẵn tại `at_date`; chỉ EOA được dùng lịch sử sau đó (§1, ca 16).
  - Quy tắc "không rõ ngày tạo ở chain khác" thống nhất: T4, `confidence = low` (trước đây §4 ghi T1, §5 ghi T4).
  - 7702: bảng tra delegate do A và B cùng phân loại (ca 13); bỏ `delegate_symexec_transfer`, `delegate_known_wallet`, `redeploy` khỏi mẫu chính.
  - Bỏ `leaklist` khỏi danh sách bằng chứng.
  - §7 viết lại: 200 mẫu gán đôi làm trước bởi cả A và B; cổng κ < 0,70 là chẩn đoán; danh sách bù theo `double_extra_rank`; phân xử; nhãn cuối; lô 2 trộn mẫu dương lấy lại; chỉ số chính theo địa chỉ; tập khó và luật cơ học tham chiếu; luật chọn case study; danh sách hash đăng ký trước.
  - §8: cam kết mù. §10 và §10.1–10.2 chuyển thành lịch sử; §10.3 bổ sung hạn chế.

## 10. Lịch sử: agenda sửa codebook v0.4 (từ pilot 50 mẫu, người gán A, 2026-10-21)

**Phần này chỉ là lịch sử, đã được áp dụng ở v0.4–v0.5 (xem §9). Quy tắc hiện hành nằm ở §1–§7.** Giữ lại để tra dấu vết quyết định; các mệnh đề dưới đây có thể khác quy tắc hiện hành (đặc biệt T2/PCD, đã đổi ở v0.5).

Danh sách điểm mơ hồ gặp khi gán pilot:

1. **T2: §3 mâu thuẫn §4.** Dẫn chứng: P024. (v0.5: PCD thành T1/T4 subtype PCD; T2 chỉ là hố đen.)
2. **Testnet có tính là chain gốc cho T4 không?** Dẫn chứng: P036. (Chốt: có tính, ca 12.)
3. **Calldata là event payload có tính là "gọi hàm" không?** Dẫn chứng: P009. (Chốt: không, ca 10.)
4. **Thứ tự ưu tiên KEY và 7702.** (Chốt: ca 13.)
5. **Tiêu chí `malicious = 1` khi chưa thấy tx rút.** Dẫn chứng: P030, P034, P045, P050. (Chốt: ca 13.)

### 10.1. Đề xuất xử lý cho agenda trên (2026-10-25)

Đã áp dụng thành v0.4 và được sửa tiếp ở v0.5. Không dùng làm quy tắc. Đề xuất ban đầu về danh sách đen/`delegate_known_wallet` làm bằng chứng đã bị bỏ: bằng chứng gán nhãn phải độc lập với engine.

### 10.2. Điểm cần chốt thêm sau κ pilot (2026-10-25: κ(is_misuse) = 0,615)

Đã áp dụng ở v0.4/v0.4.1: T2 cần tx sai ý định (điểm 6); KEY chỉ gán dương khi thấy mẫu hình rút nhanh (điểm 7); quy ước ô (điểm 8).

### 10.3. Hạn chế đã biết của nhãn vàng (ghi vào paper)

- **KEY**: vì file mẫu không biết ví có nằm trong danh sách lộ key hay không, KEY chỉ gán được khi thấy mẫu hình rút nhanh. Ví lộ key mà chưa bị rút sẽ bị gán âm (`NONE`), nên nhãn vàng KEY là **cận dưới** của KEY thật và độ chính xác của luật `leaked_key` bị tính thấp hơn thực tế. Nhãn KEY dựa vào cùng mẫu hình rút nhanh với luật `sweeper` của engine: báo chỉ số engine thêm trên tập bỏ KEY/ADDR (§7.8b).
- **Đã cân nhắc và bỏ**: thêm cột `leak_list` (làm nhãn KEY thành cơ học ở 60/60 mẫu).
- **Phép đo tự động** trên toàn danh sách (không cần người gán): `key_sweep`, xem FINDINGS_LOG 2026-10-25. Chỉ tính coin gốc nên là cận dưới.
- **Vòng tròn với engine (circularity):** các cột bằng chứng (`code_at_event`, `own_create_date`, `xc_*`, phân loại delegate, mẫu hình rút nhanh) cũng là đầu vào của engine, nên nhãn vàng và engine không hoàn toàn độc lập; precision/recall có thể bị thổi phồng. Báo kèm luật cơ học tham chiếu (§7.8f) để thấy mức này.
- **Không mù hoàn toàn theo tầng:** một luật cơ học 2 dòng trên cột bằng chứng đạt κ ≈ 0,80 với nhãn pilot (advisor kiểm 2026-10-26), nên κ cao chưa chứng tỏ người gán độc lập với dữ liệu tác giả. Báo κ trên tập khó.
- **B gán đơn 74% mẫu và là người thiết kế** (biết thiết kế mẫu, biết dương chiếm 58%): thiên lệch có thể xảy ra, ước lượng bằng sai khác với nhãn phân xử (§7.6).
- **7702:** 264 mẫu, chỉ 32–33 delegate; mẫu cùng delegate không độc lập, nhãn phụ thuộc phân loại delegate (ca 13). CI κ tính theo cụm.
- **Rò rỉ trong repo:** `dataset_v2.parquet`, `engine_eval.parquet`, `main_items.csv` nằm trong repo; `main_key.csv` thì không (gitignore). Mù dựa vào cam kết (§8). Chưa kiểm tra repo có công khai không.
- **κ ở n = 50 yếu về thống kê** (khả năng dừng nhầm ~27% khi κ thật 0,85; vượt cổng ~28% khi κ thật 0,75): vì vậy cổng chỉ là chẩn đoán ở mức 0,70 và κ chính thức dùng cả 200 mẫu.
- **Khung chỉ có 2.010 dòng / 1.680 địa chỉ:** "~2.000 nhãn" nghĩa là gán hết khung. Ta gán 100% dương và cảnh báo của engine, cộng mẫu có trọng số của âm (758 mẫu lô 1; tối đa 1.680 địa chỉ nếu chạy hết lô 2).
