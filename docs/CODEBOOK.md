# Codebook gán nhãn vàng (D5)

Bản v0.4 (2026-10-25), sửa sau pilot 50 mẫu (κ(is_misuse) = 0,615, chưa đạt). **Chưa dùng cho lô lớn** cho tới khi pilot 2 (khoảng 30 mẫu mới) đạt κ ≥ 0,8. Dùng cho 2 người gán nhãn độc lập. Mục tiêu: Cohen's κ ≥ 0,8.

Taxonomy theo [requirements.md](requirements.md) §3.1 và [PLAN_V2.md](PLAN_V2.md) §1. Kế hoạch mẫu theo PLAN_V2 D5.

---

## 1. Đơn vị gán nhãn

**Một mẫu = một cặp (chain, address).** Câu hỏi cần trả lời: *"Giao dịch người dùng gửi tới địa chỉ này trên chain này có phải là misuse không, và thuộc loại nào?"*

- Gán theo **giao dịch điển hình** tới địa chỉ, tức là phần lớn tx misuse, không phải từng tx riêng.
- Nếu địa chỉ có cả tx đúng lẫn tx misuse, vẫn gán là misuse khi có **≥ 1 tx misuse rõ ràng**, rồi ghi chú lại.
- Chỉ xét **chain ghi trong mẫu**. Cùng địa chỉ trên chain khác là một mẫu khác.

## 2. Các trường phải điền

| Cột | Giá trị | Ý nghĩa |
|---|---|---|
| `is_misuse` | `1` / `0` / `?` | `?` chỉ dùng khi thiếu bằng chứng; mỗi người không quá 10% số mẫu |
| `type` | `T1` … `T6` / `NONE` | **Một** type chính (thứ tự ưu tiên ở §4). `NONE` khi `is_misuse = 0` |
| `subtype` | `NCD` / `PCD` / `KEY` / `ADDR` / `7702` / `-` | Theo định nghĩa của Shao et al. (§3), giúp đối chiếu với tác giả |
| `xc_chain` | tên chain / `-` | Chỉ dùng với T4: chain nơi contract gốc tồn tại |
| `malicious` | `1` / `0` / `?` / `-` | Tiền có về tay bên thứ ba không (sweeper, contract cài sẵn, delegate độc). `1` = đã thấy tiền về ví bên thứ ba; `0` = đã kiểm tra và không có (ví dụ hố đen, tiền nằm yên); `?` = chưa thấy nhưng có dấu hiệu; `-` = mẫu âm |
| `confidence` | `high` / `medium` / `low` | Mức chắc chắn của chính người gán |
| `evidence` | danh sách ngắn | Bằng chứng đã dùng, ví dụ `code, timing, tx, symexec, label` |
| `note` | văn bản | Bắt buộc khi `confidence = low`, `is_misuse = ?`, hoặc mẫu rơi vào ca khó ở §5 |

**Không** tra cứu nhãn của tác giả, kết quả detector hay mẫu đó thuộc tầng nào. File mẫu đã được làm mù (blind) để tránh thiên lệch.

## 3. Định nghĩa

### CA Misuse: người dùng tương tác với địa chỉ *như thể* đó là contract

- **NCD (No Code at Destination):** tại thời điểm tx, địa chỉ đích **không có code** (`getCode == 0x`). Tx có calldata gọi hàm (selector 4 byte), hoặc gửi tiền theo cách chỉ hợp lý với contract. Tx không revert nhưng không có tác dụng.
- **PCD (Planted/Present Code at Destination):** địa chỉ đích **có code**, nhưng code đó không phải contract người dùng định gọi. Có thể là contract khác deploy sau, hoặc contract cố ý cài sẵn để nhận tiền. Kết quả là tiền bị giữ lại hoặc bị chuyển đi.

### EOA Misuse: người dùng gửi tài sản tới ví mà họ không kiểm soát được an toàn

- **KEY:** ví có private key **đã lộ công khai** (GitHub/StackExchange) và có tx tới **sau ngày lộ**. Gán dương khi ví nằm trong danh sách lộ key (ghi `leaklist` vào `evidence`); `malicious = 1` nếu thấy tiền bị rút trong vòng 10 phút về một ví lạ (không phải người gửi, không phải ví sàn hay router), `?` nếu chưa thấy rút. Không biết ngày lộ thì vẫn gán nhưng `confidence` tối đa `medium`.
- **ADDR:** người dùng gửi tới một địa chỉ ví công khai (ví dụ trong tài liệu hay code mẫu) **không phải của họ**.
- **7702:** EOA đã ủy quyền EIP-7702 (code bắt đầu `0xef0100…`) tới một delegate. Tiền gửi tới bị delegate xử lý, thường là delegate sweeper.

### Taxonomy 6 type

| Type | Tên | Điều kiện cần (đều phải thỏa) |
|---|---|---|
| **T1** | Gọi hàm tới địa chỉ không có code | NCD; **không** có bằng chứng contract cùng địa chỉ ở chain khác tồn tại **trước** tx |
| **T2** | PCD: contract người dùng không định gọi | Tại thời điểm `at` địa chỉ **có code**, và có tx **thành công** (`isError = 0`) gửi coin/token vào contract không nhận hoặc gọi hàm không tồn tại, nên tiền bị giữ lại hoặc chuyển đi. Hố đen: `malicious = 0`. Contract cài sẵn rút về ví kẻ cài: `malicious = 1` (chưa thấy rút nhưng code có đường rút: `?`). Cờ symexec ("không có đường rút", `transfer_all_eth`) **chỉ là gợi ý, không đủ để gán**. Contract được gọi đúng hàm (token, proxy, LP) là **âm** |
| **T3** | Gửi token vào chính contract token | `tokentx` có `to == contractAddress` của chính token đó |
| **T4** | Cross-chain misalignment | NCD trên chain này **và** cùng địa chỉ có code ở chain khác, deploy **trước** tx đầu tiên tới địa chỉ trên chain này (`deployed_before`) |
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
1. Địa chỉ có code trên CHAIN NÀY tại thời điểm tx?
   ├─ Không (NCD) ──► 2
   └─ Có ──► 4
2. Tx có calldata gọi hàm / hành vi chỉ hợp lý với contract?
   ├─ Không: tx chuyển tiền thường tới EOA, hoặc calldata chỉ là event topic / văn bản (§5 ca 10) ──► 5 (xét EOA misuse)
   └─ Có ──► 3
3. Cùng địa chỉ có code ở chain khác, deploy TRƯỚC tx đầu tiên trên chain này?
   ├─ Có ──► T4 (ghi xc_chain)
   ├─ Có nhưng deploy SAU ──► T1 (ghi note "xc deployed_after")
   └─ Không / không rõ ──► T1
4. Code trên chain này có phải là contract người dùng định gọi?
   ├─ Có, và tx gọi đúng hàm ──► NONE (âm)
   ├─ Là EIP-7702 delegation (0xef0100…) ──► 5
   └─ Không (PCD): tx tại `at` thành công và tiền bị giữ/chuyển đi? (tx lỗi `isError = 1` thì không mất tiền)
        ├─ Có ──► T2 (malicious = 0 hố đen / 1 rút về ví kẻ cài / ? chưa thấy rút)
        └─ Không ──► NONE
5. EOA: key lộ công khai (có tx sau ngày lộ) / delegate độc / tiền bị rút gần như ngay lập tức?
   ├─ Có ──► T5 (subtype KEY / ADDR / 7702; `malicious` = 1 / ? theo §3)
   ├─ Địa chỉ giống địa chỉ quen thuộc + tx mồi giá trị 0 ──► T6
   └─ Không (ví thường, sàn, smart wallet hợp lệ) ──► NONE (âm)
```

Thứ tự ưu tiên khi thỏa nhiều type: **T4 > T1**; **T5 > T6**; **T2** áp dụng độc lập với phía EOA. Type phụ, nếu có, ghi trong `note`.

## 5. Ca khó (đọc kỹ trước khi gán)

1. **Contract ở chain khác deploy SAU tx đầu tiên** (`xc_timing = deployed_after`): **không** gán T4. Người dùng khi đó không thể copy từ chain kia. Gán T1, ghi note.
2. **Không biết thời điểm deploy ở chain khác** (`xc_timing = unknown`): mở explorer của chain đó để xem tx tạo contract. Nếu vẫn không biết thì gán T4 với `confidence = low`.
3. **Cùng địa chỉ, cùng contract trên mọi chain, kể cả chain này** (Multicall3, Permit2, Safe, EntryPoint…): là **âm** (N7), trừ khi tx thật sự sai hàm.
4. **Địa chỉ hệ thống / precompile** (`0x000…000X`, predeploy của OP-stack `0x4200…`, system contract của BSC `0x…1000`): thường là âm. Tx gửi nhầm tới predeploy của chain *khác* (ví dụ WETH OP `0x4200…0006` trên ETH) thì gán T4.
5. **Người gửi tx đầu tiên là chính deployer** (đội dự án gửi nhầm chain): vẫn là T4. Ghi note `self-misuse`.
6. **EOA ủy quyền 7702 cho smart wallet hợp lệ** (MetaMask Delegator, Safe, Coinbase…) và chủ ví vẫn rút tiền bình thường: **âm** (N6).
   - `delegate_symexec_transfer = True` **không** có nghĩa delegate độc: smart wallet hợp lệ cũng chuyển được tiền. Phải xem tiền thực tế đi đâu.
   - Nếu EOA đã lộ key (KEY) thì vẫn là T5/KEY, dù delegate là ví hợp lệ. Lúc đó sweeper rút bằng chính key.
7. **Ví sàn hay địa chỉ nạp có auto-sweep**: tiền bị chuyển đi nhanh nhưng **về ví tổng của sàn**, nên là âm (N4). Sweeper độc thì chuyển về ví lạ và thường trả gas cao.
8. **Tx chỉ mất gas** (value = 0) tới NCD: vẫn là misuse (T1/T4). Thiệt hại nhỏ không làm đổi nhãn.
9. **Một địa chỉ vừa là PCD vừa có contract khác ở chain khác** (PCD-XC): gán T2 nếu code hiện tại giữ tiền, kèm `xc_chain` trong note. Gán T4 nếu tx misuse xảy ra **trước** khi code xuất hiện trên chain này.
10. **Calldata là văn bản** (UTF-8 đọc được) hoặc **event topic** (ví dụ `0xddf252ad…`) gửi tới EOA: không phải gọi hàm. Xét như chuyển tiền thường và đi tiếp bước 5 (KEY/ADDR/7702). Không có dấu hiệu nào ở bước 5 thì là âm (N3).
11. **Contract xuất hiện SAU tx** (lúc tx địa chỉ chưa có code): theo nhánh NCD (T1/T4). Ngoại lệ có chủ ý: kẻ cài contract rồi rút đúng khoản đó (P024) thì giữ T2/PCD, `malicious = 1`.
12. **Testnet** làm chain gốc cho T4: có tính (khớp 8 mạng của `crosschain_matrix`); ghi `xc_chain` là tên testnet, không tra được ngày tạo thì `confidence = low`. Paper báo T4 có và không có testnet.
13. **EOA 7702** (subtype tính tại `at`): thấy sweep thật → T5/7702, `malicious = 1`. Chưa thấy sweep nhưng delegate là forwarder chuyển tiền về địa chỉ cố định (xem bytecode/symexec) hoặc nằm trong danh sách đen → T5/7702, `malicious = ?`, `confidence` tối đa `medium`. Danh sách đen chỉ ghi vào `evidence`. Ô `delegate_known_wallet = -` **không** là bằng chứng độc. Delegate là ví hợp lệ có tên và chủ ví dùng bình thường → âm. Vừa lộ key vừa bị gắn delegate: theo ca 6 (KEY nếu delegate hợp lệ), nếu delegate là sweeper thì subtype `7702` kèm note "KEY?".
14. **ADDR không có sweep:** không có type nào áp dụng nếu không thấy tiền bị rút về ví lạ → âm, `confidence = low`.
15. **Cách ghi ô:** mẫu âm ghi `subtype`, `xc_chain`, `malicious` là `-`. `confidence = high` chỉ khi đã mở explorer xem tx tại `at`; chỉ dựa vào cột bằng chứng thì tối đa `medium`.

## 6. Bằng chứng có sẵn trong file mẫu

Mỗi mẫu có sẵn các cột sau (không cần tự tra, trừ khi muốn kiểm tra thêm):

| Cột | Nguồn |
|---|---|
| `code_<chain>`, `xc_nets`, `same_code_elsewhere` | `eth_getCode` hiện tại trên 8 mạng, tra cùng một cách cho **mọi** mẫu: `none` / `code` / `7702`; `xc_nets` = các mạng khác có code; `same_code_elsewhere` = bytecode ở chain này trùng với một mạng khác |
| `deployer`, `create_kind`, `origin_net`, `first_create_date` | Etherscan / Binplorer `getcontractcreation`. Chỉ điền khi chain này **không** có code mà mạng khác có (tình huống T4) |
| `first_tx_date`, `xc_timing` | tx đầu tiên tới địa chỉ trên chain này (Etherscan) |
| `symexec_*` | Symbolic execution trên code ở chain này (`transfer_all_eth`, `delegatecall`, …): kết quả của tác giả, thiếu thì nhóm tự chạy cùng engine (timeout 120 s, nên `False` có thể là chưa tìm hết đường). Chỉ có khi `code_<chain> = code` |
| `delegate_7702`, `delegate_symexec_transfer`, `delegate_known_wallet` | Delegate đọc từ code `0xef0100…` hiện tại trên chain này. Symexec cho biết delegate có đường chuyển tiền hay không (`True` / `False` / `-` = không phân tích được). Tên ví lấy từ danh sách ví hợp lệ đã kiểm chứng (N6) |
| `explorer_url`, `explorer_url_xc` | Link Etherscan/BscScan… để tự kiểm tra tx và code |

Ô ghi `-` nghĩa là **không tra được hoặc không áp dụng**; không suy ra gì từ việc ô đó trống (ví dụ `xc_timing = -` không có nghĩa là mẫu âm). Số giao dịch và thiệt hại của tác giả cố ý **không** đưa vào file: tự mở `explorer_url` để xem giao dịch.

Trạng thái code là **hiện tại**, không phải lúc tx. Khi kết luận phụ thuộc vào thời điểm (T4, PCD), phải xem `first_tx_date` hoặc mở explorer.

## 7. Quy trình

1. **Pilot 50 mẫu** (`data/gold/pilot50_items.csv`): mỗi người gán riêng vào `annotator_A.csv` / `annotator_B.csv`, không trao đổi.
2. Tính κ trên `is_misuse` và trên `type`. Liệt kê các mẫu bất đồng.
3. Họp phân xử: thống nhất nhãn cuối vào `adjudicated.csv`, rồi **sửa codebook** cho các điểm gây bất đồng (tăng phiên bản, ghi lại thay đổi ở §9).
4. Nếu κ(`is_misuse`) < 0,8: làm thêm một pilot nhỏ (khoảng 30 mẫu **chưa ai thấy**, làm giàu PCD/KEY/7702) với codebook mới. Nếu κ ≥ 0,8: gán mẫu chính. κ tính lại sau khi đã biết bất đồng **không được báo**; κ báo trong paper là của pilot 2 và của 200 mẫu gán đôi.
5. Mỗi lô khoảng 10% mẫu được gán trùng để theo dõi κ.

## 8. Đạo đức và an toàn

- Chỉ phân tích thụ động. **Không** dùng private key lộ công khai để ký hay chuyển tài sản, kể cả để "giải cứu".
- Không đưa địa chỉ cá nhân đầy đủ vào paper, slide hay chat. Khi trích thì ẩn bớt, ví dụ `0x1234…abcd`.
- File trong `data/gold/` chứa địa chỉ đầy đủ, chỉ dùng nội bộ nhóm.

## 9. Lịch sử thay đổi

- **v0.1 (2026-10-16):** bản nháp đầu, trước pilot.
- **v0.2 (2026-10-19):** bỏ các cột `n_tx`, `n_misuse_tx`, `cost_native` khỏi file mẫu (làm lộ nhãn: chỉ có ở mẫu thuộc dữ liệu tác giả); ô không tra được ghi `-` thay vì để trống.
- **v0.4 (2026-10-25):** áp dụng §10.1 (điểm 1–5, đã sửa theo advisor) và §10.2: T2 cần tx thành công và sai ý định (cờ symexec chỉ gợi ý); KEY gán dương theo danh sách lộ + tx sau ngày lộ (`malicious` `1`/`?`); `malicious` có 4 giá trị; ca khó 10–15; bỏ điều kiện `delegate_known_wallet = -` làm bằng chứng độc. PCD của mình **hẹp hơn** PCD của tác giả (có chủ ý), paper báo cả hai cách đọc.
- **v0.3 (2026-10-19):**
  - bỏ cột `delegate_flag` (thực chất là kết quả symexec, gây thiên lệch), thay bằng `delegate_symexec_transfer` và `delegate_known_wallet`;
  - tầng `neg_n6_7702_benign` đổi thành `eoa_7702_other`;
  - bổ sung ca khó 6;
  - mọi cột code/delegate tra trực tiếp cho mọi mẫu, symexec chạy bổ sung cho contract chưa có kết quả, cột nguồn gốc/thời điểm chỉ điền ở tình huống T4 (trước đó các cột này chỉ có ở một số tầng nên làm lộ tầng).

## 10. Agenda sửa codebook v0.4 (từ pilot 50 mẫu, người gán A, 2026-10-21)

Danh sách điểm mơ hồ gặp khi gán pilot. Chưa sửa quy tắc; cần thống nhất trong buổi phân xử với người gán còn lại rồi mới đổi bản. Mẫu dẫn chứng chỉ để tra lại khi họp.

1. **T2: §3 mâu thuẫn §4.** Bảng §3 định nghĩa T2 là contract "không có đường rút", nhưng §4 bước 4 xếp PCD cài sẵn để chiếm tiền vào T2 với `malicious = 1` (contract có đường rút, rút về ví kẻ cài). Cần chọn một định nghĩa, hoặc tách thành hai nhãn. Dẫn chứng: P024.
2. **Testnet có tính là chain gốc cho T4 không?** Khi contract chỉ có ở testnet (ví dụ `bsc_testnet`) và không tra được ngày tạo. Nếu không tính thì mẫu thành T1. Dẫn chứng: P036.
3. **Calldata là event payload có tính là "gọi hàm" không?** Ví dụ `0xddf252ad…` là topic của event `Transfer`, không phải selector hàm. Gợi ý: không tính, nên một tx như vậy không đủ để gán misuse theo §1 ("≥ 1 tx misuse rõ ràng"). Dẫn chứng: P009.
4. **Thứ tự ưu tiên KEY và 7702** khi EOA vừa lộ key vừa bị gắn delegate sweeper (các tx rút ký bằng key, delegation gắn sau). Gợi ý: `subtype = 7702` nếu địa chỉ hiện đang delegate (code `0xef0100…`), kèm note "KEY?" nếu tx rút ký bằng key chủ. Cả hai đều là T5 nên không ảnh hưởng κ của `type`, chỉ ảnh hưởng κ của `subtype`.
5. **Tiêu chí `malicious = 1` khi chưa thấy tx rút.** (a) Delegate độc nhưng chưa có sweep thực tế; (b) ví delegate vẫn hoạt động bình thường (DEX, bridge) và không có dấu hiệu rút về ví lạ. Cần quy tắc rõ khi nào vẫn gán T5 và `confidence` mặc định là gì. Dẫn chứng: P030, P034, P045, P050 (và P020, P043 ở mức nhẹ hơn).

### 10.1. Đề xuất xử lý cho agenda trên (2026-10-25, **chưa áp dụng**, chờ buổi phân xử)

Nên chốt 5 điểm này TRƯỚC khi gán 605 mẫu chính, vì chúng đổi nhãn của một số mẫu (đặc biệt PCD, 7702 và T4 testnet).
**Đã áp dụng thành v0.4** (§3, §4, §5, §9), có sửa theo nhận xét của advisor. Định nghĩa có thể giống đặc tả, nhưng **bằng chứng gán nhãn phải độc lập với engine**: danh sách đen/leak chỉ ghi vào `evidence`.

1. **T2:** định nghĩa lại là "địa chỉ có code mà người dùng không định gọi, và tiền gửi vào không về lại cho người dùng"
   (hố đen HOẶC contract cài sẵn rút về ví kẻ cài). Phân biệt hai trường hợp bằng `malicious`: `0` = hố đen không đường rút,
   `1` = cài sẵn chiếm tiền. `type` giữ nguyên là T2 nên không ảnh hưởng κ(type); §3 và §4 hết mâu thuẫn.
2. **Testnet làm chain gốc cho T4:** có tính (khớp RISK_SCORE §2.2 và `crosschain_matrix`, có `bsc_testnet`, `sepolia` trong 8 mạng).
   Ghi `xc_chain` là tên testnet; không tra được ngày tạo thì `confidence = low`.
3. **Calldata là event topic hay văn bản** (ví dụ `0xddf252ad…`, hoặc ASCII như `0x64617461` = "data"): không tính là gọi hàm
   (khớp bộ lọc IDM của tác giả trong engine). Tx như vậy không đủ để gán misuse; nếu đó là tx duy nhất trong mẫu thì `is_misuse = 0`.
4. **KEY và 7702:** `subtype = 7702` nếu địa chỉ đang delegate (code `0xef0100…`) tại thời điểm xét; ghi note "KEY?" nếu tx rút ký bằng
   key chủ. `type` luôn là T5.
5. **`malicious` khi chưa thấy tx rút:** gán `T5` khi delegate nằm trong danh sách đen hoặc không có tên ví hợp lệ (`delegate_known_wallet = -`).
   `malicious = 1` chỉ khi thấy tiền thực sự bị rút về ví lạ; nếu không thấy thì `malicious = 0` và `confidence = low`, kèm note.
   Delegate có tên ví hợp lệ mà chủ ví dùng bình thường (DEX, bridge) → âm (§5 ca 6).

### 10.2. Điểm cần chốt thêm sau κ pilot (2026-10-25: κ(is_misuse) = 0,615, chưa đạt 0,8)

Các điểm 1–5 ở §10 và §10.1 không gây bất đồng giữa A và B (hai người chọn giống nhau trên P009, P020, P024, P030, P034, P036, P038, P043, P045, P050).
Bất đồng nằm ở các điểm mới sau, cần chốt cùng §10.1 trước khi gán mẫu chính:

6. **T2/PCD có cần tx chứng minh không?** (6 trong 7 bất đồng.) Đề xuất: PCD chỉ gán dương khi tx tại thời điểm `at` là tx **sai ý định** (chuyển coin vào contract không nhận coin, gọi hàm không tồn tại,
   hoặc contract được cài sau tx như P024). Cờ symexec (`transfer_all_eth`, `delegatecall`, "không có đường rút") **chỉ là gợi ý, không đủ để gán**. Contract được gọi đúng hàm (token, proxy, LP) là âm.
7. **Chuẩn bằng chứng cho KEY (P012).** Đề xuất: KEY chỉ gán dương khi thấy tiền rút ra trong vài phút về ví lạ; chỉ biết "key có trong danh sách rò rỉ" là chưa đủ.
   Nếu không thấy tx rút thì `is_misuse = 0`, `confidence = low` (đồng bộ với điểm 5).
8. **Quy ước ô:** mẫu âm ghi `subtype = -`, `xc_chain = -`, `malicious = -`; `confidence = high` chỉ khi đã mở explorer xem tx tại thời điểm `at`, còn chỉ dựa vào cột bằng chứng thì `medium`.
