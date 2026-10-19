# Codebook gán nhãn vàng (D5)

Bản nháp v0.2 (2026-10-19), sẽ chỉnh sau pilot 50 mẫu. Dùng cho 2 người gán nhãn độc lập. Mục tiêu: Cohen's κ ≥ 0,8.

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
| `malicious` | `1` / `0` / `-` | Có bên thứ ba chủ động khai thác không (sweeper, planted contract, delegate độc) |
| `confidence` | `high` / `medium` / `low` | Mức chắc chắn của chính người gán |
| `evidence` | danh sách ngắn | Bằng chứng đã dùng, ví dụ `code, timing, tx, symexec, label` |
| `note` | văn bản | Bắt buộc khi `confidence = low`, `is_misuse = ?`, hoặc mẫu rơi vào ca khó ở §5 |

**Không** tra cứu nhãn của tác giả, kết quả detector hay mẫu đó thuộc tầng nào. File mẫu đã được làm mù (blind) để tránh thiên lệch.

## 3. Định nghĩa

### CA Misuse: người dùng tương tác với địa chỉ *như thể* đó là contract

- **NCD (No Code at Destination):** tại thời điểm tx, địa chỉ đích **không có code** (`getCode == 0x`). Tx có calldata gọi hàm (selector 4 byte), hoặc gửi tiền theo cách chỉ hợp lý với contract. Tx không revert nhưng không có tác dụng.
- **PCD (Planted/Present Code at Destination):** địa chỉ đích **có code**, nhưng code đó không phải contract người dùng định gọi. Có thể là contract khác deploy sau, hoặc contract cố ý cài sẵn để nhận tiền. Kết quả là tiền bị giữ lại hoặc bị chuyển đi.

### EOA Misuse: người dùng gửi tài sản tới ví mà họ không kiểm soát được an toàn

- **KEY:** ví có private key **đã lộ công khai** (GitHub/StackExchange). Bot sweeper rút tiền ngay khi tiền tới.
- **ADDR:** người dùng gửi tới một địa chỉ ví công khai (ví dụ trong tài liệu hay code mẫu) **không phải của họ**.
- **7702:** EOA đã ủy quyền EIP-7702 (code bắt đầu `0xef0100…`) tới một delegate. Tiền gửi tới bị delegate xử lý, thường là delegate sweeper.

### Taxonomy 6 type

| Type | Tên | Điều kiện cần (đều phải thỏa) |
|---|---|---|
| **T1** | Gọi hàm tới địa chỉ không có code | NCD; **không** có bằng chứng contract cùng địa chỉ ở chain khác tồn tại **trước** tx |
| **T2** | Contract "hố đen" | Địa chỉ có code, nhận native coin, **không có đường rút** (symexec không thấy `transfer_*`/`delegatecall` ra ngoài, không có hàm withdraw) |
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
   ├─ Không: tx chuyển tiền thường tới EOA ──► 5 (xét EOA misuse)
   └─ Có ──► 3
3. Cùng địa chỉ có code ở chain khác, deploy TRƯỚC tx đầu tiên trên chain này?
   ├─ Có ──► T4 (ghi xc_chain)
   ├─ Có nhưng deploy SAU ──► T1 (ghi note "xc deployed_after")
   └─ Không / không rõ ──► T1
4. Code trên chain này có phải là contract người dùng định gọi?
   ├─ Có, và tx gọi đúng hàm ──► NONE (âm)
   ├─ Là EIP-7702 delegation (0xef0100…) ──► 5
   └─ Không (PCD) ──► còn đường rút tiền?
        ├─ Không ──► T2
        └─ Có, nhưng là contract cài sẵn để chiếm tiền ──► T2, malicious = 1
5. EOA: key lộ công khai / delegate độc / tiền bị rút gần như ngay lập tức?
   ├─ Có ──► T5 (subtype KEY / ADDR / 7702)
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
7. **Ví sàn hay địa chỉ nạp có auto-sweep**: tiền bị chuyển đi nhanh nhưng **về ví tổng của sàn**, nên là âm (N4). Sweeper độc thì chuyển về ví lạ và thường trả gas cao.
8. **Tx chỉ mất gas** (value = 0) tới NCD: vẫn là misuse (T1/T4). Thiệt hại nhỏ không làm đổi nhãn.
9. **Một địa chỉ vừa là PCD vừa có contract khác ở chain khác** (PCD-XC): gán T2 nếu code hiện tại giữ tiền, kèm `xc_chain` trong note. Gán T4 nếu tx misuse xảy ra **trước** khi code xuất hiện trên chain này.
10. **Calldata là văn bản** (UTF-8 đọc được) gửi tới EOA: thường là tin nhắn, nên là âm (N3).

## 6. Bằng chứng có sẵn trong file mẫu

Mỗi mẫu có sẵn các cột sau (không cần tự tra, trừ khi muốn kiểm tra thêm):

| Cột | Nguồn |
|---|---|
| `code_<chain>` | `eth_getCode` hiện tại trên 8 mạng (`crosschain_matrix`): `none` / `code` / `7702` |
| `same_code_elsewhere`, `xc_nets` | Ma trận cross-chain |
| `deployer`, `create_kind`, `origin_net`, `first_create_date` | Etherscan / Binplorer `getcontractcreation` |
| `first_tx_date`, `xc_timing` | tx đầu tiên tới địa chỉ trên chain này (Etherscan) |
| `symexec_*` | Kết quả symbolic execution (`transfer_all_eth`, `delegatecall`, …) |
| `delegate_7702`, `delegate_flag` | `eip7702_delegations` và `eip7702_delegate_stats` của tác giả |
| `explorer_url`, `explorer_url_xc` | Link Etherscan/BscScan… để tự kiểm tra tx và code |

Ô ghi `-` nghĩa là **không tra được hoặc không áp dụng**; không suy ra gì từ việc ô đó trống (ví dụ `xc_timing = -` không có nghĩa là mẫu âm). Số giao dịch và thiệt hại của tác giả cố ý **không** đưa vào file: tự mở `explorer_url` để xem giao dịch.

Trạng thái code là **hiện tại**, không phải lúc tx. Khi kết luận phụ thuộc vào thời điểm (T4, PCD), phải xem `first_tx_date` hoặc mở explorer.

## 7. Quy trình

1. **Pilot 50 mẫu** (`data/gold/pilot50_items.csv`): mỗi người gán riêng vào `annotator_A.csv` / `annotator_B.csv`, không trao đổi.
2. Tính κ trên `is_misuse` và trên `type`. Liệt kê các mẫu bất đồng.
3. Họp phân xử: thống nhất nhãn cuối vào `adjudicated.csv`, rồi **sửa codebook** cho các điểm gây bất đồng (tăng phiên bản, ghi lại thay đổi ở §9).
4. Nếu κ(type) < 0,8: làm thêm một pilot nhỏ (khoảng 30 mẫu) với codebook mới. Nếu κ ≥ 0,8: gán phần còn lại (khoảng 2.000 mẫu) theo lô.
5. Mỗi lô khoảng 10% mẫu được gán trùng để theo dõi κ.

## 8. Đạo đức và an toàn

- Chỉ phân tích thụ động. **Không** dùng private key lộ công khai để ký hay chuyển tài sản, kể cả để "giải cứu".
- Không đưa địa chỉ cá nhân đầy đủ vào paper, slide hay chat. Khi trích thì ẩn bớt, ví dụ `0x1234…abcd`.
- File trong `data/gold/` chứa địa chỉ đầy đủ, chỉ dùng nội bộ nhóm.

## 9. Lịch sử thay đổi

- **v0.1 (2026-10-16):** bản nháp đầu, trước pilot.
- **v0.2 (2026-10-19):** bỏ các cột `n_tx`, `n_misuse_tx`, `cost_native` khỏi file mẫu (làm lộ nhãn: chỉ có ở mẫu thuộc dữ liệu tác giả); ô không tra được ghi `-` thay vì để trống.
