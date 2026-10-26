# Giao thức nhãn vàng (D5): thiết kế, quy trình, đăng ký trước, hạn chế

Bản đi kèm [CODEBOOK.md](CODEBOOK.md) v0.6.1 (2026-10-26). **Người gán không đọc file này trước khi gán xong**: nó có cỡ mẫu, tầng, tỉ lệ và cổng κ. Codebook chỉ chứa quy tắc gán.

Kế hoạch gốc: [PLAN_V2.md](PLAN_V2.md) D5. Mục tiêu: Cohen's κ ≥ 0,8, báo kèm CI.

---

## 1. Thiết kế mẫu (tiền đăng ký; `sample_gold.py`, không đổi từ v0.5)

- **Khung:** test ∪ out_of_time của `dataset_v2` (bỏ `excluded`), 2.010 dòng / 1.680 địa chỉ. Đơn vị lấy mẫu là địa chỉ; mỗi địa chỉ thuộc đúng một tầng (tầng đầu tiên có địa chỉ đó). `n_rows` = số dòng của địa chỉ trong toàn khung (Σ = 2.010). Dòng đại diện là dòng engine gắn cờ nếu có.
- **Dương** (mọi tầng `+`, 442 địa chỉ) và **âm bị engine gắn cờ** (luật cứng hoặc R ≥ τ_warn = 63,0; 3 mẫu N8): lấy hết, trọng số 1. **Âm không cờ:** mẫu ngẫu nhiên đơn giản trong từng ô (tầng × chain), chia đều eth/bsc.
- **Lô 1** = 758 mẫu (442 dương + 316 âm; eth 406, bsc 352), 200 mẫu gán đôi rút ngẫu nhiên. Tầng: +ADDR 110, +D6 42, +KEY 113, +NCD 127, +PCD 50, −N1 40, −N2 60, −N3 40, −N4 30, −N5 39, −N6 5, −N7 19, −N8 83.
- Một file cho lô 1, dương và âm xáo lẫn (seed cố định).
- **Trọng số:** `w_addr` = cỡ ô / số địa chỉ đã gán trong ô; `w_row` = `w_addr` × `n_rows`. Tính lại theo số mẫu đã gán thực tế (`gold_eval.gold_weights`).
- **Lô 2 (tuỳ thời gian):** 922 âm dự phòng, thứ tự cố định (`main_reserve_key.csv`), lô 50 mẫu; trong ô là tiếp nối thứ tự xáo của lô 1; giữa các ô xen kẽ theo tỉ lệ cỡ ô. Chỉ dừng ở ranh giới lô, theo ngân sách hoặc hạn chót, **không** theo kết quả engine.
- **Chọn tx của mẫu:** dòng đại diện của địa chỉ có `at`; tx là tx đi vào địa chỉ tại đúng `at` (`tx_hash` của dòng, hoặc khôi phục từ txlist, ưu tiên tx có calldata). Cách chọn `at` khác nhau theo tầng (xem §6, hạn chế 1).

## 2. Quy trình gán

### 2.1. Pilot

50 mẫu (`pilot50_items.csv`), gán độc lập: κ(`is_misuse`) = 0,615, κ(`type`) = 0,823. Chỉ là mốc trước khi sửa codebook. Con số 0,951 tính lại sau khi đã biết bất đồng **không được báo**. Không có pilot 2 (quyết định 2026-10-25).

### 2.2. Thứ tự

0. Người điều phối hỏi A đã đọc CODEBOOK v0.5 chưa, ghi câu trả lời vào PROGRESS.md (§6, hạn chế 7).
1. A và B rà hết bảng delegate (§2.3); `sample_gold check-delegates` báo 0 lỗi.
2. Cả A và B gán **200 mẫu gán đôi** trước (`annotator_main_double_<A|B>.xlsx`), độc lập. Kiểm cổng (§2.4).
3. Phân xử (§2.5).
4. B gán 558 mẫu đơn (`annotator_main_single_B.xlsx`); A gán lại mù 50 mẫu đơn (§2.6).
5. Lô 2 nếu còn thời gian (§2.7).

### 2.3. Bảng tra delegate 7702 (sai lệch có chủ ý so với v0.5)

v0.5 định A và B cùng phân loại từ đầu. **v0.6:** người điều phối điền sẵn `final_class` và `source` trong `data/gold/delegate_lookup.csv` từ bằng chứng khách quan (mã nguồn đã verify qua Etherscan V2 `getsourcecode`, hoặc bytecode `eth_getCode`). 33 delegate: 12 `forwarder_sweeper`, 3 `legit_wallet`, 18 `unknown` (theo số mẫu có delegate hôm nay: 230 / 4 / 30; 208 trong 264 mẫu này có `code_at_event = 7702`, 56 mẫu còn lại có tx trước ngày kích hoạt nên là `none`). A và B **bắt buộc rà soát hết bảng trước khi gán mẫu nào**:

- Mỗi dòng ghi rõ `ok` (đồng ý) hoặc một lớp khác kèm `note` (phản đối) vào `class_A` / `class_B`. **Ô trống = chưa rà**, không phải đồng ý (v0.6.1; bản v0.6 cũ coi ô trống là đồng ý).
- Phản đối được giải quyết trước khi gán. Kết quả ghi ở cột `note`; người điều phối không sửa `final_class` / `source` nếu chưa có lý do ghi rõ.
- `sample_gold check-delegates` phải báo 0 lỗi trước khi giao file gán đôi. Bảng hiện tại báo 66 lỗi (33 dòng × 2 người, chưa rà), đúng như mong đợi.
- Người rà phải mở nguồn (`source`: link verify hoặc bytecode) và tự kết luận, không chỉ đọc lại lớp đã điền (CODEBOOK ca 13).

Lý do điền sẵn: tiết kiệm thời gian và để phân loại dựa trên bằng chứng có nguồn ghi rõ. Cái giá: người điều phối biết thiết kế nên phân loại không mù, và lớp điền sẵn có thể **neo** (anchoring) người rà (§6, hạn chế 14). Vì vậy chỉ số engine và κ được báo cả có và không có các mẫu do bảng delegate quyết định (§4 j). `sample_gold main` chạy lại giữ nguyên các ô đã điền.

Trùng với engine theo cách xây dựng: danh sách đen của engine (`default_malicious_delegates`) chứa 130/230 mẫu `forwarder_sweeper` (101/174 trong số có `code_at_event = 7702`) và 29/30 mẫu `unknown` (cả 30 đều có `code_at_event = 7702`). Ở các mẫu này nhãn vàng và engine dùng chung một nguồn.

### 2.4. Cổng κ sau 50 mẫu gán đôi đầu

- 50 mẫu có `item_id` nhỏ nhất trong tập gán đôi. Tính κ(`is_misuse`). Cổng là **chẩn đoán**, không phải phép thử: ở n = 50, κ thật 0,85 vẫn có ~27% khả năng rơi dưới 0,8, nên ngưỡng dừng là **κ < 0,70**.
- κ ≥ 0,70: gán tiếp 150 mẫu gán đôi còn lại.
- κ < 0,70: dừng, phân xử 50 mẫu đó, sửa codebook (tăng phiên bản, ghi sai lệch), A và B gán lại 50 mẫu đó theo bản mới. **50 mẫu này giữ nhãn phân xử làm nhãn vàng** nhưng **không** vào κ chính thức (κ của chúng chỉ là κ hiệu chỉnh). Thay chúng trong κ chính thức bằng 50 mẫu đơn có `double_extra_rank` nhỏ nhất (thứ tự cố định trong `main_key.csv`), cả A và B gán đôi.
- **κ chính thức (tiền đăng ký):** κ(`is_misuse`) là chỉ số chính, **κ(`type`) là chỉ số phụ đăng ký trước**, trên các mẫu gán đôi gán sau khi chốt codebook. Báo kèm CI bootstrap theo cụm (§4), PABAK, Gwet AC1, % đồng ý, κ khi bỏ `?`, κ trên tập khó (§4 f). Báo dù thấp hơn 0,8.

### 2.5. Phân xử và nhãn cuối

A và B họp; mỗi mẫu bất đồng thống nhất một nhãn (`gold_adj`) kèm lý do; không thống nhất → `?` (báo hai kịch bản tính 0 / tính 1). Nhãn cuối (`gold_eval.final_gold`): mẫu gán đôi = nhãn phân xử; mẫu đơn = nhãn của B. Có cột `gold_source`.

### 2.6. Sai số của nhãn gán đơn

B gán một mình 558/758 mẫu (74%) và là người thiết kế. So B với nhãn phân xử bị **lệch thấp** (B tham gia phân xử). Báo cả ba:

1. B khác nhãn phân xử trên mẫu gán đôi (cận dưới).
2. B khác A (bất đồng thô) trên mẫu gán đôi (cận trên thô cho sai số của một người).
3. **A gán lại mù 50 mẫu đơn của B:** 50 mẫu đơn có `double_extra_rank` **lớn nhất** (không trùng danh sách thay thế ở §2.4, rút từ thứ tự cố định sẵn có). A gán sau khi xong phần gán đôi, không xem nhãn B. Báo tỉ lệ bất đồng thô kèm CI Clopper–Pearson. Không đổi nhãn cuối của 50 mẫu này (vẫn là của B) trừ khi phân xử phát hiện lỗi rõ; nếu sửa thì ghi là sai lệch. **Chi phí:** khoảng 1–2 phiên của A (~40 mẫu/phiên).

### 2.7. Lô 2

Lô 2 toàn âm nên mất tính mù. Mỗi lô 50 âm trộn thêm ~12 **mẫu dương lấy lại từ chính các mẫu gán đôi mà A đã gán** (đổi mã; A không biết là gán lại), để đo độ nhất quán của chính A. Các mẫu này **không** tính vào ước lượng. Giao lô 2 cho A (người chưa xem thiết kế).

## 3. Sinh bằng chứng (`gold_evidence.py`, `sample_gold.main_evidence`)

### 3.1. Quy tắc đều cho mọi mẫu

- Hàm sinh bằng chứng **không nhận tầng, nhãn hay cờ engine** (test `test_main_evidence_uniform_and_blind_to_stratum` đổi cột tầng/nhãn và kiểm đầu ra giống hệt).
- **Tx tại `at`:** cho cả 758 mẫu: block, vị trí trong block, calldata, value, trạng thái. ETH: RPC công khai + Etherscan `transaction.getstatus`; BSC: NodeReal. 758/758 tra được.
- **Tạo contract trên chain của mẫu:** cho **mọi** mẫu, kể cả EOA và địa chỉ hôm nay không có code (có thể đã tự huỷ). ETH: Etherscan V2 `getcontractcreation`; BSC: NodeReal `nr_getContractCreationTransaction`. Kết quả: 226 found, 468 not_found, 64 lỗi; cả 64 lỗi là địa chỉ BSC hôm nay là 7702 (NodeReal trả "internal error"), nhánh 7702 không dùng bản ghi tạo nên không ảnh hưởng cột nào.
- **`code_at_event`** (`state_at_event`): getCode hôm nay lỗi → `unknown`; hôm nay 7702 → `none` nếu tx trước ngày kích hoạt EIP-7702 của chain, ngược lại `7702`; có bản ghi tạo → so (block, vị trí trong block) với tx: trước → `code` (hôm nay còn code) / `destroyed` (hôm nay hết); sau → `none`; **tạo ngay trong chính tx đó** (cùng hash, hoặc cùng block và cùng vị trí) → `unknown` (v0.6.1; không được thành `none` vì sẽ thành PCD giả; trường hợp này không thể xảy ra khi tx gửi thẳng tới địa chỉ, nên gặp là lỗi dữ liệu; test `test_creation_inside_event_tx_is_not_pcd`; 0/758 mẫu); cùng block thiếu vị trí → `unknown`; không có bản ghi → `none` nếu hôm nay không code, `unknown` nếu có; lỗi → `unknown`.
- **Etherscan `getcontractcreation`** (v0.6.1, `parse_etherscan_creation`): `status = 1` → bản ghi; `status = 0` với thông báo bắt đầu "No data found" → không có bản ghi (`not_found`, được lưu cache); mọi trường hợp khác → lỗi (không lưu cache, cột thành `unknown`). Test `test_parse_etherscan_creation_is_explicit`.
- **`own_create_time`, `creator`:** điền khi tra được bản ghi tạo, cho mọi mẫu.
- **`xc_*`:** điền khi và chỉ khi `xc_nets ≠ -` và `code_at_event ∉ {code, 7702}` (điều kiện chỉ dựa vào cột người gán cũng thấy). Tra creation ở mọi mạng trong `xc_nets`: eth/arb/polygon/sepolia qua Etherscan; bsc qua NodeReal; op/base/bsc_testnet không có nguồn miễn phí → `unknown` như nhau cho mọi mẫu. `xc_timing`: `before` nếu có mạng tạo trước tx (so giây UTC; **cùng giây không tính là trước**); `unknown` nếu không mạng nào `before` và có mạng không tra được; còn lại `after`.
- **So sánh trong cùng chain** theo (block, vị trí); **giữa hai chain** theo giây UTC. Tie-break: cùng block → vị trí trong block (lấy vị trí của tx tạo khi cần); cùng giây giữa chain → không trước.
- **Trạng thái hôm nay** (`code_<chain>`, `xc_nets`, `same_code_elsewhere`, `delegate_7702`, `symexec_*`): dùng lại đúng ảnh chụp của bản v0.5 (`--live-from`), một ảnh cho mọi mẫu, để bảng delegate không đổi. Trong v0.5 các cột này đã tra trực tiếp cho mọi mẫu, không dùng nguồn dự phòng theo tầng.
- Lỗi tra cứu không bao giờ được thay bằng nguồn chỉ có ở một số tầng.

### 3.2. Kiểm rò rỉ (chạy 2026-10-26, file khoá chỉ dùng cho bảng này)

Tỉ lệ ô có giá trị theo tầng, **v0.5**:

| cột | +ADDR | +D6 | +KEY | +NCD | +PCD | −N1 | −N2 | −N3 | −N4 | −N5 | −N6 | −N7 | −N8 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| own_create_date | 0 | 0 | 0 | 0 | **1,00** | 0 | 0 | 0 | 0 | **1,00** | 0 | 0 | 0 |
| xc_timing | 0 | 0 | 0 | 0,70 | 0,02 | 0 | 0 | 0 | 0 | 0,10 | 0 | 0 | 0 |
| deployer / first_tx_date | 0 | 0 | 0 | 0,65 | 0,02 | 0 | 0 | 0 | 0 | 0,10 | 0 | 0 | 0 |

Nguyên nhân: `own_create_date` lấy từ `engine_creation.parquet` (chỉ phủ PCD/N5); `xc_*` lấy từ `crosschain_matrix` (chỉ phủ tầng NCD và vài mẫu). Hệ quả: (a) `own_create_date` có giá trị gần như là nhãn tầng; (b) `code_at_event` của mẫu có code ngoài PCD/N5 thật ra là trạng thái **hôm nay**; (c) 46/50 mẫu +PCD có contract ở mạng khác nhưng không có `xc_timing`.

**v0.6:**

| cột | +ADDR | +D6 | +KEY | +NCD | +PCD | −N1 | −N2 | −N3 | −N4 | −N5 | −N6 | −N7 | −N8 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| own_create_time | 0 | 0,05 | 0 | 0 | 1,00 | 0,02 | 1,00 | 0 | 0 | 1,00 | 1,00 | 1,00 | 0,60 |
| xc_timing | 0 | 0,07 | 0 | 0,70 | 0,94 | 0 | 0 | 0 | 0 | 0,10 | 0 | 0 | 0 |
| tx_status | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |

Tỉ lệ vẫn khác nhau theo tầng, nhưng giờ do **tính chất thật** của địa chỉ (có contract hay không, có contract ở mạng khác hay không), không do cách tra. Kiểm điều kiện trên file: `xc_timing` có giá trị ⇔ (`xc_nets ≠ -` và `code_at_event ∉ {code, 7702}`) ở 758/758 mẫu; mọi mẫu `code`/`destroyed` có `own_create_time`. Hai kiểm này nằm trong test.

**Thay đổi so với v0.5:** tập (item_id, chain, address), thứ tự, `tx_hash`, mọi cột trạng thái hôm nay giống hệt; `main_key.csv` và `main_reserve_key.csv` giữ nguyên hash. 7 mẫu đổi `code_at_event`: 4 −N5 `code → destroyed`, 1 +D6 `none → destroyed`, 1 +D6 và 1 −N8 `code → none` (contract tạo **sau** tx, tức PCD theo tác giả, nằm ngoài tầng +PCD). `own_create_time` có ở 226 mẫu (v0.5: 89). `xc_*` thêm ở 49 mẫu (46 +PCD, 3 +D6): 42 `before`, 6 `unknown`, 1 `after`; không mẫu nào đổi giá trị cũ.

### 3.3. Cột mới / bỏ

- Thêm: `at_time` (giờ UTC đến giây, thay `at_date`), `tx_status`, `calldata_kind`, `own_create_time` (thay `own_create_date`), `creator`, `xc_create_time` (thay `first_create_date`).
- Bỏ: `create_kind`, `first_tx_date` (T4 so với tx cho sẵn, không so với tx đầu tiên).
- `calldata_kind`: `call` 506, `-` 208, `text` 44 (36 trong đó có selector `0x64617461` = ASCII "data", inscription).
- `calldata_len` (v0.6.1): số byte calldata, tính như nhau cho mọi mẫu từ input của tx (`-` nếu không tra được; 0/758). Phân bố: 0 → 208, 68 → 178, 4 → 82, 36 → 30, còn lại rải rác. 11 mẫu `call` có đúng 32 byte (độ dài của một event topic); 44 mẫu `call` có độ dài không dạng 4 + 32k. Người gán xét 32 byte theo ca 10 (xem Method trên explorer). Thêm cột này không đổi tập mẫu, thứ tự hay cột nào khác.
- T3: 40 tx là `transfer`/`transferFrom`; 1 tx có người nhận = chính contract (một mẫu có code, tx thành công).

## 4. Quy tắc báo (tiền đăng ký)

- (a) **Chỉ số chính theo địa chỉ** (`gold_eval.evaluate(unit='addr')`); theo dòng báo phụ.
- (b) Báo chỉ số engine hai lần: đầy đủ, và bỏ tầng KEY/ADDR (`exclude_strata`), vì nhãn KEY/ADDR dựa vào mẫu hình rút nhanh trùng luật `sweeper` của engine.
- (c) Ô 0 sự kiện: cận Jeffreys (chính), Clopper–Pearson (bảo thủ). Ô điều tra toàn bộ không lấy lại mẫu khi bootstrap.
- (d) Dấu `?`: ba kịch bản (tính 0, tính 1, bỏ mẫu).
- (e) Không chọn thêm tầng để gán sau khi xem chỉ số engine theo nhãn vàng.
- (f) **Tập khó** = mẫu mà **luật cơ học tham chiếu** (dưới đây) khác nhãn cuối. Báo κ(A, B) trên tập khó và κ của luật cơ học với nhãn cuối.
- (g) Case study chọn theo luật: 5 TP có R cao nhất, 5 FP và 5 FN rút ngẫu nhiên (seed 0); địa chỉ ẩn bớt.
- (h) Báo riêng "silver" (nhãn luật của tác giả) và `key_sweep`; không cộng vào nhãn vàng.
- (i) CI κ bootstrap theo cụm: cụm = `delegate_7702`, nếu không có thì `creator`, rồi `deployer`, rồi từng mẫu (`sample_gold kappa --items`).
- (j) **Có và không có mẫu do bảng delegate quyết định** (v0.6.1). Mẫu do bảng delegate quyết định = mẫu có `code_at_event = 7702` (`gold_eval.delegate_decided`; 208 mẫu: +KEY 105, +ADDR 58, +D6 38, +NCD 4, −N8 2, −N1 1). Báo cả hai bản cho:
  - chỉ số engine: `evaluate(..., exclude_items=delegate_decided(items))`. Ô điều tra toàn bộ trừ đúng số mẫu bị bỏ; ô lấy mẫu co cỡ ô theo tỉ lệ, nên trọng số không đổi (test `test_gold_eval_exclude_delegate_decided_keeps_weights`);
  - κ: `sample_gold kappa --items` in thêm `is_misuse_no_delegate`, `type_no_delegate` kèm CI theo cụm.
  - Bỏ tầng KEY/ADDR ở (b) **không** bao gồm 38 mẫu +D6 do bảng delegate quyết định; chỉ (j) loại được chúng.

**Luật cơ học tham chiếu v0.6** (đọc đúng CODEBOOK §4.1, chỉ dùng cột trong file; bước cần explorer → NONE): `code_at_event = none` và `calldata_kind = call` → 1 (T4 nếu `xc_timing ∈ {before, unknown}`, còn lại T1); `code`/`destroyed` → 1 chỉ khi T3 (người nhận = địa chỉ, thành công); `7702` → 1 nếu `final_class = forwarder_sweeper`; còn lại 0. Kết quả trên 758 mẫu: 356 dương (T5/7702 174, T4/NCD 91, T4/PCD 47, T1/NCD 38, T1/PCD 5, T3 1). Luật này chưa áp ca 10 cho 11 mẫu 32 byte (cần cột Method, không có trong file) và chưa áp ca 7 (cần nhãn ví trên explorer), nên giữ nguyên số v0.6; 11 mẫu 32 byte là chỗ luật cơ học có thể khác người gán.

**Đường cơ sở (so với dấu của tầng, chỉ để báo, không dùng để chỉnh luật):** đồng ý 87,1%, κ = 0,744 (n = 758); trên 200 mẫu gán đôi 89,0%, κ = 0,783. Theo tầng (tỉ lệ đồng ý): +PCD 1,00, +NCD 0,98, +KEY 0,93, +ADDR 0,53, +D6 0,29; âm 0,95–1,00. Nghĩa là cột bằng chứng một mình đã quyết định phần lớn nhãn ở NCD/PCD/7702; κ của người gán cao **chưa** chứng tỏ họ thêm thông tin ngoài cột. Phần khác biệt nằm ở ADDR/D6 (cần xem lịch sử rút tiền trên explorer).

**Đi tay 20 mẫu đầu (G001–G020)** chỉ bằng cột: mọi mẫu đi hết cây không mắc kẹt và không mẫu nào thiếu cột cần cho bước A/B; 11 mẫu cần explorer để kết luận (6 ở bước D đếm rút nhanh, 5 ở bước C xét ý định), 9 mẫu kết luận được chỉ từ cột (6 T5/7702 theo bảng delegate, 3 T4). Ví dụ: G012 hôm nay là 7702 nhưng tx trước ngày kích hoạt nên `code_at_event = none` và đi bước D; G019 `destroyed` có `xc_timing` (đúng quy tắc, bước C không dùng). 19/20 khớp dấu tầng.

**KEY, đếm trên txlist (chỉ coin gốc, cận dưới; dùng cho báo cáo, không đưa người gán):** với luật "≥ 2 lần rút nhanh, ví lạ bất kỳ, ≥ 90%", +KEY: 14 mẫu ≥ 2 lần, **13 mẫu đúng 1 lần** (thành NONE/low theo v0.6), 86 mẫu 0 lần (chủ yếu là 7702: 105/113 +KEY có `code_at_event = 7702`, quyết định qua bảng delegate). +ADDR: 87 ≥ 2, 23 đúng 1. Âm có ≥ 2 lần: −N4 18/30 (ví sàn auto-sweep, phải loại theo ca 7), −N8 10, −N1 4, −N3 3. Đòi cùng một ví đích (bản nháp cũ) làm +ADDR rớt từ 87 xuống 55 nên không dùng.

**Kiểm ca 7 (ví sàn auto-sweep, v0.6.1) trên cả 30 mẫu −N4** (đi bước D2 + ca 7 bằng script trên txlist coin gốc; ví đích đối chiếu danh sách ví sàn có nhãn explorer trong `negatives.N4_HUBS`; không đi tay trên web):

- 18/30 mẫu có ≥ 2 lần rút nhanh. Mọi lần rút của cả 18 mẫu đi tới **một** ví đích có nhãn sàn (BSC: Binance Hot Wallet 6; ETH: Binance 14) → ca 7a → NONE (high).
- 12/30 mẫu còn lại có < 2 lần rút nhanh → NONE theo bước D.
- Tổng: 30/30 NONE theo v0.6.1; không có ca 7 thì 18 mẫu thành T5/KEY giả.
- Không lần rút nào của +KEY/+ADDR/+D6 đi tới ví sàn có nhãn, nên ca 7a không lật mẫu dương nào. Có 5 mẫu dương rút về một ví đích duy nhất (KEY 1, ADDR 3, D6 1); ca 7b chỉ lật chúng nếu ví đích đó chuyển tiếp sang sàn có nhãn, điều này không kiểm được ngoại tuyến.
- **Còn sót:** 17 mẫu âm có ≥ 2 lần rút nhanh tới ví **không** có nhãn (−N1 4, −N3 3, −N8 10; ví dụ một mẫu rút qua router 1inch, một mẫu có ví đích nhận từ 824 ví gửi). Ca 7b/7c có thể xử lý một phần; phần còn lại sẽ là T5 giả trong nhãn vàng nếu người gán không thấy liên kết sàn. Báo con số này trong paper.

## 5. Đăng ký trước

Trước khi gán: ghi sha256 các file dưới đây vào FINDINGS_LOG và gắn tag `prereg-gold-v0.6` (người điều phối làm sau khi soát). Mọi thay đổi sau tag ghi là sai lệch. Hash của chính file này nằm trong FINDINGS_LOG (một file không chứa được hash của chính nó). Tệp văn bản băm sau khi chuẩn hoá xuống dòng về LF (đúng bản sẽ commit, vì `.gitattributes` đặt `eol=lf`); hai file khoá băm nguyên byte như ở v0.5 để so được.

| file | sha256 | cách băm |
|---|---|---|
| `docs/CODEBOOK.md (v0.6.1)` | `513fe65e5de4bbde50dfea5c205efa233a4e07c4af62c3ff01a1051284fef35e` | LF |
| `data/gold/main_items.csv` | `c432cff6e307e7df5e794f1f16c202d82a246393fcc6b507469cfab0a9670974` | LF |
| `data/gold/main_key.csv (không commit; không đổi từ v0.5)` | `807f966042f20cd14c9f0463f73d67ddaf5f955bcb0bf1d269121aa9f9c86091` | nguyên byte, như v0.5 |
| `data/gold/main_reserve_key.csv (không commit; không đổi từ v0.5)` | `c193ffe66b5d659d2f3f549886636969e405f379316f0709dea585bd61677f3a` | nguyên byte, như v0.5 |
| `data/gold/delegate_lookup.csv (nội dung không đổi từ v0.6)` | `4d9ca0522e374917917a514c4c4097a9483859c52d8aabcd4c5ac0f6d85f3b0b` | LF |
| `src/address_misuse/gold_eval.py` | `8e2083c892dd1739913a816e9df324808f3e660e6d2f0a8cd7fa34087ae07f38` | LF |
| `src/address_misuse/sample_gold.py` | `5b4702a58c817f21140c630e570896c14a2b4c475991dd038a91a5694647493f` | LF |
| `src/address_misuse/gold_evidence.py` | `ba7e82aea2358659fec07599b25b4ebc41e0927ab6c3e5315b7620e1265a288f` | LF |

Kèm theo (không đổi từ v0.5): `src/address_misuse/engine/` (evaluate), `data/interim/engine_eval.parquet`, `data/interim/engine_metrics.json` (τ_warn = 63,0).

## 6. Hạn chế đã biết (ghi vào paper)

1. **Tx được chọn theo tầng:** `at` của mẫu dương là tx thỏa luật của tác giả (dòng đại diện của dataset), nên mẫu dương thỏa luật tác giả **gần như theo cách xây dựng**. Ngoại lệ (v0.6.1): 9 mẫu dương (+NCD 8, +PCD 1) có calldata đúng 32 byte và txlist trả `functionName` rỗng; theo ca 10 người gán có thể coi đây là event topic, không phải lời gọi hàm, nên mẫu có thể thành NONE. Mẫu âm có tx theo cách chọn riêng của từng tầng âm. Nhãn vàng đo engine trên đúng tx đó, không trên tx ngẫu nhiên của địa chỉ.
2. **Không độc lập giữa các mẫu:** nhiều mẫu chung delegate 7702 (264 mẫu có delegate hôm nay, 33 delegate), chung người tạo contract, hay chung ví đích của sweeper. CI κ lấy lại theo cụm delegate → creator → deployer; **chưa** gộp cụm theo ví đích của sweeper.
3. **T6** không có tầng riêng; chỉ có định nghĩa vận hành (CODEBOOK ca 18). Dự kiến rất hiếm; không ước lượng recall cho T6.
4. **Vòng tròn với engine:** `code_at_event`, `own_create_time`, `xc_*`, phân loại delegate và mẫu hình rút nhanh cũng là đầu vào của engine; precision/recall có thể bị thổi phồng. Luật cơ học (§4) cho thấy mức này.
5. **B gán phần lớn mẫu và thiết kế nghiên cứu** (biết tầng, tỉ lệ dương ~58%). Ước lượng qua §2.6.
6. **Tự giác mù:** `dataset_v2.parquet`, `engine_eval.parquet`, `main_items.csv` nằm trong repo và nối được với nhãn; `*_key.csv` bị gitignore nhưng có trên máy. Mù dựa vào cam kết.
7. **A có thể đã đọc CODEBOOK v0.5** (có số cỡ mẫu, tầng, tỉ lệ dương). **Điều kiện trước khi ký duyệt (v0.6.1):** người điều phối phải hỏi A đã đọc v0.5 chưa và ghi câu trả lời (ngày, có/không, đọc phần nào) vào PROGRESS.md trước khi A ký duyệt bảng delegate và trước khi gán. Câu trả lời được báo trong paper.
8. **Thời điểm ủy quyền 7702 không được tra:** `code_at_event = 7702` = hôm nay là 7702 và tx sau ngày kích hoạt. Ủy quyền có thể đặt sau tx; codebook bắt người gán xem tab Authorizations (bước D1).
9. **op/base/bsc_testnet** không có nguồn creation miễn phí → `xc_timing = unknown` khi chỉ các mạng này có code (12 mẫu `unknown`).
10. **Ảnh chụp hôm nay** dùng lại từ lần sinh v0.5 (cùng một ảnh cho mọi mẫu); `destroyed` không biết lúc huỷ.
11. **KEY là cận dưới:** ví lộ key chưa bị rút hai lần sẽ là NONE; đếm tự động chỉ tính coin gốc.
12. **κ ở n = 50 yếu** (dừng nhầm ~27% khi κ thật 0,85; vượt cổng ~28% khi κ thật 0,75): cổng chỉ chẩn đoán.
13. **Khung nhỏ:** 2.010 dòng / 1.680 địa chỉ; "~2.000 nhãn" nghĩa là gán hết khung (tối đa 1.680 địa chỉ nếu chạy hết lô 2).
14. **Người điều phối phân loại delegate** (§2.3) không mù; A/B chỉ rà soát. **Rủi ro neo:** người rà thấy lớp đã điền sẵn nên dễ đồng ý. Giảm bằng cách bắt ghi `ok` tường minh từng dòng và mở nguồn; đo bằng số dòng bị phản đối; báo chỉ số có và không có 208 mẫu do bảng delegate quyết định (§4 j). Phần lớn các mẫu này cũng nằm trong danh sách đen của engine (§2.3), nên ở đó nhãn vàng không độc lập với engine.
15. **Event topic 32 byte:** `calldata_kind` không tách được event topic khỏi lời gọi hàm (11 mẫu có `calldata_len = 32`); người gán quyết định theo ca 10 (Method trên explorer).
16. **`symexec_*` trộn hai nguồn:** một phần là kết quả của tác giả, phần còn lại là lần chạy của nhóm với giới hạn 120 giây. Hai nguồn khác cấu hình nên cột chỉ là gợi ý, không phải bằng chứng quyết định.
17. **Ca 7b/7c (ví gom không nhãn) không kiểm được ngoại tuyến:** cần xem ví đích có chuyển tiếp sang sàn không. 17 mẫu âm còn sót có ≥ 2 lần rút nhanh tới ví không nhãn (§4); chưa gộp cụm theo ví đích.

## 7. Sai lệch so với luật của tác giả (rules.py, Shao et al.)

- NCD của tác giả đòi `functionName` khác rỗng (Etherscan giải mã được) và `gasUsed ≤ 30.000`; codebook chỉ đòi `calldata_kind = call` (≥ 4 byte, không phải văn bản). PCD của tác giả không đòi `functionName` (dòng đó bị comment trong mã gốc).
- Tác giả bỏ calldata bắt đầu `0x00000000` (trừ độ dài 74) và `0xffffffff`; codebook không bỏ.
- T4 so với tx cho sẵn, không so với tx đầu tiên tới địa chỉ.
- T3 không có trong luật tác giả; lấy từ requirements.md §3.1.
- KEY của tác giả là "mọi tx vào ví có trong danh sách lộ key"; nhãn vàng cần ≥ 2 lần rút nhanh thấy được.

## 8. Lịch sử thay đổi

- **v0.1 (2026-10-16):** bản nháp đầu.
- **v0.2 (2026-10-19):** bỏ `n_tx`, `n_misuse_tx`, `cost_native` (lộ nhãn); ô không tra được ghi `-`.
- **v0.3 (2026-10-19):** `delegate_flag` → `delegate_symexec_transfer`, `delegate_known_wallet`; ca khó 6; mọi cột code/delegate tra cho mọi mẫu.
- **v0.4 (2026-10-25):** T2 cần tx thành công và sai ý định; KEY gán theo rút nhanh; `malicious` 4 giá trị; ca khó 10–15.
- **v0.4.1 (2026-10-25):** quy trình từng bước; không có cột danh sách khoá lộ (lộ nhãn 60/60).
- **Thiết kế mẫu (2026-10-25):** lấy hết dương và cảnh báo engine, âm có trọng số, danh sách dự phòng.
- **v0.5 (2026-10-26):** PCD theo tác giả (T1/T4 subtype PCD); T2 chỉ là hố đen; đơn vị là tx tại `at`; quy tắc "không rõ giờ tạo" → T4 low; bảng delegate; bỏ `redeploy`, `delegate_symexec_transfer`, `delegate_known_wallet`; quy trình gán đôi trước, cổng 0,70, danh sách bù, tập khó, hash đăng ký.
- **v0.6 (2026-10-26), sau đợt soát thứ hai:**
  - Tách tài liệu: CODEBOOK.md chỉ cho người gán (không cỡ mẫu, tầng, tỉ lệ, cổng κ); file này giữ thiết kế, quy trình, hạn chế, lịch sử. Hướng dẫn trong Excel không còn số thiết kế.
  - **Rò rỉ theo tầng đã sửa** (§3.2): `code_at_event`, `own_create_time`, `creator` tra cho mọi mẫu bằng một nguồn; `xc_*` điền theo một điều kiện trên cột nhìn thấy; thêm `destroyed`/`unknown`.
  - Thời gian: "trước tx" theo (block, vị trí); giữa chain theo giây, cùng giây không tính là trước; bỏ "tx đầu tiên" và `first_tx_date`.
  - `calldata_kind`; selector `-` không bao giờ là CA misuse; `0x64617461` = "data".
  - T3 có đường đi (bước C1).
  - KEY: ≥ 2 lần rút nhanh (ví lạ bất kỳ, ≥ 90%, ≤ 10 phút); 1 lần → NONE/low (trước đây GUIDE và codebook mâu thuẫn).
  - T6: định nghĩa vận hành (ca 18).
  - **Sai lệch có chủ ý:** bảng delegate do người điều phối điền sẵn, A/B rà soát (§2.3).
  - Cổng: 50 mẫu gán lại giữ nhãn phân xử nhưng ra khỏi κ chính thức; κ(`type`) đăng ký trước.
  - Sai số gán đơn: thêm bất đồng thô B–A và A gán lại mù 50 mẫu đơn (§2.6). Mẫu kiểm nhất quán ở lô 2 lấy từ mẫu gán đôi của A.
  - `HUONG_DAN_GAN_NHAN.md` đánh dấu đã cũ.
- **v0.6.1 (2026-10-26), sau đợt soát lại:**
  - Bảng delegate: `ok` hoặc lớp khác + `note` cho từng dòng; ô trống = chưa rà; A/B rà hết trước khi gán; lệnh `sample_gold check-delegates`. Không đổi `final_class` / `source`.
  - Báo chỉ số engine và κ có và không có 208 mẫu do bảng delegate quyết định (§4 j; `evaluate(exclude_items=...)`, `kappa` in thêm `_no_delegate`).
  - Ca 7 viết lại thành luật kiểm được chỉ từ explorer (7a ví sàn có nhãn, 7b ví gom chuyển tiếp sang sàn, 7c ví gom không liên kết sàn). Kiểm trên 30 mẫu −N4 (§4).
  - Cột `calldata_len`; ca 10 và bước B2 xét 32 byte theo Method.
  - `gold_evidence`: contract tạo trong chính tx → `unknown`; xử lý tường minh "No data found" của Etherscan; sửa chú thích kiểu `_nodereal`.
  - Hạn chế mới 16 (`symexec_*`), 17 (ca 7b/7c); hạn chế 1, 7, 14 viết rõ hơn.

## 9. Lưu trữ: agenda sửa codebook v0.4 (pilot, người gán A, 2026-10-21)

Chỉ là lịch sử, đã áp dụng ở v0.4–v0.6; có thể khác quy tắc hiện hành.

1. T2: §3 mâu thuẫn §4 (P024). → v0.5: PCD là T1/T4 subtype PCD.
2. Testnet làm chain gốc cho T4 (P036). → có tính, ca 12.
3. Calldata là event payload (P009). → không phải gọi hàm, ca 10.
4. Ưu tiên KEY và 7702. → ca 13.
5. `malicious = 1` khi chưa thấy tx rút (P030, P034, P045, P050). → ca 13.
6. Sau κ pilot (0,615): T2 cần tx sai ý định; KEY chỉ dương khi thấy rút nhanh; quy ước ô. Đề xuất dùng danh sách đen / `delegate_known_wallet` làm bằng chứng bị bỏ (bằng chứng phải độc lập với engine).
