# Giao thức nhãn vàng (D5): thiết kế, quy trình, đăng ký trước, hạn chế

Bản đi kèm [CODEBOOK.md](CODEBOOK.md) v0.6.3 (2026-10-30; v0.6.2 → v0.6.3 sau cổng κ 50 mẫu đầu, xem §8). **Người gán không đọc file này trước khi gán xong**: nó có cỡ mẫu, tầng, tỉ lệ và cổng κ. Codebook chỉ chứa quy tắc gán.

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

0. Người điều phối hỏi A đã đọc CODEBOOK v0.5 chưa, ghi câu trả lời vào PROGRESS.md (§6, hạn chế 7). Việc này vẫn đang chờ (việc của người điều phối).
1. A và B rà hết bảng delegate trên bản sao riêng (§2.3); người điều phối gộp; mọi phản đối được thống nhất; `sample_gold check-delegates --strict` báo 0 lỗi. **Chưa xong thì chưa tạo được file Excel**: `sample_gold sheet --set main` từ chối (v0.6.2).
2. Cả A và B gán **200 mẫu gán đôi** trước (`annotator_main_double_<A|B>.xlsx`), độc lập. Kiểm cổng (§2.4).
3. Phân xử (§2.5).
4. B gán 558 mẫu đơn (`annotator_main_single_B.xlsx`); A gán lại mù 50 mẫu đơn (§2.6).
5. Lô 2 nếu còn thời gian (§2.7).

### 2.3. Bảng tra delegate 7702 (sai lệch có chủ ý so với v0.5)

v0.5 định A và B cùng phân loại từ đầu. **v0.6:** người điều phối điền sẵn `final_class` và `source` trong `data/gold/delegate_lookup.csv` từ bằng chứng khách quan (mã nguồn đã verify qua Etherscan V2 `getsourcecode`, hoặc bytecode `eth_getCode`). 33 delegate: 12 `forwarder_sweeper`, 3 `legit_wallet`, 18 `unknown` (theo số mẫu có delegate hôm nay: 230 / 4 / 30). Trong 264 mẫu có delegate hôm nay (v0.6.2): 67 có `code_at_event = 7702` (delegate hôm nay đã có trước tx), 141 là `unknown` (delegate hôm nay tạo **sau** tx, §3.1), 56 là `none` (tx trước ngày kích hoạt EIP-7702). A và B **bắt buộc rà soát hết bảng trước khi gán mẫu nào**:

- **Bản sao riêng** (v0.6.2): `sample_gold delegate-copy A` / `delegate-copy B` tạo `data/gold/delegate_review_<A|B>.csv`, chỉ có cột của người đó, nên không ai thấy ý kiến của người kia. Hướng dẫn cho người rà: `data/gold/DELEGATE_REVIEW.md`.
- Mỗi dòng ghi rõ `class_X = ok` (đồng ý) hoặc một lớp khác kèm lý do ở `note_X` của chính người đó (phản đối). Cột `note` là lý do của người điều phối, không sửa. **Ô trống = chưa rà**, không phải đồng ý. Mỗi người tự kiểm bản của mình: `check-delegates <file> --who X`.
- Người điều phối gộp: `sample_gold merge-delegates <bản A> <bản B>`. Lệnh từ chối nếu bản sao đổi tập delegate hoặc đổi `final_class` / `source` / `note`.
- **Giải quyết phản đối** (trước khi gán, trên `delegate_lookup.csv` đã gộp): ba người bàn. Đổi lớp → người điều phối sửa `final_class`, ghi lý do vào `note`, xoá `class_A`, `class_B` của dòng đó, rồi **cả hai** người rà xem lại và ghi `ok`. Giữ lớp → người phản đối ghi lại `ok` (lý do cũ giữ ở `note_X`). Người điều phối không sửa `final_class` / `source` nếu chưa có lý do ghi rõ. Báo trong paper số dòng bị phản đối và số dòng đổi lớp.
- **Cổng cứng:** `sample_gold check-delegates` thoát mã 1 khi còn lỗi (ô trống, giá trị lạ, phản đối thiếu lý do). `--strict` thêm lỗi cho mọi phản đối chưa giải quyết, tức đòi `class_A`, `class_B` ∈ {`ok`, `final_class`}. `sample_gold sheet --set main` dùng đúng kiểm tra `--strict` và **từ chối tạo file Excel** khi còn lỗi. Cờ `--skip-delegate-check` chỉ cho test / chạy thử (in cảnh báo lớn), **không** dùng để tạo file thật cho người gán. Bảng hiện tại báo 66 lỗi (33 dòng × 2 người, chưa rà), đúng như mong đợi.
- Người rà phải mở nguồn (`explorer_url`) và tự kết luận trước khi đọc lớp đã điền (CODEBOOK ca 13).

Lý do điền sẵn: tiết kiệm thời gian và để phân loại dựa trên bằng chứng có nguồn ghi rõ. Cái giá: người điều phối biết thiết kế nên phân loại không mù, và lớp điền sẵn có thể **neo** (anchoring) người rà (§6, hạn chế 14). Vì vậy chỉ số engine và κ được báo cả có và không có các mẫu do bảng delegate quyết định (§4 j). `sample_gold main` chạy lại giữ nguyên các ô đã điền.

Trùng với engine theo cách xây dựng: danh sách đen của engine (`default_malicious_delegates`) chứa 130/230 mẫu `forwarder_sweeper` và 29/30 mẫu lớp `unknown` (theo delegate hôm nay). Trong 67 mẫu `code_at_event = 7702`: `forwarder_sweeper` 51 (42 trong danh sách đen), `legit_wallet` 4 (0), `unknown` 12 (11). Ở các mẫu này nhãn vàng và engine dùng chung một nguồn.

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
- **`code_at_event`** (`state_at_event`): getCode hôm nay lỗi → `unknown`; hôm nay 7702 → `none` nếu tx trước ngày kích hoạt EIP-7702 của chain; **`unknown` nếu contract delegate hôm nay được tạo không trước tx** (v0.6.2; bản ghi tạo delegate tra như mọi contract khác, cùng chain, so (block, vị trí)); ngược lại `7702`; có bản ghi tạo → so (block, vị trí trong block) với tx: trước → `code` (hôm nay còn code) / `destroyed` (hôm nay hết); sau → `none`; **tạo ngay trong chính tx đó** (cùng hash, hoặc cùng block và cùng vị trí) → `unknown` (v0.6.1; không được thành `none` vì sẽ thành PCD giả; trường hợp này không thể xảy ra khi tx gửi thẳng tới địa chỉ, nên gặp là lỗi dữ liệu; test `test_creation_inside_event_tx_is_not_pcd`; 0/758 mẫu); cùng block thiếu vị trí → `unknown`; không có bản ghi → `none` nếu hôm nay không code, `unknown` nếu có; lỗi → `unknown`.
- **Delegate tạo sau tx (v0.6.2):** 141/208 mẫu trước đây ghi `7702` có delegate hôm nay tạo **sau** tx (+KEY 75, +ADDR 41, +D6 23, +NCD 1, −N8 1). Lúc tx, delegate đó chưa tồn tại, nên v0.6.1 ghi `7702` là sai và người gán sẽ áp lớp của một delegate chưa có. Không ghi `none` vì 108/141 tx này có calldata gọi hàm (ví dụ `0x34fcd5be`, `0x8a4068dd`), dấu hiệu địa chỉ đã ủy quyền cho một delegate **khác** lúc tx rồi đổi sau. Không có node archive miễn phí (RPC công khai từ chối `eth_getCode` ở block cũ) nên ghi `unknown`; người gán xem tab Authorizations (CODEBOOK bước A). Test `test_state_at_event_7702_needs_delegate_before_tx`.
- **`calldata_kind`** khi không tra được tx: `unknown` (v0.6.2; trước là `-`, trùng nghĩa "chuyển coin thuần"). 0/758 mẫu bị ảnh hưởng.
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

**Thay đổi v0.6.1 → v0.6.2:** chỉ cột `code_at_event` của 141 mẫu (`7702 → unknown`, §3.1); mọi cột khác, tập mẫu, `tx_hash` và hai file khoá giống hệt. Phân bố `code_at_event`: `none` 376, `code` 169, `unknown` 141, `7702` 67, `destroyed` 5.

### 3.3. Cột mới / bỏ

- Thêm: `at_time` (giờ UTC đến giây, thay `at_date`), `tx_status`, `calldata_kind`, `own_create_time` (thay `own_create_date`), `creator`, `xc_create_time` (thay `first_create_date`).
- Bỏ: `create_kind`, `first_tx_date` (T4 so với tx cho sẵn, không so với tx đầu tiên).
- `calldata_kind`: `call` 506, `-` 208, `text` 44 (36 trong đó có selector `0x64617461` = ASCII "data", inscription).
- `calldata_len` (v0.6.1): số byte calldata, tính như nhau cho mọi mẫu từ input của tx (`-` nếu không tra được; 0/758). Phân bố: 0 → 208, 68 → 178, 4 → 82, 36 → 30, còn lại rải rác. 11 mẫu `call` có đúng 32 byte (độ dài của một event topic); 44 mẫu `call` có độ dài không dạng 4 + 32k. Người gán xét 32 byte theo ca 10 (xem Method trên explorer). Thêm cột này không đổi tập mẫu, thứ tự hay cột nào khác.
- T3: 40 tx là `transfer`/`transferFrom`; 1 tx có người nhận = chính contract (một mẫu có code, tx thành công).

## 4. Quy tắc báo (tiền đăng ký)

- (a) **Chỉ số chính theo địa chỉ** (`gold_eval.evaluate(unit='addr')`); theo dòng báo phụ.
- (b) Báo chỉ số engine hai lần: đầy đủ, và bỏ tầng KEY/ADDR (`exclude_strata`), vì nhãn KEY/ADDR dựa vào mẫu hình rút nhanh trùng luật `sweeper` của engine. Ước lượng khi bỏ tầng là cho quần thể không thuộc hai tầng đó.
- (c) Ô 0 sự kiện: cận Jeffreys (chính), Clopper–Pearson (bảo thủ). Ô điều tra toàn bộ không lấy lại mẫu khi bootstrap.
- (d) Dấu `?`: ba kịch bản (tính 0, tính 1, bỏ mẫu).
- (e) Không chọn thêm tầng để gán sau khi xem chỉ số engine theo nhãn vàng.
- (f) **Tập khó** = mẫu mà **luật cơ học tham chiếu** (dưới đây) khác nhãn cuối. Báo κ(A, B) trên tập khó và κ của luật cơ học với nhãn cuối.
- (g) Case study chọn theo luật: 5 TP có R cao nhất, 5 FP và 5 FN rút ngẫu nhiên (seed 0); địa chỉ ẩn bớt.
- (h) Báo riêng "silver" (nhãn luật của tác giả) và `key_sweep`; không cộng vào nhãn vàng.
- (i) CI κ bootstrap theo cụm: cụm = `delegate_7702`, nếu không có thì `creator`, rồi `deployer`, rồi từng mẫu (`sample_gold kappa --items`).
- (j) **Có và không có mẫu do bảng delegate quyết định.** Định nghĩa (v0.6.2): mẫu có `code_at_event = 7702` trong main_items.csv, tức hôm nay là 7702, tx sau ngày kích hoạt **và delegate hôm nay đã có trước tx** (`gold_eval.delegate_decided`; 67 mẫu: +KEY 30, +ADDR 17, +D6 15, +NCD 3, −N1 1, −N8 1). Đây là cận trên của số mẫu bảng có thể quyết định: thời điểm ủy quyền vẫn không được tra, nên vài mẫu có thể ủy quyền sau tx (người gán khi đó đi bước D2). 141 mẫu `unknown` có delegate (§3.1) **không** nằm trong tập này; người gán tự tra delegate lúc tx. Báo cả hai bản cho:
  - chỉ số engine: `evaluate(..., exclude_items=delegate_decided(items))`. Ô điều tra toàn bộ trừ đúng số mẫu bị bỏ; ô lấy mẫu co cỡ ô theo tỉ lệ, nên trọng số không đổi (test `test_gold_eval_exclude_delegate_decided_keeps_weights`);
  - κ: `sample_gold kappa --items` in thêm `is_misuse_no_delegate`, `type_no_delegate` kèm CI theo cụm.
  - **Đại lượng ước lượng** của bản "không có" là quần thể (khung) **trừ** các địa chỉ do bảng delegate quyết định. Ở ô lấy mẫu, cỡ miền con chỉ là ước lượng (co theo tỉ lệ đã gán), nhưng bootstrap giữ cỡ miền cố định, nên CI hơi hẹp hơn thật. Ghi rõ điều này khi báo.
  - **(j′) phụ, đăng ký trước:** mẫu `unknown` có `delegate_7702` mà người gán thấy ở tab Authorizations rằng lúc tx đã ủy quyền tới một delegate **có trong bảng** thì nhãn cũng do bảng quyết định. CODEBOOK bước A bắt người gán ghi địa chỉ đầy đủ (0x + 40 hex) của delegate đó vào `note`. Bộ phát hiện `gold_eval.delegate_named(labels, items, lookup)`: `code_at_event = unknown` và `note` chứa địa chỉ đầy đủ (không phân biệt hoa thường) của một delegate cùng chain trong `delegate_lookup.csv`; viết tắt không được tính. (j′) bỏ `delegate_decided` ∪ `delegate_named`: chỉ số engine dùng `note` của nhãn cuối; κ (`kappa --items` in `is_misuse_no_delegate_any`, `type_no_delegate_any`) bỏ mẫu mà **một trong hai** người ghi như vậy. (j) vẫn là bản chính; (j′) báo kèm.
  - (b) và (j) báo riêng, và báo thêm **một bản kết hợp** (bỏ tầng KEY/ADDR **và** bỏ mẫu do delegate quyết định; `evaluate(exclude_strata=..., exclude_items=...)`). Bỏ KEY/ADDR ở (b) không loại được 15 mẫu +D6 (và 3 +NCD, 2 âm) do delegate quyết định; chỉ (j) loại được chúng.
- (k) **Độ nhạy ca 7b/7c** (v0.6.2). Từ v0.6.2 lần rút nhanh về ví không có nhãn sàn **vẫn được tính** (CODEBOOK ca 7b/7c, `confidence = low`, note "ca 7b"/"ca 7c"), vì ví gom của sweeper bot trông giống hệt ví gom của sàn. Lần rút về ví có nhãn router / bridge / DEX cũng được tính (ca 7d, `low`, note "ca 7d"), vì đó có thể là đường kẻ trộm đổi tiền. Mẫu có note "ca 7b", "ca 7c" hoặc "ca 7d" (`gold_eval.ca7_unlabelled`, đọc từ note của nhãn cuối) được báo ba cách cho chỉ số engine: theo nhãn đã gán; **lật về 0** (`evaluate(flip_to_negative=...)`, kịch bản "đó là ví gom của sàn"); và bỏ khỏi miền (`exclude_items`). κ báo thêm khi bỏ mẫu mà một trong hai người ghi "ca 7b"/"ca 7c"/"ca 7d" (`kappa` in `is_misuse_no_ca7`, `type_no_ca7`).

**Luật cơ học tham chiếu v0.6.2** (đọc đúng CODEBOOK §4.1, chỉ dùng cột trong file; bước cần explorer → NONE): `code_at_event = none` và `calldata_kind = call` → 1 (T4 nếu `xc_timing ∈ {before, unknown}`, còn lại T1); `code`/`destroyed` → 1 chỉ khi T3 (người nhận = địa chỉ, thành công); `7702` → 1 nếu `final_class = forwarder_sweeper`; `unknown` → 0 (cần explorer); còn lại 0. Kết quả trên 758 mẫu: 233 dương (T4/NCD 91, T5/7702 51, T4/PCD 47, T1/NCD 38, T1/PCD 5, T3 1). Luật này chưa áp ca 10 cho 11 mẫu 32 byte (cần cột Method, không có trong file), chưa áp ca 7 (cần nhãn ví trên explorer) và chưa áp ngoại lệ ví đích có nhãn sàn của ca 13b; đó là các chỗ luật cơ học có thể khác người gán.

**Đường cơ sở (so với dấu của tầng, chỉ để báo, không dùng để chỉnh luật):** v0.6.2: đồng ý 71,1%, κ = 0,457 (n = 758); trên 200 mẫu gán đôi 74,0%, κ = 0,502. Theo tầng (tỉ lệ đồng ý): +PCD 1,00, +NCD 0,98, +KEY 0,27, +D6 0,17, +ADDR 0,15; âm 0,95–1,00. (v0.6.1: 87,1%, κ = 0,744; phần chênh đến từ 141 mẫu mà cột `7702` cũ cho phép kết luận T5 từ một delegate chưa tồn tại lúc tx.) Nghĩa là cột bằng chứng một mình quyết định phần lớn nhãn ở NCD/PCD; ở KEY/ADDR/D6 người gán phải xem explorer (lịch sử rút tiền, tab Authorizations).

**Đi tay 20 mẫu đầu (G001–G020)** (làm ở v0.6; ở v0.6.2 bốn mẫu G003, G006, G009, G010 đổi `7702 → unknown`, không đi lại) chỉ bằng cột: mọi mẫu đi hết cây không mắc kẹt và không mẫu nào thiếu cột cần cho bước A/B; 11 mẫu cần explorer để kết luận (6 ở bước D đếm rút nhanh, 5 ở bước C xét ý định), 9 mẫu kết luận được chỉ từ cột (6 T5/7702 theo bảng delegate, 3 T4). Ví dụ: G012 hôm nay là 7702 nhưng tx trước ngày kích hoạt nên `code_at_event = none` và đi bước D; G019 `destroyed` có `xc_timing` (đúng quy tắc, bước C không dùng). 19/20 khớp dấu tầng.

**KEY, đếm trên txlist (chỉ coin gốc, cận dưới; dùng cho báo cáo, không đưa người gán):** với luật "≥ 2 lần rút nhanh, ví lạ bất kỳ, ≥ 90%", +KEY: 14 mẫu ≥ 2 lần, **13 mẫu đúng 1 lần** (thành NONE/low theo v0.6), 86 mẫu 0 lần (chủ yếu là địa chỉ 7702: ở v0.6.2, 30/113 +KEY có `code_at_event = 7702` và 75 là `unknown`, người gán tra delegate lúc tx). +ADDR: 87 ≥ 2, 23 đúng 1. Âm có ≥ 2 lần: −N4 18/30 (ví sàn auto-sweep, phải loại theo ca 7), −N8 10, −N1 4, −N3 3. Đòi cùng một ví đích (bản nháp cũ) làm +ADDR rớt từ 87 xuống 55 nên không dùng.

**Kiểm ca 7 (v0.6.2: chỉ ví có nhãn sàn, 7a, mới loại lần rút)** bằng script trên txlist coin gốc (bước D2; ví đích đối chiếu danh sách ví sàn có nhãn explorer trong `negatives.N4_HUBS`; không đi tay trên web), cho mọi mẫu `code_at_event ∈ {none, 7702}` và mẫu `unknown` có delegate (584 mẫu):

- **−N4 (30 mẫu):** 18 mẫu có ≥ 2 lần rút nhanh, mọi lần rút đều về **một** ví có nhãn sàn (BSC: Binance Hot Wallet 6; ETH: Binance 14) → 7a không tính → 0 lần → NONE. 12 mẫu còn lại < 2 lần → NONE. Tổng 30/30 NONE, như v0.6.1 (không có ca 7: 18 T5/KEY giả).
- **Toàn bộ:** 178 mẫu có ≥ 2 lần rút nhanh khi chưa loại gì; **160** sau khi loại 7a (+ADDR 87, +D6 34, +KEY 14, +NCD 8, −N1 4, −N3 3, −N8 10). Không lần rút nào của mẫu dương về ví có nhãn sàn.
- **Vì sao bỏ ca 7b/7c kiểu v0.6.1:** 136/160 mẫu có ít nhất một lần rút về ví không nhãn mà một mẫu khác trong lô cũng rút về (một ví BSC nhận từ 19 mẫu). Nếu loại các lần rút về ví "dùng chung" này (gần với 7c cũ), 160 còn 113 (+ADDR 87 → 62, +D6 34 → 19, +KEY 14 → 10, +NCD 8 → 7, −N1 4 → 2): khoảng 47 mẫu, gần hết là dương, sẽ thành NONE. Đây chính là mẫu hình ví gom của sweeper bot, nên v0.6.2 vẫn tính các lần rút này và đo ảnh hưởng bằng (k).
- **Âm còn sót:** 17 mẫu âm (−N1 4, −N3 3, −N8 10) có ≥ 2 lần rút nhanh về ví không nhãn; theo v0.6.2 chúng nhiều khả năng thành T5 `low` có note ca 7b/7c, tức là dương giả tiềm năng trong nhãn vàng. Báo con số này và kết quả (k) trong paper.

## 5. Đăng ký trước

Trước khi gán: ghi sha256 các file dưới đây vào FINDINGS_LOG và gắn tag (người điều phối làm sau khi soát). Tag `prereg-gold-v0.6` đã gắn cho bản v0.6.1 (commit `6400e8d`). Bản v0.6.2 sửa sau tag đó nhưng **trước khi có nhãn nào**, do đợt soát thứ ba; mọi thay đổi ghi ở §8 và cần tag mới (đề xuất `prereg-gold-v0.6.2`). Mọi thay đổi sau tag mới ghi là sai lệch. Hash của chính file này nằm trong FINDINGS_LOG (một file không chứa được hash của chính nó). Tệp văn bản băm sau khi chuẩn hoá xuống dòng về LF (đúng bản sẽ commit, vì `.gitattributes` đặt `eol=lf`); hai file khoá băm nguyên byte như ở v0.5 để so được.

| file | sha256 | cách băm |
|---|---|---|
| `docs/CODEBOOK.md (v0.6.3, thay v0.6.2 `bedb1916…ffc` sau cổng κ)` | `1cf6f48fd9f96bdec8e13687d883ee3f62a0e28baddc531a916ad13fcaa8bad8` | LF |
| `data/gold/main_items.csv` | `6363c56f94b5bb51ddc1de251da1829f3714213f9a46d6957f3b2ea8dc4c18e7` | LF |
| `data/gold/main_key.csv (không commit; không đổi từ v0.5)` | `807f966042f20cd14c9f0463f73d67ddaf5f955bcb0bf1d269121aa9f9c86091` | nguyên byte, như v0.5 |
| `data/gold/main_reserve_key.csv (không commit; không đổi từ v0.5)` | `c193ffe66b5d659d2f3f549886636969e405f379316f0709dea585bd61677f3a` | nguyên byte, như v0.5 |
| `data/gold/delegate_lookup.csv (thêm cột note_A, note_B; ô cũ không đổi)` | `5e5e742b134b0b96d49918f2fba932109cf3700de662b2fc8c69a12254c37dd3` | LF |
| `data/gold/DELEGATE_REVIEW.md` | `c4e3bc00f377f5cb42ae56edd6ad8256abd6ad93c5e247686a2e6d722095e767` | LF |
| `src/address_misuse/gold_eval.py` | `9befd1613a836126dedbdb3f5c360712ee7c592ea0a616fe0ca3fd5d4f30cb96` | LF |
| `src/address_misuse/sample_gold.py` | `4ba17c0e420a18efc290774f7c3655007f754ee987acb699f52c1104ee2383b7` | LF |
| `src/address_misuse/gold_evidence.py` | `e9cbbe60ad66d2b20d9e61587e52f47d3a99d62d6470cef589e88bef9929d1b4` | LF |

Kèm theo (không đổi từ v0.5): `src/address_misuse/engine/` (evaluate), `data/interim/engine_eval.parquet`, `data/interim/engine_metrics.json` (τ_warn = 63,0).

## 6. Hạn chế đã biết (ghi vào paper)

1. **Tx được chọn theo tầng:** `at` của mẫu dương là tx thỏa luật của tác giả (dòng đại diện của dataset), nên mẫu dương thỏa luật tác giả **gần như theo cách xây dựng**. Ngoại lệ (v0.6.1): 9 mẫu dương (+NCD 8, +PCD 1) có calldata đúng 32 byte và txlist trả `functionName` rỗng; theo ca 10 người gán có thể coi đây là event topic, không phải lời gọi hàm, nên mẫu có thể thành NONE. Mẫu âm có tx theo cách chọn riêng của từng tầng âm. Nhãn vàng đo engine trên đúng tx đó, không trên tx ngẫu nhiên của địa chỉ.
2. **Không độc lập giữa các mẫu:** nhiều mẫu chung delegate 7702 (264 mẫu có delegate hôm nay, 33 delegate), chung người tạo contract, hay chung ví đích của sweeper (136/160 mẫu có ≥ 2 lần rút nhanh rút về ví mà mẫu khác cũng rút về, §4). CI κ lấy lại theo cụm delegate → creator → deployer; **chưa** gộp cụm theo ví đích của sweeper.
3. **T6** không có tầng riêng; chỉ có định nghĩa vận hành (CODEBOOK ca 18). Dự kiến rất hiếm; không ước lượng recall cho T6.
4. **Vòng tròn với engine:** `code_at_event`, `own_create_time`, `xc_*`, phân loại delegate và mẫu hình rút nhanh cũng là đầu vào của engine; precision/recall có thể bị thổi phồng. Luật cơ học (§4) cho thấy mức này.
5. **B gán phần lớn mẫu và thiết kế nghiên cứu** (biết tầng, tỉ lệ dương ~58%). Ước lượng qua §2.6.
6. **Tự giác mù:** `dataset_v2.parquet`, `engine_eval.parquet`, `main_items.csv` nằm trong repo và nối được với nhãn; `*_key.csv` bị gitignore nhưng có trên máy. Mù dựa vào cam kết.
7. **A có thể đã đọc CODEBOOK v0.5** (có số cỡ mẫu, tầng, tỉ lệ dương). **Điều kiện trước khi ký duyệt (v0.6.1):** người điều phối phải hỏi A đã đọc v0.5 chưa và ghi câu trả lời (ngày, có/không, đọc phần nào) vào PROGRESS.md trước khi A ký duyệt bảng delegate và trước khi gán. Câu trả lời được báo trong paper.
8. **Thời điểm ủy quyền 7702 không được tra:** `code_at_event = 7702` = hôm nay là 7702, tx sau ngày kích hoạt và delegate hôm nay đã có trước tx (67 mẫu). Ủy quyền vẫn có thể đặt sau tx; codebook bắt người gán xem tab Authorizations (bước D1). 141 mẫu có delegate hôm nay tạo sau tx nên ghi `unknown`; delegate lúc tx (nếu có) phải tra tay, không có node archive để kiểm tự động.
9. **op/base/bsc_testnet** không có nguồn creation miễn phí → `xc_timing = unknown` khi chỉ các mạng này có code (12 mẫu `unknown`).
10. **Ảnh chụp hôm nay** dùng lại từ lần sinh v0.5 (cùng một ảnh cho mọi mẫu); `destroyed` không biết lúc huỷ.
11. **KEY là cận dưới:** ví lộ key chưa bị rút hai lần sẽ là NONE; đếm tự động chỉ tính coin gốc.
12. **κ ở n = 50 yếu** (dừng nhầm ~27% khi κ thật 0,85; vượt cổng ~28% khi κ thật 0,75): cổng chỉ chẩn đoán.
13. **Khung nhỏ:** 2.010 dòng / 1.680 địa chỉ; "~2.000 nhãn" nghĩa là gán hết khung (tối đa 1.680 địa chỉ nếu chạy hết lô 2).
14. **Người điều phối phân loại delegate** (§2.3) không mù; A/B chỉ rà soát. **Rủi ro neo:** bảng rà (`delegate_lookup.csv`, bản sao riêng và `DELEGATE_REVIEW.md`) hiển thị lớp điền sẵn **và lý do của người điều phối** (`source`, `note`, cột "Bằng chứng", "Ghi chú"); giữ lại vì người rà cần chúng để tìm chỗ cần xem, nhưng chúng dễ làm người rà đồng ý theo. Giảm bằng cách bắt ghi `ok` tường minh từng dòng, mở explorer và tự kết luận trước, rà trên bản sao riêng (A và B không thấy ý kiến của nhau, nhưng vẫn thấy lý do của người điều phối); đo bằng số dòng bị phản đối; báo chỉ số có và không có 67 mẫu do bảng delegate quyết định (§4 j). Phần lớn các mẫu này cũng nằm trong danh sách đen của engine (§2.3), nên ở đó nhãn vàng không độc lập với engine.
15. **Event topic 32 byte:** `calldata_kind` không tách được event topic khỏi lời gọi hàm (11 mẫu có `calldata_len = 32`); người gán quyết định theo ca 10 (Method trên explorer).
16. **`symexec_*` trộn hai nguồn:** một phần là kết quả của tác giả, phần còn lại là lần chạy của nhóm với giới hạn 120 giây. Hai nguồn khác cấu hình nên cột chỉ là gợi ý, không phải bằng chứng quyết định.
17. **Ca 7b/7c/7d (ví gom không nhãn, ví router / bridge):** từ v0.6.2 vẫn tính là rút nhanh (`low`), vì không phân biệt được ví gom của sàn với ví gom của kẻ trộm chỉ từ explorer, và router / bridge có thể là đường đổi tiền của kẻ trộm. Chỉ nhãn sàn / custodian (7a) mới loại một lần rút. Hệ quả: địa chỉ nạp của sàn mà ví gom chưa có nhãn sẽ thành T5 giả (17 mẫu âm có khả năng, §4). Đo bằng phân tích độ nhạy (§4 k); chưa gộp cụm theo ví đích.

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
  - Gắn tag `prereg-gold-v0.6` (commit `6400e8d`).
- **v0.6.2 (2026-10-26), sau đợt soát thứ ba, sau tag `prereg-gold-v0.6`, trước khi có nhãn nào:**
  - **Ca 7:** chỉ ví nhận có nhãn sàn / custodian (7a) mới không tính; 7b, 7c và ví có nhãn router / bridge (7d, thêm ở bản soát cuối; CODEBOOK §3.4 trước đó còn miễn router / bridge, nay khớp ca 7a, D2, D5 và hướng dẫn Excel) vẫn tính là rút nhanh, `confidence = low`, note. Lý do: 7c cũ ẩn ví gom của sweeper bot (~47 mẫu, gần hết dương, sẽ thành NONE). Thêm phân tích độ nhạy (§4 k; `ca7_unlabelled`, `evaluate(flip_to_negative=...)`, κ `_no_ca7`).
  - **Ca 13b và bước D1:** `forwarder_sweeper` có ví đích mang nhãn sàn (ca 7a) → NONE (trước đây luôn T5, mâu thuẫn ca 7a).
  - **`code_at_event`:** delegate hôm nay tạo sau tx → `unknown` (141 mẫu; trước ghi `7702`). Tập do bảng delegate quyết định còn 67 mẫu (§4 j). Luật cơ học và đường cơ sở tính lại (κ 0,744 → 0,457).
  - **Cổng rà delegate cứng:** `check-delegates` thoát mã 1; `sheet --set main` từ chối khi chưa rà xong **hoặc còn phản đối chưa giải quyết** (`check-delegates --strict`; thủ tục giải quyết ở §2.3; thêm ở bản soát cuối) (`--skip-delegate-check` chỉ cho test); cột `note_A`, `note_B` riêng cho từng người rà; bản sao riêng (`delegate-copy`) và lệnh gộp (`merge-delegates`); `DELEGATE_REVIEW.md` cập nhật.
  - §4 (j): định nghĩa rõ, đại lượng ước lượng là quần thể trừ mẫu do delegate quyết định, bootstrap giữ cỡ miền cố định (CI hơi hẹp), thêm bản kết hợp (b)+(j).
  - `calldata_kind` khi không tra được tx: `unknown` thay cho `-`.
  - Bản soát cuối (sau commit `310efff`, vẫn v0.6.2, chưa có nhãn): (j′) cho mẫu `unknown` mà người gán ghi delegate có trong bảng (`delegate_named`, κ `_no_delegate_any`); bước A của CODEBOOK và hướng dẫn Excel tách rõ `unknown` không có / có `delegate_7702`, người gán ghi địa chỉ đầy đủ của delegate lúc tx vào note.
  - Hướng dẫn trong Excel ghi v0.6.2; `HUONG_DAN_GAN_NHAN.md` thay bằng một dòng trỏ tới CODEBOOK (bỏ số thiết kế).
- **v0.6.3 (2026-10-30), SAU khi có nhãn: sai lệch so với tiền đăng ký.** Cổng κ 50 mẫu đầu cho κ(`is_misuse`) = 0,692 < 0,70 (tag `prereg-gold-v0.6.2`; hash nhãn ở FINDINGS_LOG). Theo §2.4: dừng, phân xử 7 bất đồng ([data/gold/ARBITRATION_gate50.md](../data/gold/ARBITRATION_gate50.md)), sửa codebook, gán lại 50 mẫu đầu. Sửa (CODEBOOK "Thay đổi v0.6.3", duyệt bởi người dùng 2026-10-30; A ký duyệt trước khi gán lại): (1) rút nhanh không tính nếu tx rút ví nhận lại tài sản (swap, mint, stake…); (2) lượng ra cộng phí gas, không vượt khoản vào; (3) NFT là tài sản; (4) D2 luôn đếm lịch sử kể cả tx mẫu rỗng/fail; (5) delegate ngoài bảng = `unknown`. Ca 7d giữ nhưng bị (1) giới hạn. Codebook được tinh chỉnh sau khi thấy 7 bất đồng; 150 mẫu gán đôi còn lại là phần chưa dùng để sửa. Tập mẫu, hai file khoá, bảng delegate không đổi. 50 mẫu đầu: nhãn vàng = nhãn phân xử sau khi gán lại; không vào κ chính thức; κ chính thức tính trên 150 mẫu gán đôi còn lại + 50 mẫu đơn có `double_extra_rank` nhỏ nhất (cả A và B gán). Phải chạy lại độ nhạy ca 7 (§4 k) vì (1) làm giảm số lần rút tính được.

## 9. Lưu trữ: agenda sửa codebook v0.4 (pilot, người gán A, 2026-10-21)

Chỉ là lịch sử, đã áp dụng ở v0.4–v0.6; có thể khác quy tắc hiện hành.

1. T2: §3 mâu thuẫn §4 (P024). → v0.5: PCD là T1/T4 subtype PCD.
2. Testnet làm chain gốc cho T4 (P036). → có tính, ca 12.
3. Calldata là event payload (P009). → không phải gọi hàm, ca 10.
4. Ưu tiên KEY và 7702. → ca 13.
5. `malicious = 1` khi chưa thấy tx rút (P030, P034, P045, P050). → ca 13.
6. Sau κ pilot (0,615): T2 cần tx sai ý định; KEY chỉ dương khi thấy rút nhanh; quy ước ô. Đề xuất dùng danh sách đen / `delegate_known_wallet` làm bằng chứng bị bỏ (bằng chứng phải độc lập với engine).
