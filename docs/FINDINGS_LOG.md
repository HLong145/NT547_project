# Nhật ký phát hiện (dùng khi viết paper)

Ghi lại mọi quan sát có thể đưa vào paper, kèm cách tái tạo. Mới nhất ở trên.

## 2026-10-24 — D3b Polygon: misuse trên Polygon lớn hơn Arbitrum nhiều, 88% NCD là Type 4 (nhãn TẠM)

Tái tạo: `python -X utf8 -m address_misuse.l2_misuse txlist --chain polygon --focus author --max-records 1000` rồi
`... rules --chain polygon --focus author` → `data/interim/l2_misuse_polygon.parquet`. Loss tính bằng POL (native).

- Tập xét: key lộ + dương CA tác giả (ETH/BSC) có tx đến thành công trên Polygon: NCD 13.608, PCD 4.634, KEY 4.450;
  22.679 có txlist (13,9% bị cắt ở 1.000 tx, nhưng chỉ 0,8% địa chỉ dương bị cắt → số dương gần đủ, loss là cận dưới).
  13 PCD bỏ vì không biết lúc tạo (rà soát lần 2, #5).
- Luật tác giả nguyên bản (Polygon `gasUsed` chỉ là gas L2 nên điều kiện gas ≤ 30.000 dùng được, khác Arbitrum):
  | loại | địa chỉ | tx misuse | loss (POL) |
  |---|---|---|---|
  | NCD, không code ở mạng khác | 1.532 | 37.006 | 18.778 |
  | NCD, Type 4 (có code ở mạng khác) | 11.614 | 221.022 | 125.909 |
  | PCD | 128 + 167 XC | 12.539 | 29.639 |
  | KEY | 4.447 | 31.649 | 112.810 |
- **13.441 / 18.229 địa chỉ CA tác giả báo trên ETH/BSC cũng là misuse trên Polygon** (Arbitrum: 1.316 theo luật gốc).
  Misuse trên Polygon bắt đầu sớm: năm misuse đầu 2021 5.436, 2022 5.245, 2023 2.516, 2024 1.187, 2025 2.730, 2026 737.
- Loss tập trung: NCD top 1 = 30%, top 10 = 75%; PCD top 1 = 67%, top 10 = 99%; trung vị ~0,006 POL/địa chỉ.
- KEY: 3.023/4.447 địa chỉ chỉ có tx value 0 (như Arbitrum, lệnh của kẻ chiếm ví); 1.424 địa chỉ có người gửi value.
- → Paper: Type 4 (gọi nhầm chain) là dạng misuse chủ yếu trên Polygon; con số tác giả chỉ tính ETH/BSC đánh giá thấp
  phạm vi misuse của cùng tập địa chỉ. Cần D5 kiểm mẫu trước khi dùng làm số chính thức.

## 2026-10-24 — Rà soát lần 2 (mọi module) + baseline GoPlus

**Lỗi đã sửa:**
1. *Mẫu dương PCD chọn sai tx (Module 3, nghiêm trọng).* `pick_event` chọn tx SAU khi contract được tạo, trong khi
   Rule 2 của tác giả gắn cờ tx gọi hàm TRƯỚC khi tạo (`block < creation`); sau khi tạo là gọi contract bình thường.
   Lần sửa 2026-10-23 (#4) đã hiểu ngược. Nay: +PCD = tx gọi hàm (gas > 21.000) trước khi tạo; −N5 (contract
   recovery) = tx sau khi tạo (câu hỏi là có báo nhầm contract hợp lệ không).
2. *Contract tự huỷ bị coi là địa chỉ trống.* `Features.state()` dùng getCode hôm nay; contract đã tạo trước `at`
   rồi selfdestruct (vd. Dice2Win trong N8) bị chấm như NCD (T1 = 1). Nay coi là có code (symexec không có → 0,3).
3. *Loss dương mới D6 thiếu phí gas.* `cost_wei_new` chỉ cộng value, còn loss tác giả = value + gas. `d6_new recost`
   tính lại từ cache: 0,0857 → 0,0868 ETH, không đổi nhãn nào; thêm cột `value_wei_new`.
4. *Ví online dùng trọng số/ngưỡng học có S_history* nhưng online không có lịch sử (S_history = 0, không có luật
   `sweeper`) → R bị kéo thấp mà τ không đổi. Nay online dùng cấu hình học lại không có history (ablation "bỏ history":
   w = bytecode 0,28 / cross 0,16 / osint 0,56, τ 43,7). `wallet.replay` báo hai chế độ: `online` (đúng như ví chạy
   thật) và `offline` (có lịch sử, cận trên); KEY báo riêng tx value > 0.
5. *L2 / replay: PCD không biết lúc tạo* thì luật tác giả chạy như NCD trên một contract → nay bỏ, không đoán
   (arb: 7 địa chỉ, không ca nào bị gắn cờ, số liệu D3b không đổi).

**Hạn chế cần nêu trong paper (không sửa được):**
- *Luật cứng `malicious_delegate` ≈ định nghĩa nhãn ADDR* (ADDR của tác giả bắt buộc delegate có đường chuyển tiền):
  58/58 ADDR test dính luật này. Recall ADDR do luật cứng là đúng theo định nghĩa, không chứng minh khả năng phát hiện;
  báo riêng phần "chỉ R". Không dựng được danh sách đen chỉ từ train vì EIP-7702 kích hoạt 2025-05 (mọi mẫu 7702 ở test).
  Âm 7702 phần lớn đã có symexec delegate (N1 2/2, N8 5/6) nên không lệch kiểu "chỉ dương có symexec".
- *Âm theo tx không kiểm tay:* N8 có 2 tx ETH gửi calldata tới địa chỉ không code (có thể là NCD chưa ai gắn cờ);
  N2/N8 ETH: 0/1.235 đích được tạo sau tx (không có PCD lẫn vào); BSC không có thời điểm tạo để kiểm.
- *D5:* pilot 50 mẫu lấy từ dữ liệu tác giả; mẫu chính (~2.000) phải lấy từ `dataset_v2` (test + ngoài thời gian +
  `needs_review`) thì nhãn vàng mới dùng để chấm engine được.

**Baseline GoPlus** (`engine.goplus`, Address Security API, miễn phí): cờ độc hại bất kỳ trên địa chỉ đích, trạng thái
lúc tra (2026-10) — GoPlus được lợi vì biết sau sự việc. Gắn vào `engine.metrics` (chỉ trên mẫu tra được, so cùng mẫu
với engine và "GoPlus HOẶC engine"). Tra xong 99,3% địa chỉ (27 lỗi quá giới hạn tốc độ). Kết quả (bản trước khi sửa
lỗi probe bên dưới, GoPlus không đổi): trên test GoPlus recall 2,2%, precision 0,31, F1 0,04, báo nhầm 1,4% (21% trên
N7 contract đa chuỗi hợp lệ); engine cùng mẫu F1 0,86; "GoPlus HOẶC engine" F1 0,84 (kém engine một mình vì thêm báo
nhầm). Ngoài thời gian: GoPlus F1 0,03. GoPlus chỉ gắn cờ 0–5% dương → phần lớn misuse (nhất là NCD/PCD/ADDR) chưa có
trong danh sách đen, đúng luận điểm của đề tài.

**Lỗi 6 (phát hiện sau, nghiêm trọng): `FeatureStore.probe` nuốt lỗi RPC.** Một lô getCode ~1.900 địa chỉ luôn timeout ở
RPC công khai; `except Exception` bỏ qua, địa chỉ không có code → `state()` = None → S_bytecode = 0 và không có luật
delegate. Ảnh hưởng 1.939 địa chỉ: 42 dương D6 (23 ADDR D6 không dính luật `malicious_delegate`, tức recall ADDR ngoài
thời gian bị đánh giá thấp) và phần lớn âm N2/N3/N8 (điểm bytecode bằng 0 thay vì điểm thật, tức báo nhầm bị đánh giá
thấp). Sửa: tra theo lô 100 (`PROBE_CHUNK`), in lỗi RPC, `evaluate` cảnh báo nếu còn địa chỉ thiếu code. Sau sửa: 0
mẫu state NaN (trước: 1.659/6.429). Phải symexec lại ~940 contract mới (trước đó coi là chưa phân tích, điểm 0,3) rồi chạy
lại metrics / replay / freeze; **mọi số liệu Module 3–4 và dataset_v2 trước mục này là tạm, chưa dùng trong paper.**

**Hạn chế bổ sung (rà soát tiếp):** 67/150 mẫu KEY BSC (45%) và 7/150 KEY ETH không có tx đi vào nào trong txlist (chỉ
có tx đi ra, trung bình 7 tx) → `no_time`, bị loại khỏi đánh giá; recall KEY BSC (1,00) chỉ trên 83 mẫu còn lại, tức
nhóm KEY kiểu "chỉ thấy tx đi ra" chưa được đo. Cần nêu trong paper; chưa rõ nguyên nhân (nghi tx loại 4 mà `to` là
bên khác, hoặc nguồn NodeReal thiếu tx nội bộ).

## 2026-10-24 — Rà soát độc lập (advisor Opus, chỉ đọc) sau lần 2: 4 lỗi sửa, 8 hạn chế ghi nhận

Mọi mục đã kiểm lại trên code trước khi sửa. **Số liệu Module 3–4 và dataset_v2 trước mục này là tạm.**

**Đã sửa (chạy lại evaluate → metrics → replay → freeze):**
1. *T2 "hố đen" bật cho mọi contract không có đường rút coin, kể cả khi tx không gửi coin* (ERC-20, router): 48% đích
   N2/N8 là T2, 903 dòng train đều là âm, 0 dương. Trọng số học được bị chi phối bởi lỗi này (advisor học lại với T2
   tắt: bytecode 0,06 → 0,50, history 0,16 → 0,02). RISK_SCORE §2.1 yêu cầu "contract nhận coin". Nay có ctx thì chỉ
   T2 khi `value > 0`.
2. *Sự kiện dương NCD không phải lúc nào cũng là tx misuse theo luật tác giả* (34/600 = 5,7% không thoả: 10 là văn bản
   IDM, 12 thiếu functionName, 9 gas > 30k, 2 thất bại). Nay `pick_event` NCD lọc gas ≤ 30.000, thành công, input
   không phải văn bản (functionName không kiểm được: chỉ có cho tx có tên hàm Etherscan).
3. *Baseline getCode*: docstring nói dùng `has_call` nhưng `_row` không ghi cột này → luôn rơi về T1 (có bộ lọc IDM). Nay
   ghi `has_call`.
4. *`test` lẫn `out_of_time`*: 822/2.018 mẫu test (41%) cũng ≥ 2025-09-01, gồm cả 42 dương D6 (DATASHEET §8 nói D6 chỉ
   thuộc out_of_time). Thêm tập `test_in_time` (test, không out_of_time) vào `engine.metrics`; số liệu chính của paper
   nên báo `test_in_time` và `out_of_time` riêng.

**Hạn chế ghi nhận (chưa sửa, cần nêu trong paper hoặc làm sau):**
- *Nguồn delegate chỉ có ở dương*: delegate "lúc tác giả thu thập" (sau `at`) chỉ ghi cho EOA KEY/ADDR của tác giả; âm
  dùng delegate hôm nay. Danh sách đen của engine (`flag == 1`) khác danh sách định nghĩa nhãn ADDR D6 → 0/38 ADDR D6 trúng
  `malicious_delegate`. (Mục "Lỗi 6" ở trên gán một phần cho `probe`; phần còn lại là chênh danh sách.) Luật cứng này
  vẫn ≈ định nghĩa nhãn ADDR, nên recall ADDR phải báo cùng phần "chỉ R".
- *τ dựa trên 75 mẫu N8 ở val* (ETH 55, BSC 20): FPR ≤ 1% nghĩa là 0 báo nhầm → τ do một mẫu quyết định. Cần pool âm val
  lớn hơn hoặc bootstrap độ biến thiên của τ; `τ_block = τ_warn`.
- *Recall theo nhóm tính cả luật cứng*: KEY 300/300 là `leaked_key`; ADDR dính `malicious_delegate`/`sweeper`. Báo riêng
  "chỉ luật cứng" và "chỉ R" theo nhóm.
- *S_cross thiếu mốc thời gian cho âm và D6* (chỉ có cho CA của tác giả): hệ số cố định 0,7, tác động nhỏ hiện tại.
- *functionName "?"* cho mọi input ≥ 10 ký tự ở replay BSC và L2 (`l2_misuse`): NCD gắn cờ nhiều hơn tác giả (chỉ chữ ký
  đã biết) → số liệu NCD BSC replay / L2 là cận trên.
- *`excluded`* bỏ 422 N2 + 154 N8 khỏi test (contract phổ biến); FPR trên N8 bị loại 1,3% vs 0,4% → hơi lạc quan.
  Bootstrap resample theo dòng, không theo địa chỉ (cluster bootstrap).
- *`sweeper` bật cho 2 N8 ETH ở test*: "0 báo nhầm" chỉ đúng với train/val.
- *Nghi ngờ*: trạng thái 7702 dùng getCode hôm nay cho mọi `at` ≥ kích hoạt, không có mốc uỷ quyền; ủy quyền có thể xảy ra
  sau `at` (3 ADDR theo ước lượng thô). Cách sửa: lấy thời điểm tx loại 4.
- DATASHEET §3 và §5 cũ (lịch sử ETH nay đều từ txlist có input, IDM/T3 áp dụng cho cả ETH).

## 2026-10-24 — Xử lý các hạn chế của lượt rà soát độc lập

Mỗi mục là một hạn chế trong mục trước; **số liệu Module 3–4 sẽ chạy lại sau khi symexec xong** (còn ~400 contract).

- **Danh sách đen delegate thống nhất** (`default_malicious_delegates`): seed `flag == 1` HỢP delegate D6 thoả điều kiện
  ADDR của tác giả (`author_rule`), trừ ví hợp lệ N6 (386 delegate). `wallet.online` dùng chung hàm này (trước đây chỉ D6),
  nên engine, replay và ví thật cùng một định nghĩa. Thêm cột `delegate_src` (`recorded` = snapshot tác giả gần `at`,
  chỉ có ở dương; `current` = getCode hôm nay) và báo `by_delegate_src` trong metrics để thấy phần lệch nguồn.
  Luật vẫn ≈ định nghĩa nhãn ADDR (không thể dựng danh sách đen chỉ từ train: EIP-7702 kích hoạt 2025-05) → luôn báo
  kèm "chỉ R".
- **Ngưỡng τ**: τ_warn chọn trên FPR ≤ 1% của lưu lượng bình thường N2+N3+N8 (~190 mẫu val, trước đây 75 mẫu N8);
  τ_block = precision ≥ 0,95 VÀ không báo nhầm âm val nào (trước đây trùng τ_warn nên vô nghĩa). Độ biến thiên τ báo bằng
  bootstrap val theo địa chỉ (`threshold_boot`: p5/p50/p95).
- **Bootstrap theo địa chỉ** (cluster) thay cho theo dòng: mọi dòng cùng (chain, address) được chọn cùng nhau. CI rộng hơn,
  đúng hơn vì mẫu tx của cùng contract không độc lập.
- **Recall theo loại tách luật cứng và R**: `recall_by_group_hard`, `recall_by_group_R_only_on_soft` (kèm n mẫu mềm),
  `fp_by_hard_rule` (báo nhầm do `sweeper` / `malicious_delegate` / `leaked_key`).
- **Âm bị `excluded`**: báo FPR riêng trên chúng và trên âm test giữ lại (`excluded_neg`) để thấy mức lạc quan.
- **functionName** ở NodeReal (replay BSC) và Blockscout (OP): đã thử thay "?" bằng ánh xạ selector → tên học từ txlist
  ETH, rồi **bỏ**. Kiểm lại đúng tập liên quan (tx giống NCD: gas ≤ 30.000, thành công, input không phải văn bản): "?"
  cho mọi input đúng 94,3% còn ánh xạ chỉ 89,7% (kiểm chung 0,70 / 0,57 trước đó là trên mọi tx, không đúng quần thể NCD).
  Giữ "?" nên số liệu NCD ở replay BSC / OP là **cận trên** (gắn cờ hơi nhiều hơn tác giả); Arbitrum / Polygon lấy từ
  Etherscan nên có functionName thật.
- **Rà soát lượt hai (advisor)**: (1) ablation "bỏ history" nay cũng bỏ luật cứng `sweeper` (cần lịch sử), trước đây
  vẫn bật nên số "online" lạc quan; (2) `τ_block` thực chất là "0 báo nhầm trong âm val" (với ~290 âm, FPR ≤ 0,1% = 0 báo
  nhầm), chưa phải ngưỡng có ý nghĩa thống kê; (3) báo thêm GoPlus và engine-chỉ-R trên mẫu không dính luật cứng để so
  công bằng; (4) blacklist delegate thống nhất không gắn thời gian nên có thể gắn `malicious_delegate` cho vài âm N8 ETH ở
  test (xem `fp_by_hard_rule`); (5) replay đếm địa chỉ dương NCD/PCD không có tx nào bị luật gắn cờ sau mốc test;
  (6) `delegate_src = recorded` chỉ khi có `at`.
- **S_cross thiếu mốc thời gian**: đo lại, chỉ 32/700 mẫu có T4 (15 NCD + 14 PCD tác giả, 2 D6 NCD, 1 N1) thiếu
  `first_create_ts`; nhỏ, không sửa.
- **Test và out_of_time giao nhau**: `freeze` xuất thêm `splits_v2/test_in_time.csv` (không trùng); DATASHEET §8 ghi rõ.
- **Chưa giải quyết được: thời điểm uỷ quyền EIP-7702.** Trạng thái 7702 dùng getCode hôm nay; xác định lúc uỷ quyền cần
  archive node (RPC công khai trả lỗi "Archive requests require a personal token"; txlist chỉ thấy tx của chính EOA,
  tx loại 4 do bên khác gửi không có ở đó). Với dương ADDR, tx `at` do luật tác giả gắn cờ là lệnh sweep sau khi đã uỷ quyền
  nên không ảnh hưởng; ảnh hưởng chỉ ở 12 âm 7702 (N1 2, N8 10). Cần ghi trong paper; sửa nếu có token archive.
- **`sweeper` bật cho 2 N8 ETH ở test**: giữ luật (ngưỡng chọn trên train+val, 0 báo nhầm ở đó); báo nhầm do luật cứng
  nay xuất hiện riêng trong metrics.

## 2026-10-24 — Dataset v2 (chạy thử): contract recovery N5 là âm khó nhất

- v2 = 1.558 dương luật tác giả + 42 dương mới D6 (ETH, `at` ≥ 2025-09-01, đều ở test) + 4.947 âm (thêm N5: 118
  contract recovery tại địa chỉ PCD). 42 contract N5 trước đây nằm trong mẫu dương PCD của tác giả → chuyển sang âm
  (tác giả gắn cờ PCD cả contract recovery hợp lệ). 56 mẫu `needs_review` (42 D6 + 14 N5 chỉ dựa vào tên) chờ D5.
- KEY của tác giả trong mẫu: 149/300 có mọi tx misuse value 0 (`key_value0`) → cần báo riêng khi so sánh loss.
- AUC dương vs N5 thấp: ETH 0,368, BSC 0,587 (các nhóm âm khác 0,69–1,00). Engine coi contract recovery giống PCD
  vì cùng dấu hiệu (code xuất hiện sau khi nhận tiền, có ở chain khác). **Tạm thời:** contract N5 chưa có symexec
  (S_bytecode = 0,3 mặc định); chạy lại sau `prepare contracts` cho N5.
- Tái tạo: `python -m address_misuse.engine.evaluate` → `python -m address_misuse.freeze --version v2`.

## 2026-10-24 — Rà soát toàn bộ quy trình đánh giá (Module 3) và D3b

Tái tạo: `engine_eval.parquet` + cache `data/raw/<chain>/txlist/*.json.gz` (cờ `truncated`), `seed/eoa_misuse.parquet`.

Lỗi phương pháp đã sửa trong code (số Module 3 cũ không dùng được, chạy lại sau khi các job lấy dữ liệu xong):

- **Nguồn lịch sử trùng với nhãn trên ETH:** 800/800 mẫu dương ETH lấy lịch sử từ BigQuery (không input), 100% mẫu âm
  ETH từ Etherscan (có input). Sửa: `FeatureStore` ưu tiên txlist, BigQuery chỉ dùng khi chưa có; `prepare history`
  lấy txlist ETH cho 526 dương còn thiếu.
- **Lịch sử mẫu âm bị cắt trước `at`:** âm hạ tầng chỉ lấy 1.000 tx đầu. Mẫu có `at` sau tx thứ 1.000: N2 91%,
  N8 ETH 70% / BSC 89%, N3 ETH 34% / BSC 71%. Khi đó đặc trưng lịch sử tính trên đầu đời contract, có khi cách `at`
  nhiều năm. Sửa: mọi mẫu chỉ dùng 1.000 tx gần nhất trước `at` (`HISTORY_WINDOW`), và `prepare windows` lấy đúng
  cửa sổ đó cho 3.010 mẫu âm (ETH: Etherscan `sort=desc&endblock`; BSC: NodeReal lùi từng đoạn 1e5 block).
- **Ngữ cảnh mẫu dương dùng calldata giả `0xffffffff`** kể cả khi txlist có input thật (BSC). Bộ lọc IDM / T3 vì thế
  chỉ chạy trên mẫu âm. Sửa: dùng input thật khi có.
- **Học trọng số trên cả mẫu dính luật cứng:** mẫu KEY luôn có S_osint = 1 nên kéo w_osint lên. Sửa: chỉ học trên mẫu
  không dính luật cứng (giống chọn ngưỡng). Trên eval cũ: w_osint 0,524 → 0,387, τ 40,15 → 43,54.
- **OSINT theo khung lấy mẫu:** mọi dương có S_osint > 0, âm thì 0–97% tuỳ nhóm. Thêm tập `test_osint` (chỉ mẫu có
  trong danh sách OSINT: 480 dương, 455 âm). Trên eval cũ: FPR 0,8% → 2,6%, AUC 0,959 → 0,867. Đây là con số công bằng
  hơn cho phần không phải OSINT.

Phát hiện về dữ liệu tác giả:

- **KEY đếm cả tx value 0:** trong `eoa_misuse` của tác giả, 11.294/13.328 địa chỉ KEY trên BSC (85%) và 602/4.643 trên
  ETH (13%) không nhận đồng nào, chỉ có tx value 0. Trong Dataset v1: KEY BSC 140/163 và ETH 18/159 như vậy, tất cả có
  `at` trong 2025–2026, tức sau EIP-7702 (cùng hiện tượng sweeper gọi ví đã uỷ quyền như ở Arbitrum). Không ảnh hưởng
  phát hiện, vì KEY là luật cứng, nhưng quy mô KEY của tác giả trên BSC bị phóng đại. Dataset v2 cần cờ `key_value0`.
- **449 địa chỉ âm là dương của tác giả ở chain kia:** ví dụ contract thật trên ETH (N2, N8) bị gửi nhầm trên BSC
  (NCD), và ngược lại. Đúng định nghĩa (âm trên chính chain), đây là các mẫu âm khó, đáng nêu trong paper.

Hạn chế ghi nhận (không sửa):

- **Polygon D3b:** 966/2.269 txlist (43%) bị cắt ở 1.000 tx (`--max-records 1000`), nên số misuse Polygon là cận dưới.
- **L2 `xc`:** dùng code hiện tại ở mạng khác, không xét thời điểm.
- **`at` của N7 và PCD bị cắt** được chọn trong 1.000 / 10.000 tx đầu, nên lệch về đầu đời địa chỉ.
- **`endblock=99_999_999`** trong Etherscan: Polygon đã tới block 96,07M. Đã nâng lên 9.999.999.999.

## 2026-10-24 — Phân tích điểm yếu ADDR / PCD (chỉ train + val) và lệch đánh giá do symexec chỉ có ở dương

Tái tạo: đọc `data/interim/engine_eval.parquet` (split train/val), τ = 40,15 (`engine_metrics.json`).

- **Lệch S_bytecode theo nhãn (lỗi phương pháp, phải sửa trước khi báo số Module 3):** symexec chỉ có cho contract
  ứng viên của tác giả (dương). Contract âm (N1, N2, N7, N8) gần như 100% không có symexec → nhận điểm mặc định
  UNKNOWN_CODE = 0,3; dương PCD có kết quả thật (56% là T2, 43% điểm 0). Vì vậy "T2 không báo nhầm lần nào" là ảo.
  Có 727 contract (chủ yếu âm) chưa có symexec → `python -X utf8 -m address_misuse.engine.prepare contracts`, rồi chạy
  lại `engine.evaluate` + `engine.metrics` + `wallet.replay`.
- **OSINT lệch nhẹ theo khung lấy mẫu:** S_osint > 0 ở 100% dương và N1/N7 (đều lấy từ ứng viên GitHub/SE), N2 92%,
  N8 72%, N3 27%, N4 0%. Trọng số học được cho osint (0,52) một phần phản ánh khung lấy mẫu. Ablation "bỏ osint" giữ
  nguyên recall test (0,72) và FPR 0,9% → báo cả hai cấu hình trong paper.
- **ADDR (190 mẫu train/val): recall 0,5%.** ADDR trước 7702 là EOA bị sweeper chiếm; engine chỉ có tín hiệu lịch sử
  sweep (trọng số học được 0,073, tối đa +7 điểm R) và osint. R trung vị 7,1. SWEEP (cặp nạp → rút sạch trước `at`)
  có ở 36/190 ADDR (19%), 7/113 KEY, và 5/~2.600 âm (đều có tỉ lệ sweep ≤ 0,011).
  Luật cứng đề xuất `sweeper`: SWEEP với tỉ lệ n_sweep / n_plain_in ≥ 0,02 → ADDR train/val 0,5% → **17,9%**, âm
  train/val 0 báo nhầm. 81% ADDR còn lại không có dấu hiệu nào trước `at` (lịch sử chỉ có tx nạp) → giới hạn của
  cảnh báo phía ví khi không có danh sách ví bị chiếm.
- **PCD (249 mẫu train/val): recall 22,9%.** T2 (không có đường rút) ở 56%, PCD-XC ở 45%, cả hai 21%; 18% không có tín
  hiệu (symexec thấy đường rút). Với trọng số hiện tại T2 một mình cho R ≈ 25 < τ; T2 + PCD-XC ≈ 32 < τ. Quyết định
  tăng trọng số T2 phải chờ symexec của contract âm (ý trên) mới đo được báo nhầm thật.

## 2026-10-24 — D3b Arbitrum: địa chỉ misuse của tác giả trên ETH/BSC tiếp tục bị misuse trên Arbitrum (nhãn TẠM)

Tái tạo: `python -X utf8 -m address_misuse.l2_misuse state|txlist|rules --chain arb --focus author`
→ `data/interim/l2_misuse_arb.parquet` (cột `author_ca`, `xc`, `n_misuse_tx_nogas`, `cost_native_nogas`).

- Tập xét: key lộ + dương CA của tác giả (ETH/BSC) có tx đến thành công trên Arbitrum: 14.763 địa chỉ. Trạng thái code
  trên arb (sau khi chạy lại getCode lỗi): NCD 8.590 (5.898 có code ở mạng khác = Type 4), PCD 2.415, KEY 3.536,
  7702 222.
- Luật tác giả nguyên bản: **NCD 1.161 dương (13,5 ETH), PCD 155 dương (57,6 ETH)**; phần lớn loss nằm ở vài địa chỉ
  (lớn nhất 36,2 ETH). Năm misuse đầu: 2024 311, 2025 508, 2026 111.
- **Điều kiện gas của NCD không dùng được trên Arbitrum**: `gasUsed` gồm phần phí L1, chỉ 17,5% tx gọi hàm tới NCD có
  gasUsed ≤ 30.000 (trung vị 229k). Địa chỉ không có code thì gas thực thi L2 chỉ là phần nội tại, nên biến thể bỏ điều
  kiện gas hợp lý hơn: **NCD 5.857 dương (130,0 ETH)**, trong đó 4.969 là Type 4 (contract có ở mạng khác, gọi nhầm trên
  arb). Cần kiểm mẫu (D5) vì có thể lẫn địa chỉ từng có code (self-destruct) hoặc EOA 7702.
- → Paper: (1) misuse không dừng ở chain gốc — hàng nghìn địa chỉ tác giả đã báo trên ETH/BSC vẫn nhận tx lỗi trên L2;
  (2) ngưỡng gas của luật NCD phụ thuộc mô hình phí của chain, phải hiệu chỉnh theo chain (Arbitrum: trừ phần L1).

## 2026-10-24 — D3b Arbitrum: luật KEY của tác giả đếm cả lệnh sweep của kẻ tấn công là "misuse" (nhãn TẠM)

Tái tạo: `python -X utf8 -m address_misuse.l2_misuse txlist --chain arb --kinds KEY` (Etherscan V2, gói free có arb)
rồi `... rules --chain arb` → `data/interim/l2_misuse_arb.parquet`.

- 3.536 địa chỉ key lộ có tx đến thành công trên Arbitrum (cả 3.536 đều là dương KEY của tác giả trên ETH/BSC).
  Luật KEY tác giả (mọi tx đến từ địa chỉ khác, không lỗi) → **3.536/3.536 dương**, 16.896 tx, loss 12,82 ETH.
- Nhưng tách theo loại tx đến:
  | loại | tx | địa chỉ |
  |---|---|---|
  | value 0, gọi hàm | 11.241 | 3.488 |
  | value 0, tx thường | 700 | 97 |
  | có value | 4.955 | 271 |
  - Tx value 0 gọi hàm phần lớn là **lệnh sweep do kẻ tấn công gửi vào EOA đã gắn delegate 7702**:
    `loserSweepETH_…()` 5.650 tx, `sweep(address[])`, `forwardTokens(…)`, `withdrawEth(…)`. Hai sender
    `0x4791…5ff6` (5.067 tx) và `0xa619…8e4a` (1.674 tx).
  - **3.265/3.536 địa chỉ (92%) chỉ có tx value 0** → không phải người dùng gửi nhầm tiền. Misuse thật (có người
    gửi value tới ví key lộ): 271 địa chỉ, 12,65 ETH (5 địa chỉ đầu chiếm 52%, trung vị 0,0012 ETH).
- Thời điểm misuse đầu tiên: 2.983/3.536 vào 2025, 364 vào 2026 (sau khi Arbitrum hỗ trợ EIP-7702).
- → Paper: định nghĩa KEY của tác giả (đúng cho ETH/BSC trước 7702) **thổi phồng số nạn nhân** khi delegate 7702 xuất
  hiện; cần thêm điều kiện "value > 0 hoặc chuyển token tới ví" và loại tx do kẻ tấn công điều khiển (sender gọi
  hàm sweep). Kiểm tra lại cùng điểm này cho KEY trên ETH sau 2025-05 (D6).
- Ghi chú kỹ thuật: cộng `value` bằng int64 của pandas bị tràn (ra số âm) → luôn cộng bằng int Python (giống lỗi
  tràn phí gas đã ghi).

## 2026-10-23 — D6: misuse mới sau 2025-09 trên ETH rất hiếm trong mẫu ngẫu nhiên (lần 1)

Tái tạo: `python -X utf8 -m address_misuse.d6_new rules --per-type 400` → `data/interim/d6_new_positives_random400.parquet`
(bản sao kết quả lần 1, log `d6_rules_random400.log`).

- Ứng viên: ADDR 37.525 (EOA đang ủy quyền delegate thỏa điều kiện tác giả), NCD 18.038, PCD 2. Lấy ngẫu nhiên 400/luật.
- Dương mới (tx misuse từ 2025-09-01): **ADDR 1/400, NCD 3/400, PCD 1/2**. Ba NCD có 3 ca bị cắt ở 10k tx.
- 387/400 ứng viên ADDR dùng delegate MetaMask → điều kiện delegate của tác giả gần như chỉ chọn ví hợp lệ; luật đầy
  đủ (cặp sweep + số dư ≤ 1e14) loại hết. Lần 2 chạy toàn bộ 1.549 EOA không dùng delegate ví hợp lệ N6
  (`rules --only ADDR --no-wallets --per-type 2000`, log `d6_rules_addr_nowallet.log`).
- Lần 2 (toàn bộ 1.549 EOA, 120 delegate, không dùng delegate ví N6): **38 dương mới** (2,5%), 76 tx misuse mới,
  loss 0,082 ETH (nạn nhân ADDR thường chỉ còn ít tiền); 47 có misuse ở mọi thời điểm; 5 bị cắt ở 10k tx. Delegate
  nhiều dương nhất: `0x8332…77f0` (8), `0x2c6f…571d` (6). So với mẫu ngẫu nhiên có MetaMask: 1/400 (0,25%).
- → Paper: số ADDR mới phải báo theo cả hai cách (có / không ví N6); tỉ lệ dương trong ứng viên = thước đo độ chặt
  của bước lọc.

## 2026-10-23 — D3b Optimism: gần hết ví key lộ có tx đến trên OP đã bị gắn delegate EIP-7702 (nhãn TẠM)

Tái tạo: `python -X utf8 -m address_misuse.l2_fetch fetch --chain op --max-gb 120` rồi
`python -X utf8 -m address_misuse.l2_misuse state --chain op` → `data/raw/crosschain/code_op.jsonl`.

- 3.405 địa chỉ suy ra từ key lộ có tx đến thành công trên OP; **3.294 (96,7%) hiện đang ủy quyền EIP-7702** cho
  30 delegate. Ba delegate đầu: `0x3aa3…f0c7` (1.658 ví), `0x1232…7fac` (595), `0x8a67…408a` (522).
- Chỉ 542 ví dùng delegate đã có trong bảng D6 (ETH); phần lớn là delegate riêng của OP → cần symexec trên code OP
  trước khi kết luận là sweeper (dự đoán: kẻ tấn công gắn sweeper 7702 trên mọi chain nạn nhân có thể nhận tiền).
- So với ETH/BSC (paper gốc), đây là dạng misuse KEY trên L2 mà tác giả không đo. Số loss chưa có, chờ txlist + luật.
- Symexec (`python -X utf8 -m address_misuse.l2_misuse delegates --chain op` → `data/interim/l2_delegates_op.parquet`):
  op có 356 delegate / 38.131 EOA (trong tập địa chỉ đáng xét); 177 trùng bytecode delegate ETH (dùng lại kết quả D6),
  172 chạy mới, có kết quả 351. **Cả 30 delegate của ví key lộ đều thỏa điều kiện ADDR của tác giả (3.294/3.294 ví)**;
  22 delegate (859 ví) có `transfer_all_eth` (sweeper rõ), 4 delegate (2.430 ví, gồm `0x3aa3…f0c7` 1.658 ví) chỉ có
  `transfer_msg_value`. Không ví key lộ nào dùng delegate ví hợp lệ N6 (MetaMask có 12.014 EOA trên op, 0 key lộ).
- → Paper: trên L2, kẻ tấn công nắm key lộ gắn sẵn sweeper 7702 để tự rút tiền mới đến; lớp phòng thủ phía ví nên
  cảnh báo khi gửi tới EOA có delegate thuộc nhóm này (luật cứng `malicious_delegate` mở rộng sang L2).

## 2026-10-23 — N5: contract "recovery" tại địa chỉ PCD — tên contract không đủ làm bằng chứng lành tính

Tái tạo: `python -X utf8 -m address_misuse.negatives n5` → `data/interim/n5_recovery_contracts.parquet`.

- 1.162 contract PCD (RQ3 của tác giả), 697 có tên đã verify (Blockscout / Sourcify). Tên khớp từ khoá recovery
  (recover/rescue/refund/reclaim/retriev/return): 18.
- Trong 18 đó có contract của **kẻ tấn công** cũng đặt tên kiểu cứu hộ: `0xc78a…6ef1` "Retriever" (ETH) và
  `0x3914…680d` "RescueFacet" (BSC), đều bị tác giả gán tay là độc (manual = 1). Contract có deployer là địa chỉ key lộ:
  4, tool tác giả gắn độc cả 4 (tỉ lệ chung 40%).
- Tiêu chí cuối: giữ khi tác giả gán tay lành tính, hoặc tên recovery VÀ không bị gán tay độc VÀ deployer không phải
  key lộ. Giữ **118** (ETH 58, BSC 60): 104 do tác giả gán tay lành tính, 15 do tên (14 chỉ dựa vào tên → `needs_review`,
  đưa vào D5). 24 contract được giữ vẫn bị tool tự động của tác giả cho là độc (11 trong số gán tay lành tính, 13 trong
  số chỉ dựa vào tên) → ví dụ báo nhầm của luật tự động PCD.
- → Paper: N5 là nhóm âm khó nhất (cùng hành vi "rút hết token" với sweeper); không thể dựa vào tên contract; cần
  người gán (D5) hoặc nguồn gốc deployer.

## 2026-10-23 — D6: điều kiện delegate của luật ADDR (tác giả) gắn cờ cả ví MetaMask hợp lệ

Tái tạo: `python -X utf8 -m address_misuse.d6_new delegates --workers 5` → `data/interim/d6_delegates.parquet`.

- Symexec cho 484 delegate EIP-7702 đang được EOA trên ETH ủy quyền (d6_state): có kết quả 482 (2 delegate không có
  code). Điều kiện delegate trong luật ADDR của tác giả (`transfer_all_eth` HOẶC `transfer_msg_value` hợp lệ) đúng ở
  **318 delegate, 52.004 EOA**.
- Trong đó **`EIP7702StatelessDeleGator` của MetaMask** (`0x63c0…e32b`, 36.041 EOA = 69% số EOA "đủ điều kiện") có
  `transfer_msg_value` → bị coi như delegate độc. Các ví hợp lệ khác (Coinbase, Uniswap Calibur, Ambire, eth-infinitism)
  không bị. Delegate xếp sau: `0x0727…6786` (6.687 EOA), `0x88cf…8d46` (3.955 EOA) cũng chỉ có `transfer_msg_value`.
- → Chuyển tiếp `msg.value` là hành vi bình thường của hàm `execute` trong mọi smart wallet, nên tiêu chí này rất yếu;
  phần thật sự phân biệt là điều kiện cặp sweep + số dư ≤ 1e14 của luật ADDR. Paper: báo kết quả ADDR mới theo hai cách
  (đúng luật tác giả / bỏ delegate ví hợp lệ N6), và tách theo delegate. Engine (`wallet/online.py`) đã loại ví N6
  khỏi danh sách delegate độc.

## 2026-10-23 — Module 4 phát lại lịch sử: ví lẽ ra cảnh báo bao nhiêu (nhãn TẠM)

Tái tạo: `python -X utf8 -m address_misuse.wallet.replay` → `data/interim/wallet_replay.parquet`.

- **Cập nhật 2026-10-24:** đã tải txlist Etherscan cho 234 dương ETH test còn thiếu. ETH test: 2.357 tx misuse (182 địa
  chỉ), cảnh báo 93,8% tx / 97,3% giá trị (47,2 / 48,5 ETH); bỏ địa chỉ lớn nhất (82% giá trị) còn 85,3%. Theo loại:
  KEY 100%, NCD 93,5% tx, PCD 96,5% tx, **ADDR 0%** (65 tx). Báo nhầm ETH: N2 0,60%, N3 0%, N8 0,33%. (Bản trước in
  % giá trị âm do tràn int64 khi cộng wei — đã sửa trong `replay.summary`.)
- Cách làm: dương tập test có txlist kèm input trong cache (BSC: đủ 225 địa chỉ; ETH: chỉ 21, 234 địa chỉ chưa có
  txlist vì ETH dùng BigQuery không có input). Chạy luật tác giả lấy đúng các tx misuse từ 2023-10-05, chấm từng tx tại
  thời điểm của nó (chỉ dùng thông tin trước tx), trọng số + ngưỡng Module 3 (τ = 40,15). Cảnh báo = luật cứng hoặc
  R ≥ τ. Giá trị = value + phí gas.
- Kết quả tập test:

| | tx misuse | cảnh báo (% tx) | cảnh báo (% giá trị) | báo nhầm N8 / N2 / N3 |
|---|---:|---:|---:|---|
| ETH (13 địa chỉ) | 954 | 96,6% | 99,4% (0,84 / 0,85 ETH) | 0,33% / 0,60% / 0% |
| BSC (190 địa chỉ) | 4.273 | 67,2% | **0,4%** (0,39 / 90,7 BNB) | 0% / 0% / 0% |

- Theo loại (BSC): KEY 100% tx, NCD 71% tx (85,6% giá trị), **PCD 1,3%**, **ADDR 1,4%**. Tỉ lệ địa chỉ có ít nhất 1
  tx được cảnh báo: KEY 100%, NCD 91%, PCD 17%, ADDR 2%.
- Giá trị tập trung: một contract PCD trên BSC (`0x2401…6fdf`, R = 23,8, chỉ có tín hiệu PCD-XC) chiếm 80% giá trị
  BSC và bị bỏ sót hoàn toàn; bỏ nó ra vẫn chỉ cảnh báo 2,2% giá trị. → % tx và % tiền kể hai câu chuyện khác nhau:
  engine bắt tốt các tx nhỏ, lặp lại (KEY, NCD) nhưng bỏ sót các tx lớn đi vào PCD. Điểm yếu chính là PCD (trùng với
  Module 3: recall PCD 0,37) và ADDR (chỉ bắt được khi có delegate 7702 độc).
- Ngoài thời gian (≥ 2025-09-01): BSC 287 tx, cảnh báo 100% (81,5% do luật cứng); ETH 45 tx, 48,9% (PCD 0/23).
- Hạn chế: mẫu ETH nhỏ (13 địa chỉ, 59% giá trị từ 1 địa chỉ); danh sách key lộ / OSINT không có mốc thời gian nên
  coi như đã biết trước; nhãn dương là nhãn luật tác giả (chưa có nhãn vàng D5).

## 2026-10-23 — D8: Dataset v1 đóng băng, QA đạt

Tái tạo: `python -X utf8 -m address_misuse.freeze` (QA: `… freeze qa`). Mô tả: `data/final/README.md`, `docs/DATASHEET.md`.

- 6.429 mẫu, 4.477 địa chỉ; dương 1.600, âm 4.829. Test: ETH 255/761, BSC 225/768 (dương/âm).
- QA tự động đạt, 0 cảnh báo: khoá, dạng địa chỉ + EIP-55, nhãn khớp nhóm, không địa chỉ hai nhãn, không âm nào là
  dương của tác giả hay địa chỉ suy ra từ key lộ, không địa chỉ ở hai tập, split khớp `at`, loss không âm, không có
  chuỗi giống private key.
- 681 mẫu âm `excluded` (53 địa chỉ, chủ yếu USDT trên BSC/ETH, USDC, PancakeSwap Router, WETH): contract phổ biến
  xuất hiện ở nhiều tập nên chỉ giữ ở tập sớm nhất.
- Kiểm tra genesis xong (4.256/4.256 ví KEY ETH): chỉ 1 ví có phân bổ genesis (`0xf46b…`), không thuộc mẫu v1.

## 2026-10-23 — Module 4 PoC: kiểm tra phía ví, độ trễ

Tái tạo: `python -X utf8 -m address_misuse.wallet.bench --n 300` (`data/interim/wallet_bench.json`);
proxy: `python -X utf8 -m address_misuse.wallet.proxy --port 8545`.

- `wallet/online.py`: bảng tính sẵn nạp vào RAM **0,3–0,6 s, +107 MB** (OSINT 7,6M địa chỉ lưu 8 byte đầu, sắp xếp).
  Online chỉ gọi getCode 8 mạng song song (keep-alive), cache theo địa chỉ, mạng trả muộn điền vào cache sau.
- 300 địa chỉ tập test, RPC công khai publicnode, đo từ Việt Nam:

| chờ tối đa | lạnh p50 / p95 / p99 | ấm p50 / p99 | đủ 8 mạng |
|---|---|---|---|
| 300 ms | 156 / 290 / 311 ms | 0,03 / 0,07 ms | 97% |
| 150 ms | 152 / 165 / 173 ms | 0,04 / 0,13 ms | 45% |

- Phần tính toán < 0,1 ms; lần lạnh gần như toàn bộ là **một vòng mạng tới RPC công khai** (đo riêng: 131–152 ms mỗi
  mạng khi đã keep-alive, 555–670 ms lần bắt tay TLS đầu). Mục tiêu < 150 ms đạt khi trúng cache, chưa đạt khi lạnh
  với RPC công khai ở VN. Hướng xử lý cho paper: kiểm tra ngay khi người dùng nhập địa chỉ (trước khi bấm gửi),
  RPC gần hơn/riêng, hoặc chấp nhận thiếu vài mạng (timeout 150 ms: 45% đủ 8 mạng, thiếu TB 1 mạng).
- `wallet/proxy.py`: chặn `eth_sendTransaction`/`eth_sendRawTransaction` (giải mã tx thô legacy/1/2/3/4, cả
  authorizationList của tx 7702), trả lỗi 4001 kèm lý do. Thử thật: tx 1 ETH tới `0x6273…ef57` (Truffle, lộ key) bị
  chặn sau 149 ms; `eth_blockNumber` chuyển tiếp bình thường. Hạn chế: MetaMask ký trước khi gửi, nên proxy chỉ chặn
  được việc phát tx; cảnh báo trước khi ký cần Snap (GOALS, chưa chốt).

## 2026-10-23 — Module 3 chạy thử (nhãn TẠM: luật tác giả + N1–N8)

Tái tạo: `python -m address_misuse.engine.evaluate` → `python -m address_misuse.engine.metrics --boot 300`
(`data/interim/engine_metrics.json`, `engine_roc.csv`). Số liệu sẽ đổi khi có nhãn vàng D5 và dương mới D6.

- `w` học trên train (logistic không âm): bytecode 0,25, cross 0,15, osint 0,52, history 0,07. Ngưỡng trên val:
  τ_warn = τ_block = 40,15 (val chỉ có 75 mẫu N8 nên "FPR ≤ 1%" nghĩa là 0 cảnh báo sai; cần thêm N8 cho val).
- **Test** (480 dương / 1.529 âm): AUC 0,960; mức warn P 0,966 [0,95–0,99], R 0,721 [0,69–0,76], F1 0,826,
  FPR 0,008. Luật cứng một mình: R 0,358, P 1,0. Riêng R trên mẫu không dính luật cứng: P 0,935, R 0,565.
  Baseline `getCode == 0x ∧ calldata`: P 0,942, R 0,269, F1 0,418.
- Recall theo loại: KEY 1,00, NCD 0,96, ADDR 0,54, **PCD 0,37** (điểm yếu). FPR theo nhóm âm: **N7 0,158** (contract
  đa chain bị S_cross nghi), N1 0,064, còn lại ≤ 0,008.
- **Ngoài thời gian** (147 / 637, chưa có dương D6): F1 0,954, nhưng 121/136 TP là do luật cứng (KEY/ADDR).
- Ablation (F1 / AUC test): bỏ bytecode 0,712 / 0,945; bỏ osint 0,824 / 0,896; bỏ cross 0,826 / 0,940; bỏ history
  0,826 / 0,959; chỉ cross 0,707 / 0,658. Ở ngưỡng đã chọn, F1 gần như chỉ phụ thuộc S_bytecode + luật cứng; S_osint
  chủ yếu tăng AUC. Cẩn trọng: dương được chọn từ tập ứng viên OSINT của tác giả, nên trọng số osint cao có thể là
  do cách lấy mẫu (cần kiểm tra bằng nhãn vàng và âm có OSINT).

## 2026-10-23 — Tái lập loss KEY bằng BigQuery: phân bổ genesis bị tính là thiệt hại; tràn int64 phí gas

Người gán A tái lập loss KEY (ETH) từ `data/raw/eth/bq_txs.parquet` (BigQuery, 22,4M tx), lệch 2/4.256 địa chỉ. Kiểm tra lại:

- **Phân bổ genesis bị tác giả tính là loss.** `0xf46b6b9c…aae782f6`: tác giả 24,19 ETH, BigQuery 3,29 ETH (tx vào, status 1).
  Etherscan `txlist` trả về bản ghi block 0, `from = GENESIS`, 21,0 ETH (phân bổ presale 2015), và BigQuery
  `transactions` không có. Luật KEY của tác giả (`txs_analyzer.analyze_EOAMisuse_for_KEY_txs`) cộng mọi tx vào có
  `isError == 0` và `from != addr`, nên tính cả bản ghi này. Chủ ví tự chuyển 20,99895 ETH đi ở block 210675,
  vậy đây không phải tiền nạp vào ví lộ key.
  **Đã đếm** (`python -X utf8 -m address_misuse.key_genesis`, `eth_getBalance(addr, block 0)` qua NodeReal cho cả
  4.256 ví KEY ETH): **chỉ 1/4.256 ví** có phân bổ genesis, 21,0 ETH trên tổng value KEY ETH 103.628 ETH (0,02%).
  → Lỗi có thật trong code tác giả nhưng ảnh hưởng tổng số không đáng kể; nêu trong paper như một lỗi biên.
  Tái tạo: `Etherscan('eth').call('account','txlist',address=…,startblock=0,endblock=700000,sort='asc')`.
- **Tràn int64 khi tính phí:** `gas_price × receipt_gas_used` (cả hai int64 trong parquet) vượt 2^63 ở **41 tx**
  (33 địa chỉ đích): 25 tx thành số âm, **16 tx quay vòng thành số dương sai** (không lộ ra là âm). Đích là ví KEY: 2 tx /
  2 ví (`0x62730609…8bef57` phí thật 14,99 ETH, `0x8ad2f6fc…2371e9` 10,09 ETH); đích là CA misuse: 4 tx. Phí lớn là
  thật (gas price tới ~1,2M gwei), không phải dữ liệu rác. Sửa: nhân bằng số nguyên Python/Decimal cho mọi dòng, không
  vá riêng dòng âm.
- NCD/PCD: `bq_txs` không có cột `input` nên không chạy được luật tác giả; dùng tập con Etherscan
  (`reproduce_rules.py`, đã có cache 2.277 txlist ETH, 2.297 BSC).

## 2026-10-23 — D8 chốt chia tập (A + B); quét block 2020–2022; D6 BigQuery bước 1

**Quyết định D8** (người dùng duyệt, PLAN_V2 D8): mốc cũ cho test = 0 dương (dữ liệu tác giả dừng 07/2025).
- A — đánh giá chính: phân vị 70/85% thời điểm tx đầu tiên của 34.480 dương CA (theo năm: 2020 474, 2021 11.759,
  2022 11.035, 2023 7.351, 2024 3.350, 2025 495) → train < 2023-02-10 ≤ val < 2023-10-05 ≤ test, theo `at` của mẫu.
  Địa chỉ chỉ ở tập của mẫu sớm nhất (`engine/evaluate.assign_split`).
- B — test ngoài thời gian (≥ 2025-09-01): dương mới từ D6 + âm cùng giai đoạn.

**Âm cho giai đoạn train** (tái tạo: `negatives scan --period early` → `negatives from-scan` → `engine.prepare history`):
600 block ngẫu nhiên/chain 2020-01 → 2022-12 qua RPC NodeReal (ETH ~100k tx, BSC 96.049 tx; BSC bắt đầu từ
block 1 = 08/2020). Thêm N8 1.169, N2 800, N3 96 (văn bản tới EOA hiếm trước làn sóng inscription 2023).
Đợt "recent" không đổi (cùng seed).

**Kết quả theo tập** (trọng số 0,25, chưa học; AUC dương vs mọi âm cùng chain; `data/interim/engine_eval.log`):

| chain | train (dương/âm, AUC) | val | test | ngoài thời gian (dương/âm) |
|---|---|---|---|---|
| ETH | 414 / 1.200, 0,827 | 96 / 157, 0,893 | 255 / 761, 0,897 | 60 / 423 |
| BSC | 438 / 1.137, 0,818 | 70 / 113, 0,859 | 225 / 768, 0,975 | 87 / 529 |

Bỏ do trùng địa chỉ giữa tập: ETH 376, BSC 305 mẫu âm (đích phổ biến như USDT xuất hiện ở nhiều giai đoạn).
Không có `at` (không lịch sử): ETH 35 dương / 6 âm, BSC 67 / 6. AUC train thấp hơn test: train có nhiều âm
2020–2022 khó hơn và dương cũ hơn; cần xem lại sau khi học `w` (chưa kết luận).

**D6 bước 1 — BigQuery quota của nhóm** (`bq_fetch new-fetch`, job `eabe747a…`, **tính phí 118,7 GB**):
- Lần đầu lấy từng tx (ước lượng 196,7 GB) bị BigQuery từ chối `responseTooLarge` (> 10 GB kết quả), **0 GB tính
  phí**. Đổi sang gom một dòng thống kê mỗi địa chỉ (tx vào + tx ra), rẻ hơn.
- 4.989.536 ứng viên ETH chưa gắn cờ → 1.258.647 có tx từ 2025-09-01: 747.340 có tx vào (trung vị 3 tx), 360.356
  có tx gọi hàm vào, 1.067.624 có tx gửi đi, 61.502 gửi tx type 4 (EIP-7702). **141.348 nhận tx gọi hàm mà không
  tự gửi tx** (ứng viên NCD/PCD, cần getCode + creation rồi chạy `rules.py`).
- Địa chỉ lộ key (`candidate_pk_addresses`, 17.971) gần như không nằm trong `candidate_addresses` (46 ETH) nên
  chưa có trong truy vấn này → KEY mới cần truy vấn riêng (nhỏ).

## 2026-10-23 — Bước 2: tập âm N2/N3/N4/N8, lịch sử BSC, rà soát toàn bộ quy trình engine

**Dữ liệu mới** (tái tạo: `python -m address_misuse.engine.prepare sample` → `negatives scan --blocks 400` →
`negatives from-scan` → `negatives n4` → `engine.prepare history` → `negatives n4-verify` → `engine.evaluate`):
- Mẫu đánh giá cố định `engine_eval_sample.parquet` (seed 0): mỗi chain NCD 300, PCD 200, KEY 150, ADDR 150.
- Lịch sử BSC qua NodeReal `nr_getTransactionByAddress` cho 800 dương + N1 + N7 BSC (0 lỗi, không địa chỉ rỗng),
  và cho đích của N2/N3/N4/N8 trên cả hai chain (1.000 tx đầu). Đổi sang định dạng txlist Etherscan.
- Quét 400 block ngẫu nhiên mỗi chain (2023-01 → 2026-10; ETH 80.022 tx, BSC 44.088 tx):
  N8 = 1 tx ngẫu nhiên/block (400/chain); N2 = gọi contract bằng 30 selector hay gặp nhất trong tx tới địa chỉ NCD
  (approve, transfer, setApprovalForAll, transferFrom, mint, withdraw…; 400/chain); N3 = input là văn bản gửi tới
  EOA (ETH 400, BSC 240; 88% là inscription tự gửi `data:,{"p":"erc-20",…}`).
- N4: người gửi coin tới 6 ví nóng sàn (Binance 14/15/16, Coinbase 10, Binance BSC 6/7). Etherscan chặn đọc nhãn
  (HTTP 403), Blockscout không có nhãn → kiểm chứng bằng **hành vi**: ≥ 90% tx gửi đi là về hub và mang ≥ 90% coin
  đã nhận. Chỉ **83/400** người gửi đạt (ETH 37, BSC 46); phần lớn người gửi tới ví sàn là người dùng thường. Hub
  Binance 15/16 và Binance BSC 7 gần như không có địa chỉ nạp đạt → nhãn hub có thể sai hoặc không phải đích sweep.

**Kiểm tra nguồn dữ liệu tương đương:**
- BigQuery vs Etherscan, 579 địa chỉ pilot, cùng mốc block: các đặc trưng lịch sử trùng 98,8–100%, `n_sweep` 246 = 246.
- NodeReal vs Etherscan, 29 địa chỉ N1 ETH: `n_tx`, `n_in`, `n_in_call`, `call_senders`, `n_out` trùng 100%.
  Trước Byzantium (block < 4.370.000) NodeReal trả status 0 cho mọi tx; đã đổi sang quy ước của BigQuery
  (lỗi ⇔ dùng hết gas). Còn lệch 3 tx lỗi (Etherscan dùng trace).

**Lỗi tìm thấy khi rà soát (đã sửa):**
1. *BigQuery chỉ chứa tx của 35.664 địa chỉ đã truy vấn.* Địa chỉ khác (router, contract hạ tầng) có trong BigQuery
   một phần (chỉ tx với địa chỉ misuse) và bị lấy làm lịch sử: 30/200 N1 ETH, 14/18 N7. Nay chỉ dùng BigQuery cho
   đúng danh sách `bq_fetch.targets()`, còn lại dùng txlist.
2. *Thiếu bộ lọc IDM* (tin nhắn văn bản) trong S_bytecode: mọi tx gửi chữ tới EOA bị tính T1 = 1. Đã thêm.
3. *EIP-7702 không theo thời gian:* EOA đang ủy quyền hôm nay vẫn bị coi là 7702 (kể cả luật cứng delegate độc)
   khi xét thời điểm trước khi 7702 kích hoạt (ETH 2025-05-07, BSC 2025-03-20). Đã sửa (`EIP7702_ACTIVATION_TS`).
4. *Chọn `at` = tx đầu tiên sai cho PCD:* 87% PCD ETH chưa có code ở tx đầu tiên (contract được tạo sau), nên
   chấm như NCD-XC (S_cross 0,33 → 0,81) — đây là lý do R_at > R của PCD ở lần chấm trước. `engine/evaluate.py`
   chọn ngẫu nhiên **một tx misuse**: NCD = tx gọi hàm, PCD = tx sau khi contract được tạo; dương và âm cùng quy trình.
5. `history_source` khoá theo địa chỉ (lẫn ETH/BSC): nay khoá theo (chain, address).

**Hạn chế còn lại (cần nêu trong paper hoặc quyết định):**
- *KEY ≡ luật cứng:* 100% EOA KEY nằm trong tập lộ key (`candidate_pk_addresses`), ADDR chỉ 0,5–0,8%. Nhóm KEY chỉ
  đo luật cứng, không chứng minh R. Thời điểm lộ key không biết, nên luật này không theo thời gian.
- *Danh sách đen delegate dựng từ tập dương* → 17–22% ADDR dính luật cứng `malicious_delegate`. Phải dựng lại
  chỉ từ train.
- *OSINT:* mọi dương và N1 đều thuộc `candidate_addresses` (S_osint = 0,28), còn đích N2/N8 chỉ 0,10–0,26 (địa chỉ
  phổ biến như USDT cũng có trong code công khai). S_osint vì thế phân biệt một phần do **cách lấy mẫu**: AUC giảm
  0,01–0,17 khi bỏ S_osint. Cần tính OSINT cùng một quy trình cho mọi mẫu (D7).
- *BigQuery không có input:* ở mức địa chỉ chỉ biết "có calldata" (gas > 21.000), không chạy được IDM/T3 trong
  lịch sử; N3 ETH vẫn có S_history 0,22 do đếm tx văn bản là "gọi hàm".
- *Lịch sử hạ tầng bị cắt 1.000 tx đầu* (N6/N7, đích N2/N3/N8); NodeReal trả rỗng với vài contract rất lớn trên BSC.
- *Mốc chia D8 không dùng được:* tx đầu tiên muộn nhất của dương CA là 2025-07-22. Với mốc trong PLAN_V2
  (val từ lúc 7702 kích hoạt, test từ 2025-09-01): train 34.414, val 66, **test 0** địa chỉ có thời gian.
  Cần chọn lại mốc (chờ người dùng).

**Kết quả mô tả** (trọng số 0,25, chưa học, chưa chọn ngưỡng; 4.364 mẫu, `data/interim/engine_eval.log`):
trung vị R — NCD 57,1 (cả hai chain), PCD 31–32, KEY 25–37,5, ADDR 7,1; N1 7,1; N2 14,7–15,0; N3 0; N4 0;
N7 15,2–15,4; N8 1,0 (BSC) / 14,7 (ETH). AUC dương vs từng nhóm âm cùng chain: 0,75–1,00 (ETH: N1 0,89, N2 0,80,
N3 0,90, N4 1,00, N6 0,83, N7 0,75, N8 0,85; BSC: N1 0,89, N2 0,87, N3 1,00, N4 1,00, N7 0,79, N8 0,93).
ADDR gần như không tách được khỏi N1 bằng R (trung vị bằng nhau): thông tin chỉ nằm ở luật cứng và lịch sử.

## 2026-10-22 — Engine risk score chạy thử; delegate EIP-7702 của sweeper đã đổi sau snapshot tác giả

**Chấm thử** `address_misuse.engine` (at = hôm nay, w = 0,25 mỗi thành phần) trên 1.181 mẫu: NCD/PCD/KEY/ADDR mỗi chain + N1, N6, N7. Offline 1,7 ms/mẫu; getCode 8 mạng cho 662 địa chỉ ngoài ma trận mất 3 s. Trung vị R:

| Nhóm | ETH | BSC |
|---|---|---|
| +NCD | 57,1 | 44,6 |
| +PCD | 28,5 | 32,1 |
| +KEY (luật cứng lộ key 100%) | 32,5 | 32,5 |
| +ADDR | 16,9 | 14,6 |
| −N1 | 19,6 | 19,6 |
| −N6 / −N7 | 7,5 / 15,0 | – / 14,6 |

Chưa phải kết quả đánh giá (trọng số chưa hiệu chỉnh, chưa theo thời gian), chỉ để kiểm tra code. Lộ ra các vấn đề cần sửa trước khi đánh giá (RISK_SCORE.md §6).

**Delegate 7702 đã đổi:** getCode hôm nay cho 260 EOA trong `eip7702_delegations` của tác giả (mẫu ở trên):

| Chain | Nhóm | n | Vẫn đang 7702 | Delegate trùng bản tác giả ghi | Delegate hiện tại có trong tập delegate tác giả |
|---|---|---|---|---|---|
| BSC | ADDR | 74 | 100% | 0% | 0% |
| BSC | KEY | 56 | 100% | 26,8% | 42,9% |
| ETH | ADDR | 69 | 98,6% | 0% | 0% |
| ETH | KEY | 61 | 100% | 0% | 8,2% |

- Các EOA vẫn bị ủy quyền nhưng đã chuyển sang delegate khác (13 delegate hiện tại; nhiều nhất `0x0727ca41…` 51 EOA, `0xa19160b1…` 39).
- Hệ quả: danh sách đen delegate tĩnh lỗi thời rất nhanh. Phía ví cần phân tích delegate lạ (symexec / hành vi), không chỉ tra danh sách. Khi đánh giá theo thời gian phải dùng delegate tại thời điểm `at`, không phải delegate hôm nay.

**Sau khi sửa 4 vấn đề (2026-10-23)**, chấm lại cùng 1.181 mẫu (at = hôm nay, 4,0 ms/mẫu): trung vị R của N1 ETH giảm từ 19,6 xuống **7,1** (đã có lịch sử, S_bytecode 0,46 → 0,12); S_cross của N7 về 0; ADDR tăng lên 19,6–21,9 (delegate mới có symexec, S_bytecode 0,3 → 0,5). ADDR BSC (19,6) vẫn trùng N1 BSC (19,6): BSC chưa có lịch sử tx nên S_history = 0 cho mọi mẫu BSC. Chế độ theo thời gian (at = tx đầu tiên tới địa chỉ): NCD ETH giảm từ 57,1 xuống 44,6 vì không còn dùng lịch sử sau thời điểm xét.

**Hash bytecode quá chặt cho N7:** Uniswap V2 Router `0x7a25…488d` có code trên BSC nhưng hash khác ETH (immutable như địa chỉ WETH khác nhau), nên bị tính PCD-XC (R = 22). Cần so tập selector thay vì hash.

## 2026-10-22 — D1 ETH: `bq_txs.parquet` từ BigQuery đầy đủ, khớp Etherscan

File `data/raw/eth/bq_txs.parquet` (bạn chạy `bq_fetch fetch`, 1,49 GB, không có `input`/`hash`). Kiểm tra trên máy này:

- 22.397.803 tx, không trùng khoá `(block_number, transaction_index)`; từ 2015-08-07 đến **2026-10-20** (block 26.234.257).
- Phủ **35.664/35.664** địa chỉ ETH mục tiêu (CA + EOA của tác giả), mọi địa chỉ đều có tx.
- Số tx ≥ `n_tx` của tác giả ở 100% địa chỉ trừ 4, mỗi địa chỉ thiếu đúng 1: đó là bản ghi **GENESIS** (phân bổ ở block 0) mà Etherscan liệt kê như một tx, BigQuery thì không.
- Đối chiếu tập tx với txlist Etherscan của 579 địa chỉ pilot (bỏ 1 bị cắt ở 100k, chỉ xét block ≤ 26.234.257): **578/579 khớp từng tx**; địa chỉ còn lại chỉ khác ở bản ghi GENESIS. Không có tx nào BigQuery có mà Etherscan không có.
- Kết luận: có thể dùng `bq_txs` thay Etherscan cho mọi đặc trưng không cần `input` (S_history, N2–N4, chia thời gian D8) trên toàn bộ ETH.

## 2026-10-21 — Pilot rule mở rộng: EOA ADDR và CA lớn (n_tx > 5.000) cũng khớp tác giả 100%

`python -m address_misuse.reproduce_rules --chain eth --n-ncd 350 --n-pcd 100 --n-key 50 --n-addr 50 --n-big 30` (seed 0, 458 s, kết quả `data/interim/rules_repro_eth.parquet`, log `data/interim/reproduce_rules_2026-10-21.log`). 580 địa chỉ; 500 mẫu pilot cũ được chọn lại y hệt.

| Tầng | Subtype | n | Snapshot khớp chính xác | Loss (ETH) tác giả = mình | Hiện tại khớp chính xác | Lệch loss hiện tại |
|---|---|---|---|---|---|---|
| pilot | NCD | 350 | 100% | 309,460 | 94,3% | +0,00% |
| pilot | PCD | 100 | 100% | 230,343 | 100% | +0,00% |
| pilot | KEY | 50 | 100% | 39,955 | 50,0% | +0,23% |
| addr | ADDR | 50 | 100% | 1,680 | 100% | +0,00% |
| big | NCD | 27 | 100% | 21,384 | 92,6% | +0,05% |
| big | PCD | 3 | 100% | 0,027 | 100% | +0,00% |
| **Tổng** | | **580** | **100%** | **602,850** | | **+0,02%** |

- **Snapshot** = chỉ dùng n_tx đầu tiên như lúc tác giả kéo dữ liệu; **hiện tại** = toàn bộ tx đến hôm nay (KEY lệch nhiều nhất vì sweeper vẫn tiếp tục hoạt động).
- 1 địa chỉ bị cắt ở 100k tx; 1 địa chỉ có n_tx lúc kéo < n_tx của tác giả.
- **Giới hạn của ADDR:** rule ADDR cần "delegate độc", mình coi là thoả vì mọi EOA ADDR đều có trong `eip7702_delegations` của tác giả; số dư snapshot lấy từ dữ liệu tác giả. Nên 100% ở đây xác nhận phần đếm tx/tính loss, **không** xác nhận độc lập việc nhận diện delegate độc (FINDINGS_LOG 2026-10-19: `flag` = symexec).
- Kết luận: rule của Shao et al. tái lập đầy đủ trên ETH cho cả 4 subtype và cả nhóm n_tx lớn.

## 2026-10-20 — D3 timing BSC qua NodeReal (`crosschain_matrix timing`, `build`)

Nguồn: NodeReal MegaNode free, `nr_getTransactionByAddress` (`category=[external]`, `order=asc`, `maxCount=1`), 16.562 địa chỉ BSC trong ~5 phút, 0 lỗi. (Moralis đòi gói $149+, BigQuery không có dataset BSC, Blockscout/Ankr không dùng được.)

| Chain bị misuse | NCD/PCD-XC có timing | deployed_before | deployed_after | unknown |
|---|---|---|---|---|
| BSC | 16.562 | 16.366 (98,8%) | 196 | 753 |
| ETH | 17.918 | 17.635 (98,4%) | 283 | 1.355 |

Khoảng cách (tx đầu − deploy ở chain khác), BSC: trung vị 32 ngày, p10 0, p90 443. Kết luận như ETH: gần như mọi ca NCD/PCD-XC đã có contract ở chain khác trước khi địa chỉ nhận tx đầu tiên, tức cảnh báo cross-chain có thể đã bắn được từ đầu. Lưu ý: tx đầu tiên chỉ tính tx `external` (không tính tx nội bộ); ngày deploy dùng trạng thái hiện tại.

## 2026-10-19 — `flag` delegate 7702 của tác giả là kết quả symexec, không phải nhãn độc; tập âm N1, N6

**`eip7702_delegate_stats.flag` trùng khớp hoàn toàn với symexec** (`symexec_results`, kind = eip7702_delegate):

| flag | Ý nghĩa | Số delegate |
|---|---|---|
| 1 | có ít nhất một đường `transfer_*` | 89/89 |
| 0 | không có đường chuyển tiền | 2 |
| -1 | chưa phân tích | 10 |

- `symexec_results` (kind = eip7702_delegate) là **mọi delegate đã phân tích**, không phải tập delegate độc. Delegate hợp lệ của MetaMask `EIP7702StatelessDeleGator` (`0x63c0…dae32b`) có mặt với flag 1 (BSC, 1 EOA ADDR).
- Mọi 17.326 lần ủy quyền trong dữ liệu tác giả đều đến từ EOA KEY/ADDR, nên dữ liệu tác giả không có EOA 7702 lành tính để làm mẫu âm.
- Hệ quả cho paper: "có đường chuyển tiền" không đủ để kết luận delegate độc (smart wallet nào cũng chuyển được tiền). Phải kết hợp danh sách ví hợp lệ đã kiểm chứng và luồng tiền thực tế. Đây cũng là một nguồn FP cần đo khi đánh giá.

**N6, delegate 7702 hợp lệ** (`python -m address_misuse.negatives n6` → `data/interim/n6_benign_7702_delegates.parquet`): giữ 5/5 ứng viên. Tên contract đã verify được kiểm tra qua Blockscout API (không cần key), và cả 5 đều có code trên ETH.
- MetaMask `EIP7702StatelessDeleGator`
- Coinbase `EIP7702Proxy`
- Uniswap `CaliburEntry`
- `Simple7702Account` (eth-infinitism)
- Ambire `AmbireAccount7702`

**N1, địa chỉ ngẫu nhiên không bị gắn cờ** (`python -m address_misuse.negatives n1 --per-chain 200 --seed 0` → `data/interim/n1_random_unflagged.parquet`): 400 địa chỉ lấy từ `candidate_addresses`, loại mọi địa chỉ có trong `ca_misuse`/`eoa_misuse`.

| Chain | none | code | 7702 |
|---|---|---|---|
| ETH | 174 | 21 | 5 |
| BSC | 140 | 51 | 9 |

14/400 (3,5%) địa chỉ ngẫu nhiên lấy từ code công khai **hiện đang ủy quyền EIP-7702**. Cảnh báo phía ví không thể coi mọi EOA 7702 là đáng ngờ.

**Pilot D5 làm mù lại:** trước đây một số cột bằng chứng chỉ được điền ở vài tầng, nên người gán đoán được tầng:
- `xc_timing` có ở mọi địa chỉ thuộc ma trận misuse;
- `delegate_7702` chỉ có ở EOA của tác giả;
- `symexec_*` chỉ có ở PCD;
- N7 thiếu `xc_nets`.

Bản mới tra `getCode` cho mọi mẫu. Symexec chạy bổ sung cho 12 contract chưa có kết quả của tác giả: 1 bị kill vì OOM, 3 hết timeout 120 s. Cột nguồn gốc/thời điểm chỉ được điền ở tình huống T4. Một mẫu `t4_xc_after` trên ETH nay đã có code ngay trên ETH: trạng thái hiện tại khác với lúc bị misuse.

## 2026-10-17 — D3 bổ sung creation trên BSC qua Binplorer (`crosschain_matrix origin/timing/build`)

Lấy creation cho 13.472 contract trên BSC qua Binplorer `getAddressInfo` (key riêng), sau đó chạy lại timing và build. Phần lớn ETH-NCD-XC có contract nằm trên BSC, nên chỗ "unknown" phía ETH giờ đã được lấp.

**Timing trên ETH misuse** (19.273 địa chỉ XC; trước đây chỉ tra được 5.132):

| Nhãn | deployed_before | deployed_after | unknown |
|---|---|---|---|
| NCD-XC | 17.221 (538,9 ETH, 385.818 tx) | 232 (25,9 ETH) | 1.329 |
| PCD-XC | 414 (482,9 ETH) | 51 (10,3 ETH) | 26 |

- **98,4% (17.635/17.918) ca đã biết thời điểm có contract ở chain khác trước tx đầu tiên trên ETH**, tương đương 91,5% tổng số XC. Riêng contract gốc trên BSC: 13.395/13.486 (99,3%). Kết quả trước (90,9%) đúng là cận dưới.
- deployed_after chủ yếu đến từ sepolia (82/320) và arb (62); khi đó địa chỉ trên ETH bị dùng trước, nên theo codebook các ca này là T1 chứ không phải T4.
- Khoảng cách tx đầu − deploy: trung vị 39 ngày (p10 1, p90 414); 6,9% trong 1 ngày, 23,1% trong 7 ngày, 44,8% trong 30 ngày.
- Còn 1.355 unknown, phần lớn vì contract gốc nằm trên OP/Base/BSC testnet (`no_creation_api`, 1.438 dòng).

**Khả năng deploy lại** phía ETH misuse (trước: unknown 14.955): claimable 11.293 (308,0 ETH), burned 3.112 (205,8 ETH), already_deployed 527 (492,5 ETH), factory có / không có trên ETH 1.172 / 1.597, unknown 1.572.

- **Hạn chế:** timing phía BSC misuse vẫn là unknown, vì chưa có nguồn miễn phí lấy tx đầu tiên trên BSC. Đã thử ngày 2026-10-17:
  - Etherscan free không hỗ trợ BSC.
  - Ankr công khai bắt buộc key.
  - Binplorer `getAddressTransactions` bỏ tx giá trị 0 và không có `input`/`gasUsed`.
  - RPC công khai chặn receipt cũ (cần token archive).

## 2026-10-16 — D3 thời gian: contract ở chain khác có trước lúc misuse không (`crosschain_matrix timing`)

So `first_create_ts` (thời điểm deploy sớm nhất **đã biết** ở mạng khác, từ Etherscan creation) với tx đầu tiên tới địa chỉ trên chain bị misuse (Etherscan `txlist` asc). Chỉ làm được cho **misuse trên ETH** có creation ở arb/polygon/sepolia/eth: 5.132 địa chỉ, 0 lỗi. Misuse trên BSC: chưa có nguồn lịch sử tx BSC miễn phí.

| Nhãn | deployed_before | deployed_after | unknown |
|---|---|---|---|
| NCD-XC | 4.538 (249,1 ETH, 186.678 tx) | 377 (29,9 ETH) | 13.867 |
| PCD-XC | 128 (304,8 ETH) | 89 (10,1 ETH) | 274 |

- **90,9% (4.666/5.132) contract đã tồn tại ở chain khác trước tx đầu tiên trên ETH** → bằng chứng trực tiếp cho Type 4: người dùng dùng một địa chỉ contract có thật của chain khác, không phải địa chỉ ngẫu nhiên.
- Khoảng cách tx đầu − deploy: trung vị 45 ngày (p10 0, p90 441). 8% trong vòng 1 ngày, 21% trong 7 ngày, 38% trong 30 ngày → nhiều ca xảy ra ngay sau khi dự án deploy đa chain (có thể chính đội dự án/người tích hợp gửi nhầm). Cần kiểm tra người gửi tx đầu có trùng deployer không.
- Hạn chế: `first_create_ts` chỉ là mốc sớm nhất **đã biết** (thiếu BSC/OP/Base) nên tỉ lệ deployed_before là **cận dưới**. "tx đầu tiên" là mọi tx tới địa chỉ, không riêng tx misuse (với NCD gần như trùng nhau).

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

## 2026-10-24 — D5: mẫu vàng chính phải lấy từ dataset_v2 (rà soát)

- **Đơn vị mẫu**: pilot lấy theo địa chỉ, nhưng engine chấm theo mẫu (địa chỉ, `at`) và trạng thái code thay đổi theo thời
  gian (PCD chưa có contract lúc `at`; 7702 uỷ quyền sau `at`). Người gán phải thấy bằng chứng tại `at`: `at_date`,
  `code_at_event`, `own_create_date`, `tx_hash`, selector, value.
- **Cỡ mẫu**: PLAN_V2 ghi ~1.000 dương mới, nhưng dataset_v2 chỉ có 42 dương mới (D6) và ~450 dương test → mẫu chính ~600
  (`MAIN_PLAN` trong `sample_gold.py`), tầng nhỏ lấy hết. Cần `weight` = cỡ tầng / số rút khi tính precision, recall từ
  mẫu vàng; không có thì tầng bị lấy mẫu con làm lệch số.
- **Gán đôi**: 200 mẫu được gán bởi cả hai người để tính κ; người gán không thấy nhãn, tầng, điểm R (file `main_key.csv`
  giữ riêng).
- **Lỗi bắt được khi viết test**: `d[[...]]` với list rỗng chọn 0 cột (tầng rỗng làm `draw_main` sập); nay dùng mảng bool.
- Tái tạo: `python -X utf8 -m address_misuse.sample_gold main --seed 0 --double 200` (sau `freeze`).

## 2026-10-24 — Số liệu engine sau lượt sửa (chạy lại toàn chuỗi)

Nhãn vẫn là luật tác giả + tập âm N1–N8 (TẠM, chưa phải nhãn vàng D5). Tái tạo: `engine.prepare contracts` → `engine.evaluate`
→ `engine.metrics` → `wallet.replay` → `freeze` (log ở `data/interim/*.log`). Mức cảnh báo (τ_warn = 63,0; τ_block = 65,7).

| Tập | Dương / âm | P | R | F1 | FPR | AUC |
|---|---|---|---|---|---|---|
| test | 442 / 1.568 | 0,985 | 0,873 | 0,926 | 0,004 | 0,976 |
| test_in_time (không trùng out_of_time) | 266 / 927 | 0,991 | 0,808 | 0,890 | 0,002 | 0,957 |
| out_of_time (≥ 2025-09) | 176 / 641 | 0,977 | 0,972 | 0,974 | 0,006 | 0,997 |

- **Phải đọc kèm "chỉ R"** (mẫu không dính luật cứng): test P 0,980 · R 0,728 · F1 0,836; out_of_time R 0,688 (chỉ 16 mẫu mềm).
  Luật cứng một mình: R 0,534 (test), 0,909 (out_of_time). Recall theo loại ở test: ADDR 0,82 (toàn do luật cứng; trên mẫu
  mềm 0/26), KEY 1,00 (luật cứng `leaked_key`), NCD 0,81 (hầu hết do R, luật cứng 0,01), PCD 0,90 (do R). Nghĩa là NCD/PCD
  là phần engine "học" được; ADDR/KEY gần như đồng nghĩa nhãn.
- **test_in_time thấp hơn test** (F1 0,890 vs 0,926; ADDR 0,63 vs 0,82): phần cao của test nhờ mẫu ≥ 2025-09 (ADDR/delegate 7702
  mới) mà luật cứng bắt dễ. Số đưa vào paper nên là `test_in_time` và `out_of_time` tách riêng, không dùng `test` gộp.
- **GoPlus** (trạng thái hiện tại, có lợi thế hindsight): test P 0,29 · R 0,020 · F1 0,038; trên mẫu mềm R 0,039. Engine
  trên cùng mẫu F1 0,925; GoPlus HOẶC engine không tốt hơn engine một mình (FPR 0,018 vs 0,004). Baseline `getCode==0x ∧ calldata`:
  P 0,24, FPR 0,36 → luật đơn giản không đủ.
- **Ablation (F1 warn, test)**: đủ 4 = 0,926; bỏ bytecode 0,905; bỏ cross 0,822 (nặng nhất, R 0,706); bỏ osint 0,925 (AUC
  0,976 → 0,934); bỏ history 0,874 (nay đã bỏ cả luật `sweeper`); chỉ cross 0,873 nhưng AUC 0,641. S_osint gần như không
  đổi F1 vì dương lẫn N1 đều từ candidate_addresses (RISK_SCORE §2.3) → chờ D7.
- **τ không ổn định**: τ_warn bootstrap theo địa chỉ p5 25,9 · p50 63,0 · p95 65,7 (val chỉ 186 âm bình thường) — ngưỡng cần
  ghi kèm khoảng, hoặc dùng nhiều âm hơn. τ_block bootstrap 65,7 cố định.
- **FPR theo nhóm âm** (test): N7 0,053 (hợp lệ nhiều chain, hash/selector khác), N5 0,026, N1 0,011; báo nhầm do luật cứng:
  `sweeper` 2, `malicious_delegate` 1 (ETH). Âm `excluded` (681) FPR 0,012 vs 0,004 ở âm giữ lại → số FPR hơi lạc quan.
- **Ví thật (replay)**: offline, ETH misuse cảnh báo 94,9% tx / 98,2% giá trị; BSC 74,6% tx / 99,9% giá trị; FPR N8 ETH 0,98%, BSC
  1,64% (online, không history: ETH 0,33%, BSC 0%). Online bắt ADDR chỉ 26,7% tx ETH (thiếu history/luật `sweeper`). Địa chỉ dương
  test bị bỏ vì không có tx nào bị luật tác giả gắn cờ sau mốc test: ETH 42, BSC 20.
- **dataset_v2** đóng băng: 6.547 mẫu (1.600 dương, 4.947 âm), QA đạt (checksum 0 sai). Số liệu GoPlus: tra được 99% mẫu.

## 2026-10-25 — D7 GitHub OSINT và OP (Blockscout hết credit)

- **D7 xong**: `osint_github run` tra 4.549 địa chỉ của dataset_v2 (code search, ~6 giờ), cache `data/raw/osint/github.jsonl`;
  xem lại bằng `osint_github summary`. Có kết quả: dương 82,9% (n=1.594), âm 83,9% (n=2.955), số file trung vị 4 ở cả hai.
  **S_osint nhị phân (có / không trên GitHub) không phân biệt dương và âm**: địa chỉ có mặt trên GitHub vì là contract nổi tiếng,
  danh sách đen (DefiLlama adapters…), ví dụ. Theo nhóm: PCD 96%, NCD 89%, N2 94%, N8 81%, ADDR 74%, KEY 65%, N1 61%.
  Việc cần làm trước khi dùng số này: tách ngữ cảnh (đường dẫn test/ví dụ/README, repo "blacklist" so với repo mã nguồn)
  và thử `1 − e^(−n/k)` theo số repo; hiện `n_context` đã lưu nhưng chưa nối vào `S_osint`. Ablation hiện tại "bỏ osint"
  (F1 0,925 vs 0,926) nhất quán với điều này; trọng số 0,359 của osint chủ yếu do tập `candidate_addresses` của tác giả.
- **OP (Blockscout PRO)**: key chạy ở `api.blockscout.com/10/api` nhưng gói miễn phí hết credit sau ~1.250 txlist
  (HTTP 402 `Out of credits`), nên `txlist --chain op --focus author` mới tải 1.254/8.869 địa chỉ; đã dừng tác vụ để khỏi lặp
  lỗi 402. Chưa chạy `rules --chain op` (dữ liệu thiếu sẽ làm số misuse OP lệch). Hướng đi: chờ credit reset (chưa rõ chu kỳ)
  hoặc giữ OP chỉ ở mức tín hiệu getCode, như PLAN_V2 §D3b đã cho phép.


## 2026-10-25 — Rà soát lần 3, D7 không phân biệt, OP sửa lấy thời điểm tạo contract

- **Credit Blockscout reset theo ngày** (người dùng xác nhận: hết credit ngày trước, reset lại sau 24 giờ). Không tạo thêm tài
  khoản để lấy thêm credit (lách hạn mức, có thể vi phạm điều khoản); chia nhỏ crawl qua nhiều ngày. `_bs_get` nay ném
  `OutOfCredits` ngay khi gặp HTTP 402 (trước đó thử lại 6 lần cho từng địa chỉ) và `cmd_txlist` dừng sạch.
- **Lỗi `op batch thất bại ... phần tử lỗi` đã rõ nguyên nhân**: `getcontractcreation` trả block trước Bedrock (< 105.235.063,
  tức contract tạo từ 11/2021 tới 6/2023), RPC công khai (publicnode) không có các block này nên mỗi lô lỗi mãi và không ghi,
  còn mỗi lần chạy lại tốn ~30 giây/lô. Cache cũ chỉ có block ≥ 105.258.820, tức **PCD tạo trước Bedrock bị thiếu hệ thống**
  (lệch về PCD mới). Sửa: block cũ lấy timestamp qua Blockscout `module=block&action=getblockreward`. Có test.
- **D7 tách ngữ cảnh vẫn không phân biệt** (AUC dương vs âm, train / val / test): tổng số file 0,33 / 0,56 / 0,53; số repo
  0,35 / 0,61 / 0,61; số file ngữ cảnh test/ví dụ 0,30 / 0,53 / 0,57; nhị phân 0,46 / 0,50 / 0,50. Dấu đổi giữa train và
  val/test nên không có tín hiệu ổn định. Âm hạ tầng (N2 trung vị 60 repo, N7 67, N5 18) nhiều hơn hẳn dương (NCD 6, PCD 9,
  ADDR 1, KEY 1). Kết luận: **không nối GitHub vào S_osint**; S_osint chỉ còn vai trò thật là khoá lộ (luật cứng KEY).
  Phần trọng số 0,359 của osint là do `candidate_addresses` của tác giả: mọi dương nằm trong tập đó (và N1 cũng vì lấy mẫu
  từ đó), nên cần nêu trong paper là tín hiệu do cách lấy mẫu, không phải tín hiệu triển khai được.
- **Rà soát code (không sửa vì không làm sai số liệu đã công bố)**:
  * `same_contract`: 14/≈400 báo nhầm S_cross của âm (PCD-XC 0,6) là do một bên thiếu selector (hash khác, không so được Jaccard);
    nên coi là "không rõ" thay vì "khác code". Hầu hết còn lại là hash khác thật và Jaccard < 0,8.
  * Cùng địa chỉ ở hai chain khác tập: 8 địa chỉ; khác nhãn giữa hai chain: 13 (khoá QA là (chain, address) nên không bắt).
  * Mẫu âm theo tx lặp địa chỉ: test N2 253 dòng/230 địa chỉ, N3 559/343, N8 518/440; val bình thường 186 dòng/169 địa chỉ
    (τ_warn dựa trên ≈ 2 mẫu âm cao nhất, nên bất ổn). Bootstrap đã lấy mẫu theo địa chỉ.
  * pyflakes sạch (trừ một import thừa trong `bq_fetch.py`); 85 test đạt.

## 2026-10-25 — Rà soát lần 4: mẫu vàng D5 lộ nhãn qua bằng chứng giao dịch (đã sửa)
- **Lỗi**: ở `data/gold/main_items.csv`, `tx_hash`/`selector`/`value_native` chỉ có ở mẫu âm theo tx (N2/N3/N8); mọi mẫu dương và
  các âm theo địa chỉ đều trống. Tỷ lệ có `tx_hash`: nhãn âm 0,58, nhãn dương 0,00 → người gán chỉ cần thấy có hash là đoán được
  "âm", làm hỏng điều kiện làm mù và thổi phồng κ / độ chính xác nhãn vàng.
- **Sửa**: `sample_gold.event_tx(chain, address, at)` khôi phục tx đi vào tại đúng `at` từ txlist đã lưu (ưu tiên tx có calldata);
  `main_evidence` dùng nó cho mẫu theo địa chỉ. Sau khi sinh lại: `tx_hash` và `value_native` 1,00 ở cả hai nhãn, `selector`
  0,68 (âm) / 0,76 (dương) (chênh do chuyển ETH thường không có calldata, không còn là dấu hiệu nhãn). Khoá mẫu `main_key.csv`
  giữ nguyên (605 dòng giống hệt, vì chọn mẫu không đổi).
- Test mới `test_event_tx_recovers_incoming_tx_at_event_time`. Nếu đã gửi file Excel cũ cho người gán thì phải sinh lại.
