# Bàn giao viết paper

Tài liệu cho người viết tiếp `main.tex`. Đọc theo thứ tự: file này, [../docs/GOALS.md](../docs/GOALS.md) (mục tiêu cố định, không đổi hướng paper), rồi các mục FINDINGS_LOG được nêu dưới đây.

## 1. Tình trạng (2026-11-16)

- Bản thảo đủ mọi phần (Intro → Conclusion). Dịch bằng Tectonic: 18 trang, 0 lỗi, 0 trích dẫn thiếu.
- `references.bib` có 30 mục, mục nào cũng được trích và đã xác minh (xem §4).
- **Đã điền 2026-11-16 (cần nhóm xác nhận):**
  1. Tác giả: Nguyen Hoang Long (24521005), Lam Tu Lan (24520943). Email sinh viên theo mẫu `MSSV@gm.uit.edu.vn`. Tên giảng viên (Tran Tuan Dung) đã bỏ khỏi danh sách tác giả theo yêu cầu ngày 2026-11-16.
  2. Công bố có trách nhiệm: viết đúng sự thật là **chưa liên hệ ai**, và "dự định báo trước khi công bố". Nếu nhóm không định báo thì phải sửa câu này.
  3. Acknowledgments: cảm ơn Shao et al. và các nhà cung cấp dữ liệu. **Không ghi tài trợ** (nếu có thì thêm).
  4. Thêm kết quả D2 toàn bộ ETH (KEY, ADDR) và pilot 580 vào RQ1; cập nhật mục Contributions theo kết quả đã có.
- **Còn phải làm:**
  1. Giới hạn số trang của hội nghị đích. LNCS thường cho 12–16 trang không tính tài liệu tham khảo, nên có thể phải rút gọn. Nên cắt ở Background và các đoạn phụ của RQ2 trước, không cắt kết quả RQ3. Tóm tắt hiện 278 từ (LNCS khuyên 150–250).
  2. Dịch lại sau lần sửa 2026-11-16 (máy sửa không có LaTeX; chỉ kiểm cân bằng ngoặc và `check_refs.py`).
  3. Đọc soát văn phong tiếng Anh lần cuối.

## 2. Số liệu → nguồn

Mọi số trong paper phải có trong [../docs/FINDINGS_LOG.md](../docs/FINDINGS_LOG.md). Cột "Mục FINDINGS" ghi ngày và đầu tiêu đề của mục; tìm bằng Ctrl+F (số dòng sẽ đổi khi log dài thêm). File kết quả đều đã commit trong `data/interim/`.

| Phần paper | Số chính | Mục FINDINGS | File / lệnh |
|---|---|---|---|
| Tái lập luật (Tab. repl) | 500/500 địa chỉ, khớp đến wei | 2026-10-15 "Pilot tái lập rule", 2026-10-21 "Pilot rule mở rộng", 2026-10-22 "D2 (ETH)" | `rules_repro_eth.parquet`; `python -m address_misuse.reproduce_rules` |
| Symbolic execution | khớp tác giả trong hạn 120 s | 2026-10-12 "Tái lập symbolic execution" | `symexec_repro.parquet`; `python -m address_misuse.reproduce_symexec` |
| Delegate 7702 | 17.326 authorization | 2026-10-19 "`flag` delegate 7702…" | `d6_delegates.parquet` |
| Cross-chain (Tab. xc) | 45.633 địa chỉ; 77,2% / 68,1%; tổn thất 18,9% / 3,1% | 2026-10-16 "Ma trận cross-chain D3" | `crosschain_matrix.parquet`; `python -m address_misuse.crosschain_matrix all` |
| Thời gian (Tab. timing) | 98,4–98,8% có contract trước | 2026-10-16 "D3 thời gian", 2026-10-17 "D3 bổ sung creation trên BSC", 2026-10-20 "D3 timing BSC" | như trên (`timing`, `build`) |
| Redeploy (Tab. redeploy) | 11.515 / 11.293 claimable… | các mục D3 ở trên | `crosschain_matrix.py` (cột `redeploy`) |
| Các nhóm âm N1–N8 | N2 1.600, N8 1.969, N3 736, N4 83, N5 118 | 2026-11-13 "Số lượng nhóm âm trong dataset v2" | `n*_*.parquet`; `python -m address_misuse.negatives` |
| Trọng số R, τ | w = 0,522/0,359/0,086/0,033; τ_warn 63,01, τ_block 65,67 | 2026-11-16 "Trọng số học và ngưỡng của engine v1" | `engine_metrics.json` → `main.weights`, `main.threshold_boot.warn.p50/p95`; `python -m address_misuse.engine.metrics` |
| R = 62,4 < τ_warn | công thức đính chính | 2026-11-13 "Dịch paper bằng Tectonic…" | [../docs/GOLD_PROTOCOL.md](../docs/GOLD_PROTOCOL.md) §10.1 |
| Nhãn vàng | 858 mẫu = 758 lô 1 + 100 lô 2; κ = 0,799 | 2026-11-05 "κ chính thức", 2026-11-08 "nhãn vàng cuối 758 mẫu" | `gold_eval.json` |
| v1 đóng băng (Tab. gold) | P 0,94 / R 0,65 | 2026-11-08, 2026-11-13 "Lô 2" | `gold_eval_v2_heldout.json` → `c_combined_v1.main_addr` (lô 1 riêng: `gold_eval.json` → `main_addr`) |
| v2 (2 luật tiền đăng ký) | R 0,92 / P 0,84 / FPR 8,8% | 2026-11-10 "Engine v2", 2026-11-13 "Lô 2" | `gold_eval_v2_heldout.json` → `c_combined_v2_at.main_addr` |
| Held-out lô 2 (Tab. heldout) | 15/100 dương; v2 bắt 10/15, v1 0/15 | 2026-11-13 "Lô 2" | `gold_eval_v2_heldout.json` → `b_heldout_v2_at.raw`, `b_heldout_v1.raw` |
| Ablation, baseline GoPlus | các kịch bản `b_no_key`, `j_no_delegate`, `k_ca7_*` | 2026-11-08; 2026-10-24 "Rà soát lần 2 + baseline GoPlus" | `gold_eval.json`, `engine_metrics.json` |
| Độ trễ (bench) | lạnh p50/p95/p99 138/236/289 ms; ấm 0,04 ms; 69% < 150 ms | 2026-11-06 "Bench Module 4…" | `wallet_bench.json` → `runs["0.3"]`; `python -m address_misuse.wallet.bench` |
| Snap trong ví | block R 91,7; 244–265 ms lần đầu; 0,08 ms khi cache | 2026-11-13 "Snap thật trên MetaMask Flask", "Lần check đầu chậm…" | log của `wallet/api.py` |
| Phát lại / demo | 3 tx misuse trên Anvil fork | 2026-11-06 "Demo Module 4 trên Anvil fork" | `wallet_demo.json`, `wallet_replay.parquet` |

Lưu ý khi diễn giải:
- **v1 là kết quả chính.** v1 được đóng băng trước khi có nhãn vàng. Số v2 trên lô 1 là *trong mẫu*: luật v2 được thiết kế sau khi xem lỗi của lô 1. Bằng chứng ngoài mẫu duy nhất của v2 là lô 2 (10/15). Không viết v2 thành kết quả chính.
- Trọng số w không xác định duy nhất: đổi mức chính quy hoá L2 thì w_osint chạy từ 0,62 xuống 0,05 mà F1 gần như giữ nguyên (FINDINGS 2026-10-25 "Tính lại độc lập"). Paper đã nêu điều này. Đừng diễn giải w thành tầm quan trọng của đặc trưng.
- Số theo địa chỉ dùng trọng số Horvitz–Thompson và CI bootstrap phân tầng. Đừng thay bằng tỉ lệ thô trên mẫu.
- Lần check đầu chậm trong ví là hiệu ứng khởi động, **không phải** do kết nối rảnh. Giả thuyết "giữ kết nối nóng" đã thử và bị bác bỏ, xem mục 2026-11-13.

## 3. Quy tắc viết

- **Chỉ dùng số liệu, không dùng ảnh chụp hay hình chụp giao diện** (quyết định 2026-11-13). Bảng số liệu thì được.
- Chỉ điền số đã có trong FINDINGS_LOG. Có số mới thì ghi vào FINDINGS_LOG trước, kèm lệnh tái tạo, rồi mới đưa vào paper.
- Ẩn địa chỉ cá nhân dạng `0x1234…abcd` ([../docs/CODEBOOK.md](../docs/CODEBOOK.md) §8). Địa chỉ contract công khai (router, token) thì để nguyên được.
- Không viết như thể đã có hành động chủ động (gửi giao dịch, liên hệ nạn nhân). Mọi phân tích đều thụ động, và mọi giao dịch thử trong ví đều đã bị Cancel.
- Commit không kèm dòng `Co-Authored-By`.

## 4. Tài liệu tham khảo

- Chỉ dùng **hội nghị hoặc tạp chí đã bình duyệt** (USENIX Security, CCS, S&P, NDSS, WWW, ICSE, FSE, ISSTA, ACSAC…) hoặc **đặc tả chính thức** (EIP/ERC, Yellow Paper). Không dùng bài chỉ có trên arXiv. Một số bài có bản preprint đã bị loại vì lý do này (danh sách ở FINDINGS 2026-11-13 "Tài liệu tham khảo").
- Thêm mục mới cần:
  - Tra DOI qua Crossref (`https://api.crossref.org/works/<doi>`) hoặc trang bài trên usenix.org.
  - Khớp tên bài, tác giả, nơi đăng, năm và trang.
  - Chỉ trích những gì đã đọc trong bài. Các nhận định chưa kiểm chứng (ví dụ con số "63%" về 7702) đã bị gỡ khỏi paper.
- Kiểm tra mọi `\cite` đều có trong bib và ngược lại bằng `python paper/check_refs.py`. Lệnh trả mã 0 nếu khớp.

## 5. Biên dịch

Xem [README.md](README.md). Cách nhanh nhất là `tectonic main.tex` (tự tải `llncs.cls`) hoặc dùng Overleaf. `main.pdf` không được commit.

## 6. Dữ liệu không có trong repo

Người viết **không cần** những file này. Chỉ cần đến chúng khi muốn chạy lại đánh giá:

- `data/gold/gold_final.csv`, `batch2_gold.csv` và `*_key.csv`: nhãn vàng gắn với địa chỉ, cùng khoá giải mù.
- `data/gold/*.xlsx`: bảng gán nhãn của từng người gán.
- `data/interim/attx_cache*.json`: cache API cho `gold_attx.py` và `gold_batch2.py`, tạo lại được.
- `.env`: API key.

Muốn chạy lại thì xin trực tiếp người điều phối. Các file kết quả JSON và parquet đã commit là đủ để viết.
