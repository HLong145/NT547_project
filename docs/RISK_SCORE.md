# Đặc tả Risk Score R(A, C) — Module 2 (bản nháp v0.1, 2026-10-19)

Công thức theo [requirements.md](requirements.md) §3.2 và [PLAN_V2.md](PLAN_V2.md) §3:

$$R(A, C) = 100 \cdot \big(w_1 S_{\text{bytecode}} + w_2 S_{\text{cross}} + w_3 S_{\text{osint}} + w_4 S_{\text{history}}\big), \quad S_i \in [0,1],\ w_i \ge 0,\ \textstyle\sum w_i = 1$$

File này chốt **mỗi thành phần S tính từ đặc trưng nào**, cách học trọng số, ngưỡng cảnh báo và giao diện code (`src/address_misuse/engine/`). Chưa có số liệu: mọi hằng số ghi `(*)` sẽ chọn trên tập val.

## 1. Đầu vào và nguyên tắc

- **Đối tượng chấm điểm:** địa chỉ đích `A` trên chain `C`, tại thời điểm `t`. Tuỳ chọn thêm ngữ cảnh giao dịch `ctx = {value, calldata, token}` khi chạy trong ví (Module 4).
- **Chỉ dùng thông tin có trước `t`.** Khi replay lịch sử (Module 3/4), "contract có ở chain khác không" nghĩa là `create_ts ≤ t`, không phải trạng thái hôm nay. Nếu không, risk score sẽ "nhìn thấy tương lai" (ví dụ 283 ca `deployed_after` trong FINDINGS_LOG 2026-10-17).
- **Hai chế độ:**
  - *Theo giao dịch* (ví): có `ctx`, chấm đúng giao dịch sắp ký.
  - *Theo địa chỉ* (đánh giá trên nhãn vàng): không có `ctx`. Dùng ngữ cảnh giả định từ lịch sử: tỉ lệ tx tới `A` có calldata, có giá trị.
- **Mỗi điểm kèm lý do:** trả về thành phần đóng góp lớn nhất và Type T1–T6 nghi ngờ, để ví hiển thị giải thích.

## 2. Bốn thành phần

### 2.1. S_bytecode(A, C) — cấu trúc code trên chain đích

Theo trạng thái `code_C(A)` tại `t` (`none` / `code` / `7702`):

| Trạng thái | Điều kiện | S_bytecode | Type |
|---|---|---|---|
| `none` | tx có calldata (gọi hàm tới địa chỉ không có code) | 1,0 | T1 |
| `none` | chuyển coin thuần, không calldata | 0 | — (chuyển cho EOA bình thường) |
| `code` | symexec: không có `transfer_*`, `delegatecall`, `selfdestruct` và contract nhận coin | 1,0 | T2 (hố đen) |
| `code` | proxy chưa khởi tạo (slot implementation = 0) | 0,8 (*) | T2 |
| `code` | ERC-20 `transfer(to = A)` với `A` là chính token | 1,0 | T3 |
| `code` | có đường rút | 0 | — |
| `7702` | delegate độc đã biết | 1,0 | T5 |
| `7702` | delegate là ví hợp lệ (N6) | 0 | — |
| `7702` | delegate chưa biết, symexec thấy đường chuyển tiền | 0,5 (*) | T5? |
| `7702` | delegate chưa biết, không có đường chuyển tiền | 0,2 (*) | — |

Nguồn đã có:
- `crosschain_matrix` (code 8 mạng);
- symexec (tác giả và chạy lại, khớp 100%);
- N6.

Lưu ý: "có đường chuyển tiền" **không** đủ để kết luận delegate độc (FINDINGS_LOG 2026-10-19), nên nó chỉ cho 0,5 chứ không phải 1.

### 2.2. S_cross(A) — nhất quán địa chỉ xuyên chuỗi

Xét các mạng khác `C' ≠ C` trong 8 mạng:

| Tình huống tại `t` | S_cross | Type |
|---|---|---|
| `C` không có code, có `C'` đã có contract **trước** `t` | 1,0 | T4 (NCD-XC) |
| như trên nhưng chưa biết thời điểm deploy ở `C'` | 0,7 (*) | T4? |
| `C` có code, `C'` có code **khác** bytecode | 0,6 (*) | PCD-XC, có thể là contract cài sẵn |
| `C` có code, trùng bytecode với `C'` | 0 | — (N7: hạ tầng đa chain) |
| không mạng nào có code | 0 | — (để S_bytecode/S_history xử lý) |

Điểm cộng thêm (lấy max, không vượt 1):
- Địa chỉ deploy lại được trên `C` (`redeploy = claimable`): kẻ xấu có thể chiếm, +0,1 (*).
- Có code ở mạng testnet nhưng `C` là mainnet: nguồn NCD phổ biến trên ETH (testnet cũ), giữ nguyên 1,0.

Nguồn đã có: `crosschain_matrix.parquet` (`xc_nets`, `same_code_elsewhere`, `first_create_ts`, `xc_timing`, `redeploy`). Chỉ cần đổi phép so "hôm nay" thành "tại `t`".

### 2.3. S_osint(A) — xuất hiện trong mã nguồn công khai

| Tín hiệu | S_osint |
|---|---|
| Private key của `A` đã lộ công khai (`candidate_pk_addresses`; tài khoản mặc định Hardhat/Ganache/Anvil) | 1,0 |
| `A` xuất hiện trong code công khai (`candidate_addresses`), `n` = số repo/bài chứa | 1 − e^(−n/k), k = 3 (*) |
| Ngữ cảnh là file test / ví dụ / README (địa chỉ minh hoạ) | × 1,2, chặn ở 1 (*) |
| Không xuất hiện | 0 |

Hạn chế hiện tại: seed của tác giả có tập địa chỉ ứng viên nhưng **không** có số repo cho từng địa chỉ, cũng không có ngữ cảnh file. Bản v1 dùng nhị phân (có / không, lộ key = 1). Số repo và ngữ cảnh lấy từ D7 (OSINT GitHub cho top ~3.000 địa chỉ).

Cảnh giác: mọi mẫu dương lẫn N1 đều lấy từ `candidate_addresses`, nên S_osint nhị phân **không** phân biệt được dương/âm trong tập này. Ablation phải báo cáo rõ điều đó. S_osint chủ yếu có ích khi chấm địa chỉ bất kỳ trong ví.

### 2.4. S_history(A, C) — lịch sử giao dịch trước `t`

Kết hợp kiểu noisy-OR: `S_history = 1 − (1 − s_sweep)(1 − s_revert)(1 − s_misuse)`.

| Đặc trưng | Định nghĩa | Nguồn |
|---|---|---|
| `s_sweep` | Tỉ lệ coin nạp vào `A` bị rút gần hết trong ≤ N block bởi tx gas cao (`rules.find_sweep_pairs`) | tx thô |
| `s_revert` | Tỉ lệ tx gọi tới `A` bị revert, chỉ tính khi có ≥ 5 tx (*) | tx thô |
| `s_misuse` | Đã có tx khớp rule misuse của Shao et al. từ ≥ 2 người gửi khác nhau (*) | tx thô + `rules.py` |

Phụ thuộc D1 (tx thô ETH qua BigQuery hoặc Etherscan, BSC qua NodeReal). Trong lúc chưa có D1, S_history chỉ tính được cho mẫu pilot 500 ETH (`reproduce_rules`).

## 3. Học trọng số và ngưỡng

1. **Nhãn:** `is_misuse` từ nhãn vàng D5. Mẫu âm: N1, N6, N7 (sau này thêm N2–N5, N8).
2. **Chia tập theo thời gian, không trùng địa chỉ** (D8): train / val / test.
3. **Học `w`:** logistic regression với hệ số không âm trên 4 thành phần S (train), rồi chuẩn hoá `w_i = β_i / Σβ`. Như vậy R ∈ [0, 100] đúng như công thức, và giữ nguyên thứ hạng của mô hình.
   - Báo cáo thêm bản xác suất đã hiệu chỉnh `σ(β₀ + Σβ_i S_i)` để so sánh.
   - Nếu một β về 0, ghi nhận thành phần đó không đóng góp.
4. **Ngưỡng (trên val):**
   - `τ_warn`: FPR ≤ 1% trên N8 (giao dịch bình thường).
   - `τ_block`: precision ≥ 0,95 (*).
5. **Ablation:** bỏ từng S_i; chỉ dùng S_cross (tương đương heuristic cross-chain); chỉ dùng rule gốc của Shao et al.
6. **Chỉ số trên test:** P/R/F1/FPR theo Type và chain, ROC/PR, bootstrap CI (PLAN_V2 §4).

Ngoài điểm số, có **luật cứng** cho ví: private key lộ, hoặc delegate độc đã biết, thì cảnh báo ngay, bất kể R. Đánh giá phải báo cáo riêng phần do luật cứng và phần do R, để không thổi phồng hiệu quả của R.

## 4. Ngân sách độ trễ (< 150 ms trong ví)

| Thành phần | Online | Offline (tính trước) |
|---|---|---|
| S_bytecode | `eth_getCode` trên `C` (cache) + nhận diện `0xef0100` | symexec cho contract/delegate đã biết. Symexec mất từ giây đến phút nên **không** chạy online; contract lạ dùng quét opcode nhanh (có `CALL`/`SELFDESTRUCT`/`DELEGATECALL` hay không) |
| S_cross | `eth_getCode` song song 8 mạng, timeout 100 ms, cache theo địa chỉ | `first_create_ts`, `redeploy` từ ma trận |
| S_osint | tra bảng cục bộ (set/bloom filter) | tập lộ key, tập ứng viên |
| S_history | tra bảng cục bộ | chỉ số sweeper / revert tính sẵn theo lô |

Mạng nào quá timeout thì bỏ qua và ghi vào lý do ("không kiểm tra được arb"). Không chặn giao dịch chỉ vì RPC chậm.

## 5. Giao diện code (`src/address_misuse/engine/`)

```python
@dataclass
class RiskResult:
    score: float                      # 0–100
    components: dict[str, float]      # {"bytecode": .., "cross": .., "osint": .., "history": ..}
    types: list[str]                  # ví dụ ["T4"], ["T1", "T4"]
    reasons: list[str]                # câu giải thích ngắn cho ví
    hard_rule: str | None             # "leaked_key" | "malicious_delegate" | None

def score(address: str, chain: str, at: int | None = None, ctx: TxContext | None = None,
          weights: dict[str, float] = DEFAULT_WEIGHTS) -> RiskResult: ...
```

- Mỗi thành phần là một hàm thuần `s_bytecode(features, ctx) -> (float, types, reasons)`, nhận đặc trưng đã tra sẵn. Dễ unit test, không gọi mạng.
- Lớp `FeatureStore` lo việc tra: cache getCode, ma trận, symexec, N6, tập lộ key. Bản offline đọc Parquet, bản online gọi RPC.
- `DEFAULT_WEIGHTS` = 0,25 mỗi thành phần cho tới khi học xong trên train.

## 6. Việc cần làm

- [x] `engine/features.py`: FeatureStore offline (ma trận, symexec, proxy, N6, lộ key, ứng viên, delegations, `bq_txs` cho ETH). Địa chỉ ngoài ma trận: `probe()` getCode 8 mạng → `data/interim/engine_code.parquet`.
- [x] `engine/score.py`: 4 hàm S, kết hợp, luật cứng, lý do; `tests/test_engine.py` (11 test). CLI: `python -m address_misuse.engine 0x... --chain bsc --data 0x...`.
- [x] Chấm thử 1.181 mẫu (at = hôm nay, trọng số 0,25): 1,7 ms/mẫu offline. Vấn đề phát hiện (FINDINGS_LOG 2026-10-22):
  - [x] Delegate 7702 đổi sau snapshot tác giả: `engine.prepare delegates` chạy symexec cho 30 delegate mới (30/30 ok, `engine_symexec.jsonl`); khi có `at` dùng delegate tác giả ghi lại, không dùng delegate hôm nay.
  - [x] Mẫu âm ETH có tx thô: `engine.prepare history` lấy txlist Etherscan cho N1 (≤ 10k tx) và N6/N7 (1.000 tx đầu, vì Etherscan ~45 s/trang với contract hạ tầng). BSC: cả dương lẫn âm đều chưa có lịch sử.
  - [x] So contract giữa các chain: trùng hash **hoặc** Jaccard selector dispatcher ≥ 0,8 (`same_contract`). S_cross trung bình của N7 từ 0,17–0,20 về 0.
  - [x] Hoá ra 100% PCD có symexec; 258 contract thiếu là địa chỉ **NCD về sau mới được deploy**. `engine.prepare creation` lấy thời điểm tạo (Etherscan cho ETH, NodeReal cho BSC, 258/258) → `engine_creation.parquet`; khi `at` trước thời điểm tạo, địa chỉ được coi là chưa có code.
- [ ] Sau D1: S_history. Sau D5 + D8: học `w`, chọn ngưỡng, ablation.
- [ ] Sau D7: S_osint có số repo và ngữ cảnh.

## Lịch sử

- **v0.1 (2026-10-19):** bản nháp đầu.
- **2026-10-22:** cài đặt `engine/` theo v0.1.
