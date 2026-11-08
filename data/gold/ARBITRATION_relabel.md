# Kiểm 5 bất đồng: A gán lại mù 50 mẫu đơn của B (GOLD_PROTOCOL §2.6)

- Ngày: 2026-11-08. Người kiểm: người điều phối. Đề xuất này **chờ B duyệt, sau đó A xác nhận**.
- Đầu vào:
  - `annotator_main_single_B.xlsx`: 508/508 mẫu, sha256 `d84d131f5d93dc725d813ff2c8ce63570c296b2b210952f8085d5e89725ea1cc`.
  - `annotator_main_relabel_A.xlsx`: 50/50 mẫu, sha256 `92a7eeba0e181e826b3c5c6c169bfa2143361858831c3e3c75287712689ad5f8`.
  - Cả hai không có lỗi hình thức. 50 mẫu của A nằm trong file của B, cùng địa chỉ, không trùng tập κ chính thức.
- Quy tắc: CODEBOOK v0.6.4, `delegate_lookup.csv` bản cuối (`fbf472e8…8790`). Làm mù: không mở `main_key.csv` hay nhãn tác giả.
- §2.6: nhãn cuối của 50 mẫu vẫn là của B, **chỉ sửa khi thấy lỗi rõ** và ghi là sai lệch.

## Kết quả thô (báo trong paper)

| Chỉ số | Giá trị |
|---|---|
| Bất đồng is_misuse B–A | 4/50 = 8,0% [Clopper–Pearson 95% 2,2–19,2%] |
| Bất đồng type B–A | 5/50 = 10,0% [3,3–21,8%] |
| κ(is_misuse) | 0,839 [CI95 theo cụm 0,642–1,000], AC1 0,842, PABAK 0,840 |
| κ(type) | 0,854 [0,697–0,970] |
| Bảng chéo is_misuse | A=0/B=0: 20, A=0/B=1: 4, A=1/B=0: 0, A=1/B=1: 26 |

Cả 4 bất đồng is_misuse đều là B gán 1, A gán 0.

## Kiểm on-chain từng bất đồng

| Mẫu | Chain | A | B | Kiểm on-chain | Đề xuất | Đúng |
|---|---|---|---|---|---|---|
| G488 | bsc | 0 NONE | 1 T5/7702 ? | Tx mẫu type-4 do ví thu 0xa61919b4… gửi, chứa ủy quyền **của chính địa chỉ** (nonce 3). Archive NodeReal: nonce 3→4, code `0xef0100c99f40a9…` → `0xef0100a1c72cfc…` (forwarder_sweeper). Cùng kiểu nhóm 1 của ARBITRATION_official. | giữ B: 1 T5/7702, mal ?, medium | B |
| G620 | bsc | 0 NONE | 1 T5/7702 ? | Như G488: ủy quyền của chính địa chỉ (nonce 12→13), delegate cũ 0x1107396b… → 0xa1c72cfc (forwarder_sweeper). | giữ B: 1 T5/7702, mal ?, medium | B |
| G452 | bsc | 0 NONE | 1 T5/KEY | Lịch sử đầy đủ (NodeReal, 1.712 sự kiện): 4 lần rút nhanh, 4 ví nhận khác nhau, không nhận lại tài sản trong cùng tx (USDT 11,67 năm 2024; USDC 1.715, 3.548,9, 84,3 năm 2026). A chỉ xem được 1.000 thao tác gần nhất. Không kiểm được nhãn ví nhận (BscScan chặn Cloudflare), nên là ca 7b/7c. | giữ B is_misuse/type; đề nghị đổi `confidence` medium → **low**, note "ca 7b/7c" (CODEBOOK §3.4 bước D2) | B (is_misuse) |
| G484 | eth | 1 T4/PCD xc base | 1 T1/PCD | Tx 2024-04-29 17:00:35 UTC. Base có code từ block 13.767.523 (2024-04-28 17:13:13), **trước** tx. Contract trên ETH tạo sau tx (2024-04-30 17:35). CODEBOOK: T1 chỉ khi không có contract cùng địa chỉ ở chain khác tạo trước tx. | **sửa** type: 1 **T4**/PCD, xc base, mal 1 | A |
| G745 | eth | 0 NONE low | 1 T5/KEY low | Lịch sử ghép cả hai chiều (2.219 sự kiện, 2022-12 → 2026-10): 2 ứng viên. (1) 0,18 ETH → StarkGate ETH Bridge 0xae0ee0a6 (ca 7d, tính). (2) 0,17 ETH → MetaMask Swap Router 0x881d4023, **cùng tx nhận lại 1.297 LORDS** → swap, không phải rút nhanh (ngoại lệ ca 7d, §3.4 v0.6.3). Còn 1 lần → NONE. | **sửa**: 0 NONE, low, note "1 lần rút nhanh" | A |

## Tóm tắt

- B đúng 3/5, A đúng 2/5. Lỗi rõ của B: **2/50 mẫu**.
  - Sai is_misuse 1/50 = 2,0% [CP95 0,05–10,6%] (G745).
  - Sai type 2/50 = 4,0% [0,5–13,7%] (G745, G484).
- Ba loại nguyên nhân:
  1. A bỏ sót ủy quyền 7702 trong chính tx mẫu (G488, G620). Cùng lỗi với nhóm 1 ở ARBITRATION_official.
  2. A xem thiếu lịch sử (G452).
  3. B bỏ qua contract ở chain khác (G484) và tính nhầm một swap là rút nhanh (G745).
- Sửa vào nhãn cuối (ghi sai lệch GOLD_PROTOCOL §8): G484 type T1→T4 (xc base); G745 1/T5 → 0/NONE low; G452 confidence → low + note ca 7b/7c. Sửa trong file gold_adj, **không** sửa file xlsx gốc của B.
- Ước lượng sai số nhãn đơn cho paper: báo cả số thô (8,0% bất đồng B–A) và số sau kiểm (2,0% lỗi is_misuse của B). Số sau kiểm có thể lệch thấp vì B (người thiết kế, người bị đo) tham gia duyệt phân xử (§2.6 ý 1).

## Duyệt

- [ ] B (người dùng) duyệt đề xuất.
- [ ] A xác nhận.
