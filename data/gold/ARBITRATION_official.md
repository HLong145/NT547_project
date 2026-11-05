# Phân xử 24 bất đồng is_misuse trong tập κ chính thức (200 mẫu)

- Ngày: 2026-11-05. Người phân xử: người điều phối. Đề xuất này **chờ B duyệt, sau đó A xác nhận**.
- Đầu vào: `annotator_main_official_A.xlsx`, `_B.xlsx` (κ(is_misuse) = 0,799, 24 bất đồng).
- Quy tắc: CODEBOOK v0.6.4, bảng `delegate_lookup.csv` bản cuối (sha256 `fbf472e8…8790`).
- Làm mù: chỉ dùng dữ liệu on-chain, **không** mở `main_key.csv` hay nhãn của tác giả.
- Nguồn kiểm:
  - Archive RPC: BSC qua NodeReal; ETH qua drpc, blastapi, tenderly; Base qua mainnet.base.org.
  - Etherscan V2 API: txlist, txlistinternal, tokentx, tokennfttx, token1155tx, getsourcecode.
  - Ủy quyền 7702 trong chính tx mẫu (`gold_attx.own_authorizations`): kiểm nonce trước → sau, và code `0xef0100…` tại block tx.
- Cột "Đúng": ai khớp nhãn vàng đề xuất ở is_misuse và type.

## Nhóm 1: tx mẫu tự cài delegate forwarder_sweeper (ca 13b), 10 mẫu

Trong cả 10 mẫu, tx mẫu là tx type-4 chứa ủy quyền 7702 **của chính địa chỉ mẫu**. Ủy quyền hợp lệ: nonce tăng, và code tại block tx là `0xef0100‖delegate`. Delegate đó có trong bảng là `forwarder_sweeper`, nên nhãn là **T5/7702**.

- A xét delegate cũ, hoặc coi là EOA thường (T1/NCD vì có selector).
- B ở G321 và G502 xét delegate trước tx, nên bỏ sót ủy quyền mới.

| Mẫu | Chain | A | B | Delegate cài trong tx mẫu | Vàng đề xuất | Đúng |
|---|---|---|---|---|---|---|
| G233 | bsc | 0 NONE | 1 T5/7702 ? | 0xa1c72cfc (ví thu 0xa61919b4…), số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G281 | bsc | 0 NONE | 1 T5/7702 ? | 0xa1c72cfc, số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G427 | bsc | 1 T1/NCD 0 | 1 T5/7702 ? | 0xa1c72cfc, số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G443 | bsc | 1 T1/NCD 0 | 1 T5/7702 ? | 0xa1c72cfc, số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G474 | bsc | 0 NONE | 1 T5/7702 ? | 0xa1c72cfc, số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G583 | bsc | 0 NONE | 1 T5/7702 ? | 0xa1c72cfc, số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G674 | bsc | 0 NONE | 1 T5/7702 ? | 0xa1c72cfc, số dư 0→0 | 1 T5/7702, mal ?, medium | B |
| G524 | eth | 0 NONE | 1 T5/7702 ? | 0x3ae1f70c (forwardAllEth, đích cứng); nonce 698→699. Delegate cũ là 0xb6785b78 AdvancedCrimeEnjoyor | 1 T5/7702, mal ?, medium | B |
| G321 | eth | 1 T1/NCD 0 | 0 NONE | 0x2a5894ea; nonce 8→9, code trước tx `0x` | 1 T5/7702, mal ?, medium | không ai (A đúng is_misuse) |
| G502 | eth | 1 T5/7702 1 | 0 NONE | 0x4b4e9179 (họ schaubb). Trong tx, Rarible ERC-1155 id 466177 ×32700 chuyển tới đích cứng 0xb9cc2d5c… | 1 T5/7702, mal 1, medium | A |

Các mẫu BSC có số dư 0→0 nên không thấy tài sản bị chuyển trong tx. Vì vậy `malicious = ?`.


## Nhóm 2: code và chain khác, 5 mẫu

| Mẫu | Chain | A | B | Kiểm on-chain | Vàng đề xuất | Đúng |
|---|---|---|---|---|---|---|
| G318 | bsc | 1 T1/NCD | 1 T4/NCD base | Gọi approve() tới địa chỉ không code trên BSC. Base có code từ 2025-02-09 18:13:33, trước tx (2025-02-13). | 1 T4/NCD, xc base, mal 0, high | B |
| G489 | eth | 1 T1/NCD | 1 T4/NCD base | Gọi approve() tới địa chỉ không code trên ETH. Base có code từ 2024-10-11 01:27:15, trước tx (2024-12-30). | 1 T4/NCD, xc base, mal 0, high | B |
| G466 | eth | 1 T1/NCD 0 | 0 NONE | Archive getCode(block-1) = `0x`: code đã mất trước tx, nên đi bước B. Gọi setApprovalForAll, không có contract cùng địa chỉ ở chain khác. | 1 T1/NCD, mal 0, medium | A |
| G617 | bsc | 1 T4/NCD eth | 0 NONE | getCode(block-1) = `0x`, nên đi bước B. Contract cùng địa chỉ trên ETH được tạo trước tx. | 1 T4/NCD, xc eth, mal 0, medium | A |
| G370 | eth | 1 T2 1 | 0 NONE | depositETH2() trên proxy đang hoạt động (code từ 2021-08-22). 0,02 ETH được chuyển tiếp theo đúng logic nạp. Contract đúng, gọi đúng hàm (bước C). | 0 NONE, medium | B |

Ở G466 và G617, cột `code_at_event = destroyed` của workbook gây hiểu nhầm. Archive cho thấy code đã bị huỷ **trước** tx, nên áp dụng bước B, không phải bước C.

## Nhóm 3: đếm rút nhanh và nhãn ví (D2, ca 7), 9 mẫu

Lịch sử đầy đủ lấy ở cả ba nguồn: giao dịch thường, token và NFT, cùng giao dịch nội bộ. Ứng viên được lọc với ngưỡng ≤ 10 phút và tỉ lệ 0,85–1,02. Sau đó từng ứng viên được kiểm tay theo D2.

| Mẫu | Chain | A | B | Kiểm on-chain | Vàng đề xuất | Đúng |
|---|---|---|---|---|---|---|
| G357 | eth | 0 NONE | 1 T5/KEY | Mọi lần ra đều về 0x28c6c062…1d60, ví mang nhãn Binance 14 (ca 7a), nên không phải ví lạ. | 0 NONE, medium | A |
| G526 | eth | 0 NONE | 1 T5/KEY | Như G357: tiền ra về Binance 14 (ca 7a). | 0 NONE, medium | A |
| G520 | eth | 0 NONE | 1 T5/KEY | Địa chỉ nạp OKX, tiền ra về ví nóng OKX (ca 7a). | 0 NONE, medium | A |
| G347 | bsc | 1 T5/KEY | 0 NONE | Có 0 lần rút nhanh. Các ứng viên đều nhận lại tài sản trong cùng tx (swap). Tx mẫu là inscription "data". | 0 NONE, medium | B |
| G328 | eth | 0 NONE | 1 T5/KEY | Chỉ 1 lần rút nhanh đạt. Ứng viên thứ hai có lượng ra lớn hơn lượng vào trong cùng tx, nên bị loại. Ủy quyền 0x8d190c8a chỉ có sau tx. | 0 NONE, low, "1 lần rút nhanh" | A |
| G541 | bsc | 0 NONE | 1 T5/KEY | 2 lần rút nhanh tới ví lạ (ca 7c và 7d). | 1 T5/KEY, mal 1, low | B |
| G440 | eth | 0 NONE | 1 T5/KEY | Lần 1: được nạp gas rồi token NOTHING bị rút ra ví lạ. Lần 2: NFT DOG được mint rồi chuyển đi ngay trong cùng tx. Ủy quyền 0x8a67b502 chỉ có sau tx. | 1 T5/KEY, mal 1, low (nghiêng) | B |
| G624 | bsc | 1 T5/KEY | 0 NONE | Có nhiều cặp vào và ra tới ví không nhãn, và không nhận lại tài sản. Ví đích bận, trông như dịch vụ, nhưng không kiểm được nhãn (BscScan bị Cloudflare chặn). Theo ca 7c, vẫn tính là ví lạ. | 1 T5/KEY, mal 1, low (nghiêng) | A |
| G742 | bsc | 1 T5/KEY | 0 NONE | Tx mẫu có calldata 32 byte, không phải gọi hàm (ca 10). USDT bị rút ra contract 0x00b93851 qua `depositTo(address,address,uint256)`. CIOTX bị rút ra contract 0x797f1465. Không nhận lại tài sản. Đây là router/bridge, nên theo ca 7d vẫn tính. | 1 T5/KEY, mal 1, low (nghiêng) | A |

## Tóm tắt

- Nhãn vàng is_misuse: 18 mẫu là 1, 6 mẫu là 0.
- So với nhãn vàng (is_misuse + type):
  - B đúng 14/24.
  - A đúng 9/24.
  - G321: không ai đúng hoàn toàn. A đúng is_misuse nhưng sai type.
- Ba ca phán đoán (G440, G624, G742) đều `low`. Cần đưa vào phân tích độ nhạy ca 7, cùng với G541.
- Nguyên nhân bất đồng:
  1. **Bỏ sót ủy quyền 7702 nằm trong chính tx mẫu.** Gặp ở 10 mẫu; người gán xét delegate cũ hoặc delegate hôm nay.
  2. **Nhãn sàn.** Blockscout không có nhãn sàn, nên B tính tiền ra ví sàn là rút nhanh (G357, G526, G520).
  3. **Cột `destroyed` của workbook.** Không cho biết code bị huỷ trước hay sau tx (G466, G617).
  4. **Tiền vào và ra trong cùng tx.** Ca này mơ hồ (G328, G440).
  5. **Ca 7c/7d chặt.** Ví dịch vụ chưa có nhãn bị tính là ví lạ (G624, G742, G541).

## Duyệt

- [x] B (người dùng) duyệt đề xuất (2026-11-05).
- [x] A xác nhận đồng ý toàn bộ (2026-11-05, người dùng báo trong chat). Nhãn vàng 24 mẫu chốt theo cột "Vàng đề xuất".
