# Bảng phân xử cổng κ 50 mẫu đầu (gán đôi)

Ngày 2026-10-30. κ(`is_misuse`) = 0,692 (< 0,70), đồng ý 43/50. 7 mẫu bất đồng. Cột "Kiểm chứng" là sự thật tôi (người điều phối) kiểm trên chuỗi, **không dùng nhãn của tác giả**. "Đề xuất" chỉ là gợi ý; nhãn cuối do A, B và người điều phối thống nhất.

Tóm tắt: A đúng ở G033, G184; B đúng ở G110 (kết quả), G157, G173, G177; G068 tuỳ quyết định quy tắc. Lỗi hai phía là **quy trình**, không phải do chọn bừa: B hay chỉ xét tx mẫu mà bỏ qua lịch sử; A bỏ sót NFT, bỏ qua tỉ lệ rút sau phí gas, và có thể chưa có bảng delegate cuối.

| Mẫu | A | B | Đề xuất | Link |
|---|---|---|---|---|
| G033 | 1/T5 | 0/NONE | A đúng (1/T5) | [tx](https://bscscan.com/tx/0x76d5c812f3f4b4bbf672b45afacc9952fd40d92e9e03bfeb58662266cf395812) · [địa chỉ](https://bscscan.com/address/0x1c87c368c9a8b23236777cef6f45304af767a712) |
| G068 | 1/T5 | 0/NONE | Phụ thuộc quy tắc (đề xuất A1) | [tx](https://etherscan.io/tx/0x8cc597ae24b8cf2f13ec27879c17aac4b19aea24c21c18d5cc3b2e22f3cf9a01) · [địa chỉ](https://etherscan.io/address/0x40e6b7ff1c2ea4d1706c4d66f311572985719493) |
| G110 | 0/NONE | 1/T5 | B đúng về kết quả (1/T5), nhưng ghi chú của B sai | [tx](https://etherscan.io/tx/0x48e767fdf0163cb759e6d4f4b86e35f44f0545e215d20ace62b11e50041ebc1e) · [địa chỉ](https://etherscan.io/address/0x63eb3fd749fdd727a3433d4a96c86c66ed72a578) |
| G157 | 1/T5 | 0/NONE | B đúng (0/NONE) | [tx](https://etherscan.io/tx/0x5ba62f75510934b8aa950c9be053114bb3f975a80e0e3eb69fdcccf8746c930d) · [địa chỉ](https://etherscan.io/address/0x7963a74a27221fb7534f4fc0113d7f5e9f33567b) |
| G173 | 0/NONE | 1/T5 | B đúng (1/T5) | [tx](https://etherscan.io/tx/0x1045b4310eff7e4082131312031ef6fd846ebcea008f5e369067864d418b20bd) · [địa chỉ](https://etherscan.io/address/0xa7366dbffc6518a5c6e7c14e120da809c12775a1) |
| G177 | 0/NONE | 1/T5 | B đúng (1/T5) | [tx](https://etherscan.io/tx/0x5d449c3367476519142f1a9f2747eea2ac3c7b43569fde68e2ead2d54d6d0493) · [địa chỉ](https://etherscan.io/address/0xb191a13bfe648b61002f2e2135867015b71816a6) |
| G184 | 1/T5 | 0/NONE | A đúng (1/T5) | [tx](https://bscscan.com/tx/0xe27eb19315ab29606c9934ad6a1683c5c3d1f4f09bc217b7e4a2477abbe80a0e) · [địa chỉ](https://bscscan.com/address/0x7978016c365d4e57a5682dcf7137aa2a0276e016) |

## G033
- **A:** 1/T5, ghi chú: auth delegate 0xa54643ba3b553c7bdd5790ddeb1faed745f7d87b (không có trong bảng); schaubbSweep: 100 DDM vào 09:53:20 bị chuyển 100 DDM sang 0xcc04506d… lúc 09:53:21
- **B:** 0/NONE, ghi chú: Delegate lúc tx 0xa54643ba3b553c7bdd5790ddeb1faed745f7d87b (không có trong bảng; ca 13c): gọi schaubbSweep nhưng không có token/native rời ví
- **Kiểm chứng:** Ủy quyền trong chính tx (authorizationList) tới `0xa54643ba3b553c7bdd5790ddeb1faed745f7d87b` (không có trong bảng, coi như `unknown`, ca 13c). Tx mẫu không chuyển gì, nhưng lịch sử có **2 lần rút nhanh 100%**: 2026-04-03 00:03:34 vào và ra cùng giây 0,0005 (token ETH trên BSC) tới `0x91163366…`; 2026-10-11 09:53:20 vào 100 DDM, 1 giây sau ra 100 DDM tới `0xcc04506d…`. Đủ ≥ 2 lần ở bước D2. B chỉ xét tx mẫu, chưa đếm lịch sử.
- **Đề xuất:** A đúng (1/T5). Việc sửa codebook liên quan: Bước D2 luôn đếm cả lịch sử, kể cả khi tx mẫu không chuyển gì (đề xuất A4).

## G068
- **A:** 1/T5, ghi chú: ≥2 lần rút nhanh: 2.36116611 ETH vào 08:00:35 → 2.3 ETH tới 0xdef1c0de… (0x Exchange Proxy) sau 156s; 0.5762204 → 0.549 tới 0xb2ecfe4e… (Blur) sau 216s — đích router/DEX (ca 7d)
- **B:** 0/NONE, ghi chú: Ví DeFi hoạt động; không có cặp rút nhanh quanh tx
- **Kiểm chứng:** Cả hai lần A nêu đều có thật (2,36117 vào → 2,3 ETH tới `0xdef1c0de…` 0x Exchange Proxy sau 156 giây; 0,5762 vào → 0,549 tới `0xb2ecfe4e…` Blur sau 216 giây). Nhưng đây là ví giao dịch DeFi/NFT hoạt động: nhiều lần chuyển 90–98% tới Uniswap Universal Router `0x3fc91a3a…`, 0x, Blur, trong tx có nhận lại token (ví dụ Blur Pool). Theo chữ của codebook v0.6.2 (ca 7d: router vẫn tính) thì = 1, `low`. Theo đề xuất A1 (swap/mint/stake có nhận lại tài sản cùng tx thì không phải rút) thì = 0.
- **Đề xuất:** Phụ thuộc quy tắc (đề xuất A1). Việc sửa codebook liên quan: Quyết định A1 (xem file đề xuất).

## G110
- **A:** 0/NONE, ghi chú: chuyển tiếp ~85% mỗi khoản trong ~12s (dưới ngưỡng 90%), không có lần rút nhanh; delegate hôm nay 0x1ee2… chỉ có sau tx
- **B:** 1/T5, ghi chú: ≥2 lần rút nhanh: 2024-01-31 nhận 2,6 ETH → 2,59958 ETH (99,98%) sang 0xbf94f0ac sau 2m24s; 2026-02-21 10:56:35 nhận 3,837e-6 → gửi 4,036e-6 cùng giây sang 0x2932d01b; chuỗi sweep ~85% sang 0x107a4596; delegate hiện tại 0x1ee2581d34819de3d77715c758d8d0c525332492 (forwarder_sweeper)
- **Kiểm chứng:** Ví nhận ~2,52e-5 ETH rồi 12 giây sau gửi 2,14e-5 tới `0x107a4596…`, lặp **hàng chục lần** trong 26 phút. Tỉ lệ 85% chỉ vì phí gas: kiểm 2 tx rút, **giá trị + phí gas = đúng bằng khoản vào** (2,52229e-5), tức rút sạch số dư. Ước đếm sơ bộ cho thấy lịch sử còn có token chuyển 100% (VPAD 2021-12-22, DAI 2023-06-23), cần xem tay. **Lưu ý:** B ghi lần rút 2,6 ETH → `0xbf94f0ac` ngày 2024-01-31; **không tìm thấy** giao dịch nào như vậy trong lịch sử ví này (không có khoản ≥ 0,26 ETH nào từ 2024, không có địa chỉ `0xbf94f0ac`): B cần xem lại ghi chú (có thể dán nhầm từ mẫu khác). A tính 85% < 90% nên bỏ qua.
- **Đề xuất:** B đúng về kết quả (1/T5), nhưng ghi chú của B sai. Việc sửa codebook liên quan: Tính lượng rút cộng phí gas (đề xuất A2).

## G157
- **A:** 1/T5, ghi chú: 2 lần rút nhanh: 0.142 → 0.14 ETH tới 0x1f75881d… sau 276s (98.6%); 0.32878621 → 0.4 ETH tới 0xe86142af… sau 216s
- **B:** 0/NONE, ghi chú: Khoản 0,142 ETH vào ElixirDeposit sau 4,5 phút (contract, không phải ví lạ); còn lại stake/bridge bình thường
- **Kiểm chứng:** Chỉ có 1 lần rút nhanh hợp lệ: 0,142 vào → 0,14 ra (98,6%) sau 276 giây là lệnh `deposit()` (`0xd0e30db0`) vào contract `0x1f75881d…`. Lần thứ hai A nêu (0,328786 vào → 0,4 ra) **vượt** khoản vào (122%), là lệnh mint `0x46f45b8d` nhận lại token yaySTO cùng tx; không phải ≥ 90% của khoản vào đó và có nhận lại tài sản. Còn lại là stake/bridge bình thường. 1 lần → NONE `low`.
- **Đề xuất:** B đúng (0/NONE). Việc sửa codebook liên quan: Thêm điều kiện: khoản ra không vượt khoản vào, và tx nhận lại tài sản thì không tính (A1).

## G173
- **A:** 0/NONE, ghi chú: tx aggregate, ủy quyền tới 0x664f4f97329d7a19f99cf01a1b213d5c98ba9a94 (không có trong bảng); tx không chuyển tiền/token (ca 13c)
- **B:** 1/T5, ghi chú: Delegate lúc tx 0x664f4f97329d7a19f99cf01a1b213d5c98ba9a94 (không có trong bảng; ca 13c); aggregate transferFrom đưa NFT sang 0x575a45f4361e937551b05f5287e21069532b2f0e
- **Kiểm chứng:** Tx mẫu do bên thứ ba `0x63556e77…` gửi, ủy quyền (authorizationList) tới `0x664f4f97329d7a19f99cf01a1b213d5c98ba9a94` (không có trong bảng → `unknown`). Trong tx này **NFT "CH" bị chuyển từ ví sang `0x575a45f4…`** (tab NFT Transfers), không có gì quay lại. A viết "không chuyển tiền/token" vì codebook chỉ nói coin hoặc token, chưa nói NFT.
- **Đề xuất:** B đúng (1/T5). Việc sửa codebook liên quan: Ghi rõ NFT (ERC-721/1155) cũng là tài sản (đề xuất A3).

## G177
- **A:** 0/NONE, ghi chú: tx là lần ủy quyền tới 0x2c6f01799fa9db1e7f2797e5ba892b72b865571d (không có trong bảng); không chuyển tiền, chưa thấy rút (ca 13c)
- **B:** 1/T5, ghi chú: Delegate lúc tx 0x2c6f01799fa9db1e7f2797e5ba892b72b865571d (forwarder_sweeper); 0x6918609b không thấy ETH/token rời ví trong tx
- **Kiểm chứng:** Ủy quyền trong chính tx (authorizationList) tới `0x2c6f01799fa9db1e7f2797e5ba892b72b865571d`. Địa chỉ này **có trong bảng delegate** với `final_class = forwarder_sweeper` (chốt 2026-10-29). Theo ca 13b → T5/7702 dù tx mẫu không rút gì. Lịch sử còn có 1 USDT chuyển đi cùng giây tới `0x91163366…` (cùng ví đích với G033). A ghi "không có trong bảng": có thể A chưa có bảng cuối.
- **Đề xuất:** B đúng (1/T5). Việc sửa codebook liên quan: Phát cho A bảng `delegate_lookup.csv` cuối; ghi rõ không có trong bảng = `unknown` (A5).

## G184
- **A:** 1/T5, ghi chú: tx schaubbBatch thất bại, auth 0x78c7ad39e03f05219bbd8ac6e2f2add76df89fa1; địa chỉ là forwarder 0xa19160b1b01396da5fb72927c033fd71c62d79df, đã chuyển 100% các khoản vào tới 0x02b1c6ca… (ví lạ)
- **B:** 0/NONE, ghi chú: Tx fail; delegate lúc tx 0x78c7ad39e03f05219bbd8ac6e2f2add76df89fa1 (không có trong bảng; ca 13c); schaubbBatch không chuyển tài sản
- **Kiểm chứng:** Ủy quyền trong chính tx tới `0x78c7ad39e03f05219bbd8ac6e2f2add76df89fa1` (không có trong bảng → `unknown`). Tx mẫu **fail** nên không có gì chuyển, nhưng lịch sử có nhiều lần chuyển 100% khoản vào tới `0x02b1c6ca…` trong vài giây (ví dụ 2026-02-17 11:30:02 và 11:31:28), đủ ≥ 2 lần ở bước D2. B chỉ xét tx mẫu. (A viết nhầm là delegate hôm nay `0xa19160b1…` nhưng kết luận vẫn đúng nhờ lịch sử.)
- **Đề xuất:** A đúng (1/T5). Việc sửa codebook liên quan: Như G033 (A4).

## Quyết định (2026-10-30)

Người dùng (B) đồng ý bảng này và duyệt codebook v0.6.3. Nhãn phân xử tạm cho `is_misuse` / `type` (subtype ghi sau khi A và B gán lại theo v0.6.3; nhãn vàng cuối của 50 mẫu = nhãn phân xử sau lượt gán lại):

| Mẫu | is_misuse | type | Lý do ngắn |
|---|---|---|---|
| G033 | 1 | T5 | ≥ 2 lần rút nhanh 100% trong lịch sử (D2) |
| G068 | 0 | NONE | **Chọn 0**: ví giao dịch DeFi/NFT, các khoản "rút" là swap/mua có nhận lại tài sản trong cùng tx (v0.6.3 điều 1) |
| G110 | 1 | T5 | quét sạch số dư nhiều lần, tỉ lệ 85% chỉ do phí gas (điều 2) |
| G157 | 0 | NONE | chỉ 1 lần rút hợp lệ; lần kia là mint có nhận lại token (điều 1) |
| G173 | 1 | T5 | NFT bị chuyển đi (điều 3) |
| G177 | 1 | T5 | delegate `forwarder_sweeper` trong bảng (ca 13b) |
| G184 | 1 | T5 | ≥ 2 lần chuyển 100% trong lịch sử (D2) |

Vì sao G068 = 0: nếu coi các giao dịch đó là rút thì mọi ví giao dịch tích cực sẽ thành KEY, làm nhãn dương phình ra. Lưu ý (paper): quyết định này theo điều 1 mới, chưa thấy trước khi có dữ liệu.
