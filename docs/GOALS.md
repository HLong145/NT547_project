# MỤC TIÊU ĐỀ TÀI (cố định — không tự ý đổi)

> Nguồn gốc: [requirements.md](requirements.md). Kế hoạch chi tiết: [PLAN_V2.md](PLAN_V2.md). Tiến độ: [PROGRESS.md](PROGRESS.md).
> Chỉ sửa file này khi **chủ đề tài yêu cầu**. Không đổi hướng paper (ví dụ thành "benchmark paper") — đã bị từ chối.

**Tên tạm:** *Characterizing and Mitigating Address Misuse Risks in Cross-Chain EVM Ecosystems*
**Nền tảng:** Shao et al., "Lost in Blockchain: Address Misuse", USENIX Security '26 (dữ liệu Zenodo 17984167, ở `data/Address-Misuse/`).

## Mục tiêu chính

1. **Tái lập một phần** nghiên cứu Address Misuse trên ETH/BSC (dữ liệu + rule Algorithm 1–3 + symbolic execution của tác giả).
2. **Phân loại** CA Misuse (NCD, PCD) và EOA Misuse (KEY, ADDR, EIP-7702) — taxonomy Type 1–6 trong requirements.
3. **Detector** dựa trên rule + mẫu giao dịch, **kiểm chứng bằng manual audit** (~2.000 nhãn vàng, 2 người gán, Cohen's κ ≥ 0,8; case study 50–100 ca).
4. **Cải tiến (đóng góp mới):**
   - **Cross-chain address consistency** — địa chỉ là contract ở chain này nhưng không có code ở chain đang giao dịch (Type 4, đóng góp cốt lõi).
   - **Risk score** R(A, C) ∈ [0, 100].
   - **Wallet-side warning** trước khi ký giao dịch, độ trễ < 150 ms (đề xuất: Risk Engine + MetaMask Snap; RPC proxy chỉ để đo độ trễ — *chưa chốt*).

## Thứ tự ưu tiên

1. **Hoàn thiện dataset** (D0–D8 trong PLAN_V2) ← ưu tiên số 1.
2. Detection & risk engine (Module 2) → đánh giá (Module 3).
3. Wallet-side warning (Module 4) → viết paper.

## Ràng buộc đạo đức / bảo mật

- Tuyệt đối **không** dùng private key thật để chuyển tài sản; không tải hay lưu private key — chỉ dùng địa chỉ đã suy ra.
- Phân tích thụ động; ẩn bớt địa chỉ cá nhân khi trích trong paper; responsible disclosure.
- API key chỉ để trong `.env` (đã gitignore), không dán vào chat. File JSON của GCP để ngoài thư mục dự án.
