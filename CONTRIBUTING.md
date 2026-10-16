# Quy ước làm việc nhóm

Áp dụng cho mọi thành viên (và trợ lý AI nếu có dùng).

## Trước khi bắt đầu một buổi làm việc

1. `git pull` để lấy bản mới nhất. Nếu `requirements.txt` thay đổi, chạy lại `.venv\Scripts\python.exe -m pip install -r requirements.txt`. Nếu không, test sẽ báo lỗi import, ví dụ thiếu `Crypto` (pycryptodome).
2. Đọc [docs/PROGRESS.md](docs/PROGRESS.md) để biết đang làm tới đâu, ai đang làm gì và việc nào đang chờ.
3. Đọc [docs/GOALS.md](docs/GOALS.md). Đây là mục tiêu cố định của đề tài; **không tự ý đổi hướng paper** khi chưa thống nhất cả nhóm.
4. Cần chi tiết thì đọc [docs/PLAN_V2.md](docs/PLAN_V2.md) (kế hoạch) và [docs/FINDINGS_LOG.md](docs/FINDINGS_LOG.md) (phát hiện).

## Trong khi làm

- Mỗi khi xong một bước, chạy xong một tác vụ dài hoặc chốt một quyết định, cập nhật `docs/PROGRESS.md`:
  - checklist,
  - nhật ký (mới nhất ở trên),
  - mục "Đang làm / bước kế tiếp",
  - ngày cập nhật.

  Commit cập nhật này **cùng** với code liên quan.
- Phát hiện có thể đưa vào paper thì ghi vào `docs/FINDINGS_LOG.md`, kèm lệnh để tái tạo.
- Dùng Python trong venv: `.venv\Scripts\python.exe` (Windows) hoặc `.venv/bin/python`. Thêm `-X utf8` khi lệnh in ra tiếng Việt.
- `data/Address-Misuse/` là dữ liệu gốc của tác giả, **chỉ đọc**, không sửa.
- Chạy `pytest` trước khi push; tất cả test phải pass.

## Bảo mật và đạo đức

- **Không bao giờ** đưa private key, API key, URL RPC có key hay file JSON của GCP vào code, commit, tài liệu hoặc chat. Key chỉ để trong `.env`, file này đã được ignore.
- Không dùng private key (kể cả key bị lộ công khai) để ký hay chuyển tài sản. Chỉ phân tích thụ động.
- Khi trích địa chỉ cá nhân trong paper hay slide, ẩn bớt một phần (ví dụ `0xf39f…2266`).
- Trước khi commit, chạy `git status` và `git diff --cached` để chắc không có file bí mật.

## Git

- Nhánh chính: `main`. Việc lớn nên làm trên nhánh riêng (`feature/<tên-việc>`) rồi mở Pull Request.
- Commit message ngắn gọn, nói rõ đã làm gì (tiếng Việt hoặc tiếng Anh đều được).
- File lớn (> 50 MB) và dữ liệu tạo lại được thì không commit; xem bảng "Cái gì có trong repo" trong [README.md](README.md).
