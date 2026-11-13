# Bản thảo paper (Springer LNCS)

Khung bài báo theo mẫu **Springer LNCS** (`llncs.cls`). Các chỗ `\todo{...}` hiện màu đỏ là phần cần điền.

## Lấy file mẫu của Springer (không kèm trong repo)

Tải gói "LaTeX2e Proceedings Templates" ở trang hướng dẫn của Springer
(https://www.springer.com/gp/computer-science/lncs/conference-proceedings-guidelines),
rồi chép `llncs.cls` và `splncs04.bst` vào thư mục này.

**Cách dễ nhất, không cần cài LaTeX:** trên Overleaf, tạo dự án từ mẫu Springer LNCS
(đã có sẵn `llncs.cls`), rồi tải lên `main.tex` và `references.bib` của thư mục này.

## Biên dịch (nếu có LaTeX trên máy)

```
latexmk -pdf main.tex
```

Hoặc dùng **Tectonic** (một file chạy, tự tải gói TeX kể cả `llncs.cls` và `splncs04.bst`, tự chạy BibTeX):
tải bản phát hành ở https://github.com/tectonic-typesetting/tectonic/releases (đã thử 0.17.0 trên Windows), rồi

```
tectonic main.tex
```

`main.pdf` là sản phẩm dịch, không commit (đã có trong `.gitignore`).

## Quy ước

- Số liệu lấy từ [../docs/FINDINGS_LOG.md](../docs/FINDINGS_LOG.md); chỉ điền số đã có trong đó.
- Ẩn bớt địa chỉ cá nhân khi trích (`0x1234…abcd`), theo [../docs/CODEBOOK.md](../docs/CODEBOOK.md) §8.
- `references.bib`: mọi mục đã đối chiếu Crossref/USENIX/EIP (2026-11-13); chỉ dùng nguồn đã bình duyệt hoặc đặc tả chính thức.
- Trước khi nộp: bỏ `\todo`, điền tác giả thật, kiểm tra số trang theo yêu cầu hội nghị.
