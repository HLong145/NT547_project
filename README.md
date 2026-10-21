# Address Misuse — Cross-Chain & Wallet-Side Warning

Đề tài (môn NT547): phát hiện địa chỉ hợp đồng/EOA bị dùng sai (Address Misuse) trên EVM, tái lập một phần nghiên cứu của Shao et al. (USENIX Security 2026) và cải tiến bằng kiểm tra nhất quán địa chỉ xuyên chuỗi (cross-chain), risk score và cảnh báo phía ví.

- **Tiến độ (đọc đầu tiên):** [docs/PROGRESS.md](docs/PROGRESS.md) · Mục tiêu cố định: [docs/GOALS.md](docs/GOALS.md)
- Yêu cầu gốc: [docs/requirements.md](docs/requirements.md) · Kế hoạch: [docs/PLAN_V2.md](docs/PLAN_V2.md)
- Phát hiện cho paper: [docs/FINDINGS_LOG.md](docs/FINDINGS_LOG.md) · Risk score: [docs/RISK_SCORE.md](docs/RISK_SCORE.md) · Dữ liệu: [data/README.md](data/README.md)
- Lấy API key / BigQuery / RPC: [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)

## Bắt đầu sau khi clone (Windows PowerShell)

Cần Python 3.12+ và khoảng 2 GB ổ đĩa trống.

```powershell
git clone https://github.com/HLong145/NT547_project.git
cd NT547_project

# 1. Môi trường Python
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip install -e .

# 2. Dữ liệu gốc của tác giả (~250 MB tải từ Zenodo, ~444 MB sau giải nén), có kiểm tra SHA-256
.venv\Scripts\python.exe -X utf8 -m address_misuse.fetch_author_data

# 3. Tạo bảng seed Parquet từ dữ liệu tác giả (~15 giây)
.venv\Scripts\python.exe -X utf8 -m address_misuse.seed

# 4. Kiểm tra: phải thấy "39 passed" (seed khớp số liệu trong paper)
#    Sau mỗi lần pull mà requirements.txt đổi: chạy lại lệnh pip install -r ở bước 1
.venv\Scripts\python.exe -m pytest

# 5. Cấu hình key (tuỳ chọn, cần cho bước kéo dữ liệu on-chain)
copy .env.example .env      # rồi điền theo docs/SETUP_GUIDE.md
```

Paper gốc không có trong repo vì lý do bản quyền. Tải `usenixsecurity26-shao-zhenzhe.pdf` từ trang USENIX Security '26 rồi đặt vào `docs/`.

**macOS/Linux:** thay `.venv\Scripts\python.exe` bằng `.venv/bin/python` và `copy` bằng `cp`.

## Cái gì có trong repo, cái gì không

| Có trên git | Không có, tự tạo lại |
|---|---|
| Code `src/`, test `tests/`, tài liệu `docs/` | `data/Address-Misuse/`: chạy `fetch_author_data` |
| `data/seed/MANIFEST.json` (mã băm để kiểm tra) | `data/seed/*.parquet`: chạy `seed` |
| Kết quả nhỏ trong `data/interim/`: `crosschain_pilot`, `crosschain_matrix`, `rules_repro_eth`, `symexec_repro`, `n1_random_unflagged`, `n6_benign_7702_delegates`, `n7_multichain_contracts` (`.parquet`) | `data/raw/` (cache giao dịch, getCode, creation), `data/gold/*_key.csv` (đáp án pilot, không commit), phần còn lại của `data/interim/` |
| `.env.example` | `.env`: **chứa key, không bao giờ commit** |

## Cấu trúc

```text
project/
├── src/address_misuse/       # Code chính
│   ├── config.py             # Đường dẫn, chain, RPC, đọc .env
│   ├── fetch_author_data.py  # Tải dữ liệu tác giả từ Zenodo và kiểm tra
│   ├── seed.py               # Dữ liệu tác giả -> data/seed/*.parquet
│   ├── etherscan.py          # Client Etherscan API V2 (thay onchain_fetcher của tác giả)
│   ├── rules.py              # Rule CA/EOA Misuse (port Algorithm 1–3, trả về từng tx)
│   ├── symexec/              # Symbolic execution của tác giả, đã chạy được trên Windows
│   ├── reproduce_symexec.py  # So kết quả symexec với tác giả
│   ├── reproduce_rules.py    # Kéo tx thô qua Etherscan, chạy rules.py, so với CSV tác giả (pilot 500 ETH)
│   ├── crosschain.py         # Kiểm tra cross-chain (getCode song song nhiều chain)
│   ├── crosschain_pilot.py   # Pilot cross-chain trên NCD thiệt hại lớn nhất
│   ├── crosschain_matrix.py  # D3: ma trận CA Misuse × 8 mạng, nguồn gốc contract, khả năng deploy lại
│   ├── known_multichain.py   # Tập âm N7: contract hợp lệ cùng địa chỉ trên nhiều chain
│   ├── negatives.py          # Tập âm N1 (ngẫu nhiên không bị gắn cờ), N6 (ví EIP-7702 hợp lệ)
│   └── sample_gold.py        # D5: lấy mẫu pilot gán nhãn (làm mù, có bằng chứng) và tính Cohen's κ
├── tests/                    # pytest
├── data/                     # Xem data/README.md
└── docs/                     # Mục tiêu, tiến độ, kế hoạch, phát hiện, lý thuyết, slide
```

## Lệnh hay dùng

```powershell
# Kiểm tra cross-chain một giao dịch (không cần API key)
.venv\Scripts\python.exe -X utf8 -m address_misuse.crosschain 0x7a250d5630b4cf539739df2c5dacb4c659f2488d --chain bsc --data 0x7ff36ab5
.venv\Scripts\python.exe -X utf8 -m address_misuse.crosschain_pilot --top 100
.venv\Scripts\python.exe -X utf8 -m address_misuse.known_multichain                 # tập âm N7 (~1 phút)
.venv\Scripts\python.exe -X utf8 -m address_misuse.negatives n1                     # tập âm N1 (400 địa chỉ)
.venv\Scripts\python.exe -X utf8 -m address_misuse.negatives n6                     # tập âm N6 (kiểm chứng qua Blockscout)

# Gán nhãn vàng D5 (cần crosschain_matrix.parquet); file mẫu đã làm mù ra data/gold/; file *_key.csv không commit
.venv\Scripts\python.exe -X utf8 -m address_misuse.sample_gold pilot
.venv\Scripts\python.exe -X utf8 -m address_misuse.sample_gold kappa data/gold/annotator_A.csv data/gold/annotator_B.csv

# Ma trận cross-chain D3: code (RPC, không cần key) → origin (Etherscan key; BSC qua Binplorer) → timing → build. Có cache, chạy lại sẽ tiếp tục
.venv\Scripts\python.exe -X utf8 -m address_misuse.crosschain_matrix all
.venv\Scripts\python.exe -X utf8 -m address_misuse.crosschain_matrix build          # chỉ ghép lại từ cache data/raw/crosschain/

# Tái lập rule trên giao dịch thô (cần Etherscan key)
.venv\Scripts\python.exe -X utf8 -m address_misuse.reproduce_rules --chain eth --n-ncd 350 --n-pcd 100 --n-key 50 --n-addr 50 --n-big 30   # + EOA ADDR, CA n_tx > 5.000
.venv\Scripts\python.exe -X utf8 -m address_misuse.reproduce_rules --chain eth --summary-only

# Kiểm tra Etherscan key hỗ trợ chain nào (cần .env)
.venv\Scripts\python.exe -X utf8 -m address_misuse.etherscan

# Chạy lại symbolic execution so với tác giả (~1–2 giờ, RAM ≤ 1 GB)
.venv\Scripts\python.exe -X utf8 -m address_misuse.reproduce_symexec --workers 2 --max-mem-mb 400
.venv\Scripts\python.exe -X utf8 -m address_misuse.reproduce_symexec --summary-only
```

## Quy ước làm việc nhóm

Xem [CONTRIBUTING.md](CONTRIBUTING.md). Tóm tắt: đọc và cập nhật `docs/PROGRESS.md`, không commit key, không sửa dữ liệu tác giả, chạy `pytest` trước khi push.

## Nguồn và giấy phép

Dữ liệu và code gốc: Shao et al., *Lost in Blockchain: Address Misuse — Hidden Cross-Platform Risks and Their Security Impact*, USENIX Security 2026. Zenodo [17984167](https://zenodo.org/records/17984167), giấy phép CC BY 4.0. Code trong `src/address_misuse/symexec/` được chỉnh sửa từ code của tác giả.
