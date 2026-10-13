"""Tải dữ liệu + code gốc của Shao et al. từ Zenodo về data/Address-Misuse/ và kiểm tra SHA-256.

python -m address_misuse.fetch_author_data            # tải (~250 MB) + giải nén + kiểm tra
python -m address_misuse.fetch_author_data --verify   # chỉ kiểm tra bản đã có

Dữ liệu không đưa lên git (444 MB sau giải nén; giấy phép CC BY 4.0, nguồn: Zenodo 17984167).
Mã băm đối chiếu lấy từ data/seed/MANIFEST.json (được commit) → đảm bảo mọi người dùng đúng một bản dữ liệu.
"""

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

import requests

from address_misuse.config import AUTHOR_DIR, RAW_DIR, SEED_DIR

ZENODO_URL = "https://zenodo.org/records/17984167/files/Address-Misuse.zip?download=1"
ZIP_SIZE = 247_614_942


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size == ZIP_SIZE:
        print(f"Đã có {dest}")
        return dest
    tmp = dest.with_suffix(".part")
    with requests.get(ZENODO_URL, stream=True, timeout=(10, 120)) as r:
        r.raise_for_status()
        done = 0
        with tmp.open("wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                done += len(chunk)
                print(f"\r  {done / 2**20:6.0f} / {ZIP_SIZE / 2**20:.0f} MB", end="", flush=True)
    print()
    if tmp.stat().st_size != ZIP_SIZE:
        raise RuntimeError(f"Kích thước tải về {tmp.stat().st_size} != {ZIP_SIZE}")
    tmp.replace(dest)
    return dest


def extract(zip_path: Path, target: Path):
    """Giải nén vào target, bỏ thư mục gốc chung (vd. Address-Misuse/) trong zip và các file rác của macOS."""
    root = target.resolve()
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if not n.startswith("__MACOSX/") and not n.endswith("/")]
        tops = {n.split("/", 1)[0] for n in names}
        prefix = f"{tops.pop()}/" if len(tops) == 1 and "/" in names[0] else ""
        for n in names:
            out = (root / n[len(prefix):]).resolve()
            if not out.is_relative_to(root):          # chặn đường dẫn kiểu ../ trong zip
                raise RuntimeError(f"Đường dẫn không hợp lệ trong zip: {n}")
            out.parent.mkdir(parents=True, exist_ok=True)
            with z.open(n) as src, out.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def verify() -> bool:
    manifest = json.loads((SEED_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    bad = []
    for s in manifest["sources"]:
        p = AUTHOR_DIR / s["path"]
        if not p.exists() or p.stat().st_size != s["bytes"] or _sha256(p) != s["sha256"]:
            bad.append(s["path"])
    print(f"Kiểm tra {len(manifest['sources'])} file nguồn: " + ("OK" if not bad else f"{len(bad)} file sai/thiếu"))
    for b in bad[:10]:
        print("  ", b)
    return not bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="chỉ kiểm tra, không tải")
    ap.add_argument("--keep-zip", action="store_true", help="giữ file zip trong data/raw/ sau khi giải nén")
    a = ap.parse_args()
    if not a.verify:
        zip_path = download(RAW_DIR / "Address-Misuse.zip")
        print(f"Giải nén vào {AUTHOR_DIR} ...")
        extract(zip_path, AUTHOR_DIR)
        if not a.keep_zip:
            zip_path.unlink()
    sys.exit(0 if verify() else 1)


if __name__ == "__main__":
    main()
