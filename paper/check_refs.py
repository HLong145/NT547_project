"""Kiểm tra mọi \\cite trong main.tex đều có trong references.bib và ngược lại.

Chạy từ gốc repo: python paper/check_refs.py
"""
import re
from pathlib import Path

here = Path(__file__).parent
tex = (here / "main.tex").read_text(encoding="utf8")
bib = (here / "references.bib").read_text(encoding="utf8")
cites = {k.strip() for m in re.findall(r"\\cite\{([^}]*)\}", tex) for k in m.split(",")}
keys = set(re.findall(r"@\w+\{([^,\s]+),", bib))
missing, unused = sorted(cites - keys), sorted(keys - cites)
print(f"cite {len(cites)}, bib {len(keys)}")
print("thiếu trong bib:", missing or "không")
print("có trong bib nhưng không trích:", unused or "không")
raise SystemExit(1 if missing or unused else 0)
