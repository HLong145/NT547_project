"""Đánh số tài liệu theo thứ tự trích dẫn đầu tiên trong main.tex.

    python paper/make_bibliography.py

`splncs04.bst` luôn xếp theo tên tác giả, nên script này tự dựng khối `thebibliography`
(định dạng như splncs04) từ references.bib theo thứ tự xuất hiện của \\cite, ghi vào main.tex
giữa hai dòng đánh dấu, và xếp lại khoá trong từng \\cite{a,b} để số tăng dần.
Sửa references.bib hoặc thêm/bớt \\cite xong thì chạy lại script.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEX, BIB = HERE / "main.tex", HERE / "references.bib"
BEGIN, END = "% BEGIN GENERATED BIBLIOGRAPHY (paper/make_bibliography.py)", "% END GENERATED BIBLIOGRAPHY"


def parse_bib(text: str) -> dict:
    out, i = {}, 0
    while True:
        m = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,").search(text, i)
        if not m:
            return out
        fields, i = {"_type": m.group(1).lower()}, m.end()
        while True:
            f = re.compile(r"\s*(\w+)\s*=\s*\{").match(text, i)
            if not f:
                break
            depth, j = 1, f.end()
            while depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            fields[f.group(1).lower()] = re.sub(r"\s+", " ", text[f.end():j - 1]).strip()
            i = re.compile(r"\s*,?").match(text, j).end()
        out[m.group(2)] = fields


def strip_braces(s: str) -> str:
    """Bỏ ngoặc nhóm, giữ ngoặc là đối số của lệnh (\\'{c}, \\url{...})."""
    res, stack, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            m = re.compile(r"\\([a-zA-Z]+|.)").match(s, i)
            res.append(m.group(0))
            i = m.end()
            if i < len(s) and s[i] == "{":
                stack.append(True), res.append("{")
                i += 1
            continue
        if c == "{":
            stack.append(False)
        elif c == "}":
            if stack.pop():
                res.append("}")
        else:
            res.append(c)
        i += 1
    return "".join(res)


def title_case(s: str) -> str:
    """Như change.case$ "t" của BibTeX: hạ chữ thường, trừ ký tự đầu, ký tự sau ': ' và phần trong {}."""
    res, depth, keep = [], 0, True
    for k, c in enumerate(s):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        if depth == 0 and c.isalpha():
            res.append(c if keep else c.lower())
            keep = False
        else:
            res.append(c)
            if c.isalpha():
                keep = False
            elif c == ":" and s[k + 1:k + 2] == " ":
                keep = True
    return strip_braces("".join(res))


def authors(s: str) -> str:
    names = []
    for a in re.split(r"\s+and\s+", s):
        if a.startswith("{") and a.endswith("}"):
            names.append(a[1:-1])
            continue
        last, first = [x.strip() for x in a.split(",", 1)]
        initials = "".join(p[0] + "." for p in re.split(r"[\s\-]+", first) if p)
        names.append(f"{strip_braces(last)}, {initials}")
    return ", ".join(names)


def link(e: dict) -> str:
    if "doi" in e:
        return f". \\url{{https://doi.org/{e['doi']}}}"
    return f", \\url{{{e['url']}}}" if "url" in e else ""


def fmt(e: dict) -> str:
    head = f"{authors(e['author'])}: {title_case(e['title'])}."
    pages = e.get("pages", "").replace("--", "--")
    if e["_type"] == "inproceedings":
        s = f"{head} In: {e['booktitle']}."
        if pages:
            s += f" pp.~{pages}."
        pub = f"{e['series']}, {e['publisher']}" if "series" in e else e["publisher"]
        return f"{s} {pub} ({e['year']}){link(e)}"
    if e["_type"] == "article":
        return f"{head} {e['journal']} \\textbf{{{e['volume']}}}({e['number']}), {pages} ({e['year']}){link(e)}"
    s = f"{head} {e['howpublished']} ({e['year']})"
    return s + (f", {e['note']}" if "note" in e else "")


def main():
    tex = TEX.read_text(encoding="utf-8").replace("\r\n", "\n")
    bib = parse_bib(BIB.read_text(encoding="utf-8"))
    body = tex.split(BEGIN)[0]
    order = []
    for m in re.finditer(r"\\cite\{([^}]*)\}", body):
        for k in (x.strip() for x in m.group(1).split(",")):
            if k not in order:
                order.append(k)
    missing = [k for k in order if k not in bib]
    if missing:
        sys.exit(f"missing in references.bib: {missing}")
    num = {k: i + 1 for i, k in enumerate(order)}

    def resort(m):
        keys = sorted((x.strip() for x in m.group(1).split(",")), key=num.get)
        return "\\cite{" + ",".join(keys) + "}"

    body = re.sub(r"\\cite\{([^}]*)\}", resort, body)
    items = "\n\n".join(f"\\bibitem{{{k}}}\n{fmt(bib[k])}" for k in order)
    block = f"{BEGIN}\n\\begin{{thebibliography}}{{{len(order)}}}\n\n{items}\n\n\\end{{thebibliography}}\n{END}\n"
    if BEGIN in tex:
        tail = tex.split(END, 1)[1].lstrip("\n")
        new = body + block + tail
    else:
        old = "\\bibliographystyle{splncs04}\n\\bibliography{references}\n"
        if old not in body:
            sys.exit("cannot find \\bibliography lines in main.tex")
        new = body.replace(old, block)
    TEX.write_text(new, encoding="utf-8", newline="\n")
    print(f"{len(order)} references numbered by first citation; unused bib entries: "
          f"{sorted(set(bib) - set(order)) or 'none'}")
    for k in order:
        print(f"{num[k]:>2} {k}")


if __name__ == "__main__":
    main()
