"""Vẽ các hình của paper thành PDF vector trong paper/figures/.

    python paper/make_figures.py          # thêm --png để xuất kèm PNG xem nhanh

Số liệu: hình 2–3 lấy từ các bảng trong main.tex (nguồn docs/FINDINGS_LOG.md);
hình 4 đọc data/interim/wallet_bench_items.csv. Hình 1 là sơ đồ, không có số đo.
"""

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "paper" / "figures"
PNG = "--png" in sys.argv

W = 4.8                     # bề rộng vùng chữ LNCS (12,2 cm) tính bằng inch
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d3"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["STIXGeneral", "Times New Roman", "DejaVu Serif"],
    "mathtext.fontset": "stix", "font.size": 8, "axes.labelsize": 8, "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5, "legend.fontsize": 7.5, "axes.edgecolor": MUTED, "axes.linewidth": 0.6,
    "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK, "axes.labelcolor": INK,
    "pdf.fonttype": 42, "hatch.linewidth": 0.5, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.pdf")
    if PNG:
        fig.savefig(OUT / f"{name}.png", dpi=220)
    plt.close(fig)
    print("saved", OUT / f"{name}.pdf")


def clean(ax, grid="y"):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis=grid, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.tick_params(length=2.5, width=0.6)


# ---------------------------------------------------------------- Hình 1: kiến trúc
def fig_architecture():
    fig, ax = plt.subplots(figsize=(W, 2.25))
    ax.set_xlim(0, 100), ax.set_ylim(0, 47), ax.axis("off")

    def box(x, y, w, h, title, lines=(), fill="#ffffff", edge=MUTED):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                                    facecolor=fill, edgecolor=edge, linewidth=0.8))
        if lines:
            ax.text(x + w / 2, y + h - 2.6, title, ha="center", va="top", fontsize=7.2, fontweight="bold")
            ax.text(x + w / 2, y + h - 8.2, "\n".join(lines), ha="center", va="top", fontsize=6.6,
                    color=MUTED, linespacing=1.3)
        else:
            ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=7.6, fontweight="bold")

    def arrow(p, q, label=None, dy=1.6, style="-|>", color=INK):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=7, linewidth=0.8,
                                     color=color, shrinkA=0, shrinkB=0))
        if label:
            ax.text((p[0] + q[0]) / 2, (p[1] + q[1]) / 2 + dy, label, ha="center", va="bottom",
                    fontsize=6.4, color=MUTED)

    # hàng trên: đường đi lúc ký (online)
    box(0, 27, 15, 18, "User", ["transaction", "to $A$ on $C$"])
    box(21, 27, 24, 18, "MetaMask Snap", ["transaction insight:", "score, type, reasons"], fill="#eaf2fc", edge=BLUE)
    box(51, 27, 24, 18, "Local risk engine", ["$R(A,C)$: 4 components", "+ 2 hard rules"], fill="#eaf2fc", edge=BLUE)
    box(84, 27, 16, 18, "Public RPCs", ["eth_getCode,", "8 networks"])
    arrow((15, 38), (21, 38))
    arrow((21, 32), (15, 32))
    ax.text(18, 39.2, "sign?", ha="center", va="bottom", fontsize=6.4, color=MUTED)
    ax.text(18, 30.6, "warn", ha="center", va="top", fontsize=6.4, color=MUTED)
    arrow((45, 38), (51, 38))
    arrow((51, 32), (45, 32))
    ax.text(48, 39.2, "$(A,C)$", ha="center", va="bottom", fontsize=6.4, color=MUTED)
    ax.text(48, 30.6, "$R$", ha="center", va="top", fontsize=6.4, color=MUTED)
    arrow((75, 38), (84, 38))
    arrow((84, 32), (75, 32))
    ax.text(79.5, 39.2, r"$\leq$0.3 s", ha="center", va="bottom", fontsize=6.4, color=MUTED)
    ax.text(79.5, 30.6, "code", ha="center", va="top", fontsize=6.4, color=MUTED)

    # hàng dưới: phần tính trước (offline)
    box(24, 0, 76, 17, "Offline facts (precomputed, cached)", fill="#fdf1ea", edge=ORANGE)
    ax.texts[-1].set_position((62, 13.6))
    for i, t in enumerate(["symbolic-execution\nlookup table", "leaked-key and\ndelegate lists",
                           "foreign-contract\ncreation timeline", "transaction-history\nfeatures"]):
        ax.text(33.5 + 19 * i, 6.0, t, ha="center", va="center", fontsize=6.4, color=MUTED, linespacing=1.25)
    arrow((63, 17), (63, 27))
    ax.text(64.5, 22, "lookup", ha="left", va="center", fontsize=6.4, color=MUTED)
    ax.text(0, 8.5, "Online check:\nmedian 138 ms cold,\n0.04 ms cached", ha="left", va="center",
            fontsize=6.6, color=MUTED, linespacing=1.3)
    save(fig, "fig_architecture")


# ---------------------------------------------------------------- Hình 2: số địa chỉ so với giá trị mất
def fig_crosschain():
    labels = ["NCD-XC", "NCD-Other", "PCD-XC", "PCD-Other"]
    colors = [BLUE, ORANGE, AQUA, YELLOW]
    hatches = [None, "////", None, "////"]
    data = {  # (% địa chỉ, % giá trị mất) — Bảng tab:xc
        "BSC": ([77.2, 20.1, 2.3, 0.4], [18.9, 67.6, 13.0, 0.4]),
        "Ethereum": ([68.1, 29.7, 1.8, 0.3], [3.1, 81.5, 2.2, 13.2]),
    }
    fig, ax = plt.subplots(figsize=(W, 1.75))
    ypos = {("BSC", 0): 4.1, ("BSC", 1): 3.2, ("Ethereum", 0): 1.7, ("Ethereum", 1): 0.8}
    for chain, rows in data.items():
        for k, vals in enumerate(rows):
            left = 0.0
            for v, c, h in zip(vals, colors, hatches):
                ax.barh(ypos[chain, k], v, left=left, height=0.62, color=c, edgecolor="white", linewidth=1.0,
                        hatch=h)
                if v >= 6:
                    ax.text(left + v / 2, ypos[chain, k], f"{v:.1f}", ha="center", va="center", fontsize=7,
                            color=INK, bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.85))
                left += v
    ax.set_yticks(list(ypos.values()), ["BSC  addresses", "loss", "Ethereum  addresses", "loss"])
    ax.set_xlim(0, 100), ax.set_ylim(0.3, 4.6)
    ax.set_xlabel("Share of the victim chain's contract-misuse addresses / loss (%)")
    clean(ax, grid="x")
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    handles = [plt.Rectangle((0, 0), 1, 1, facecolor=c, hatch=h, edgecolor="white") for c, h in zip(colors, hatches)]
    ax.legend(handles, labels, ncol=4, loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False,
              handlelength=1.3, columnspacing=1.4)
    save(fig, "fig_crosschain")


# ---------------------------------------------------------------- Hình 3: v1 so với v2 (gộp 858 địa chỉ)
def fig_detector():
    metrics = ["Precision", "Recall", "F1", "FPR"]
    v1 = [0.939, 0.654, 0.771, 0.021]
    v2 = [0.840, 0.917, 0.877, 0.088]
    ci = {1: ((0.61, 0.70), (0.88, 0.95))}          # khoảng tin cậy 95% của recall
    fig, ax = plt.subplots(figsize=(W * 0.78, 1.9))
    x, bw = np.arange(len(metrics)), 0.36
    for off, vals, c, h, name, k in ((-bw / 2 - 0.02, v1, BLUE, None, "v1 (frozen)", 0),
                                    (bw / 2 + 0.02, v2, ORANGE, "////", "v2 (cut at $t$)", 1)):
        ax.bar(x + off, vals, bw, color=c, hatch=h, edgecolor="white", linewidth=0.8, label=name)
        for i, v in enumerate(vals):
            top = ci[i][k][1] if i in ci else v
            ax.text(x[i] + off, top + 0.02, f"{v:.2f}" if v >= 0.1 else f"{v:.3f}", ha="center", va="bottom", fontsize=7)
            if i in ci:
                lo, hi = ci[i][k]
                ax.errorbar(x[i] + off, v, yerr=[[v - lo], [hi - v]], color=INK, linewidth=0.8, capsize=2, capthick=0.8)
    ax.set_xticks(x, metrics)
    ax.set_ylim(0, 1.12), ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    clean(ax)
    ax.tick_params(axis="x", length=0)
    ax.legend(ncol=2, loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False, handlelength=1.3)
    save(fig, "fig_detector")


# ---------------------------------------------------------------- Hình 4: độ trễ khi cache nguội
def fig_latency():
    df = pd.read_csv(ROOT / "data" / "interim" / "wallet_bench_items.csv")
    fig, ax = plt.subplots(figsize=(W * 0.78, 1.9))
    for to, c, ls, name in ((0.3, BLUE, "-", "300 ms timeout"), (0.15, ORANGE, "--", "150 ms timeout")):
        v = np.sort(df[df.timeout == to].cold_ms.to_numpy())
        ax.step(v, np.arange(1, len(v) + 1) / len(v), where="post", color=c, linestyle=ls, linewidth=1.3,
                label=f"{name} (n = {len(v)})")
    ax.axvline(150, color=MUTED, linewidth=0.7, linestyle=":")
    ax.text(153, 0.06, "150 ms budget", fontsize=7, color=MUTED, ha="left")
    ax.set_xlim(100, 440), ax.set_ylim(0, 1.02)
    ax.set_xlabel("Cold-cache check latency (ms)"), ax.set_ylabel("Fraction of checks")
    clean(ax, grid="both")
    ax.legend(loc="lower right", frameon=False, handlelength=2.2)
    save(fig, "fig_latency")


if __name__ == "__main__":
    fig_architecture()
    fig_crosschain()
    fig_detector()
    fig_latency()
