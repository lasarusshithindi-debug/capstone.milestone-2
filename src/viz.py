"""
Shared figure style for every chart in the capstone.

Rules applied consistently (so the figures read as one set):
  * one y-axis per chart, never a second scale
  * a fixed categorical colour order (Okabe-Ito, a colour-vision-deficiency safe set)
  * a single hue, light to dark, for magnitude/heatmaps - never a rainbow
  * recessive grid and axes, legend whenever more than one series is drawn
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")          # write files, no interactive window needed
import matplotlib.pyplot as plt

# Okabe-Ito: distinguishable under the common forms of colour blindness
CATEGORICAL = ["#0072B2", "#E69F00", "#009E73", "#CC79A7",
               "#56B4E9", "#D55E00", "#F0E442", "#7F7F7F"]
SEQ_CMAP = "Blues"             # single hue, light -> dark
NORMAL_C, ATTACK_C = "#0072B2", "#D55E00"

plt.rcParams.update({
    "figure.dpi": 130,
    "savefig.dpi": 130,
    "savefig.bbox": "tight",
    "font.size": 9,
    "axes.titlesize": 10.5,
    "axes.titleweight": "bold",
    "axes.labelsize": 9,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.6,
    "legend.frameon": False,
    "figure.facecolor": "white",
})


def finish(fig, ax_or_axes, path, caption: str | None = None):
    """Save a figure and, optionally, stamp a one-line caption under it."""
    if caption:
        fig.text(0.01, -0.02, caption, fontsize=7.5, color="#444444", ha="left")
    fig.savefig(path)
    plt.close(fig)
    return path
