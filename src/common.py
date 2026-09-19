"""
SAS821S Capstone 2026 - T08 Mining Remote Operations and Industrial-IoT Intrusion Analytics
Group: 222093471 (S. Kalume, Member A) and 215103815 (L. Shithindi, Member B)

common.py - shared paths, constants and small helpers used by every stage script.

Plain English: this file is the single place where we set folder locations, the
random seed and a few utility functions, so that every other script behaves the
same way and the whole pipeline can be re-run from a clean checkout.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

# --------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = ROOT / "data" / "raw"
DATA_INTERIM = ROOT / "data" / "interim"
DATA_PROCESSED = ROOT / "data" / "processed"
OUT = ROOT / "outputs"
OUT_TABLES = OUT / "tables"
OUT_FIGS = OUT / "figures"
OUT_LOGS = OUT / "logs"
OUT_MODELS = OUT / "models"

for _p in (DATA_RAW, DATA_INTERIM, DATA_PROCESSED, OUT_TABLES, OUT_FIGS, OUT_LOGS, OUT_MODELS):
    _p.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------------------
# Reproducibility
# --------------------------------------------------------------------------------------
SEED = 215103815 % 100000  # 3815 - derived from the group member's student number
RNG = np.random.default_rng(SEED)

# Raw source locations (relative to data/raw)
SRC_IOT_DIR = DATA_RAW / "ton_iot_gh" / "Train_Test_IoT_dataset"
SRC_NETWORK = DATA_RAW / "netrepo" / "data" / "TON_IoT_Train_Test_Network.csv"
SRC_ATTACK_TEXT = DATA_RAW / "attack_ics_text.csv"
SRC_ACCESS = DATA_RAW / "synthetic_remote_access_log.csv"
SRC_TICKETS = DATA_RAW / "synthetic_maintenance_tickets.csv"


def get_logger(name: str) -> logging.Logger:
    """Console + file logger so every run leaves an auditable trace."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = logging.FileHandler(OUT_LOGS / "run_log.txt", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def sha256(path: Path, block: int = 1 << 20) -> str:
    """File hash - used as the provenance fingerprint for every raw input."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(block):
            h.update(chunk)
    return h.hexdigest()


def env_stamp() -> dict:
    """Record the exact environment so results can be reproduced later."""
    import pandas as pd
    import sklearn

    return {
        "utc_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": sklearn.__version__,
        "seed": SEED,
    }


def write_json(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


def git_commit(path: Path) -> str:
    """Commit hash of a cloned source repository (provenance evidence)."""
    try:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return "unknown"
