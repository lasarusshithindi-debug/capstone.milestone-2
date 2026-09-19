"""
Run the whole capstone pipeline from raw data to compliance checklist.

    python src/run_all.py            # run every stage in order
    python src/run_all.py --from s08 # resume from a stage

Stages are ordinary Python modules, so any of them can also be run on its own.
Every stage appends to outputs/logs/run_log.txt.
"""
from __future__ import annotations

import argparse
import importlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT_TABLES, env_stamp, get_logger, write_json

LOG = get_logger("run_all")

STAGES = [
    ("s01", "s01_extract_attack_text", "extract ATT&CK ICS text corpus"),
    ("s02", "s02_generate_context_and_access", "generate asset/user context + access log"),
    ("s03", "s03_generate_tickets", "generate maintenance/incident tickets"),
    ("s04", "s04_inventory", "data inventory, dictionary, quality profile"),
    ("s05", "s05_requirements_matrix", "requirements matrix and minimum-data check"),
    ("s06", "s06_clean", "cleaning, features, joins, crosswalk"),
    ("s07", "s07_eda", "descriptive/diagnostic analytics and baselines"),
    ("s08", "s08_supervised", "supervised intrusion classification"),
    ("s09", "s09_anomaly", "unsupervised anomaly detection"),
    ("s10", "s10_access_analytics", "access and user-behaviour analytics"),
    ("s11", "s11_investigation", "investigation timeline and response plan"),
    ("s13", "s13_simulation", "Monte Carlo control-scenario simulation"),
    ("s14", "s14_textmining", "text mining and NLP"),
    ("s15", "s15_risk_adversarial", "predictive risk score and adversarial tests"),
    ("s12", "s12_intelligence", "intelligence requirements and products"),
    ("s16", "s16_architecture", "architecture diagram"),
    ("s17", "s17_member_a_pack", "Member A evidence pack (dictionary, evaluation, experiment log)"),
    ("nb", "make_notebook", "build the walkthrough notebook"),
    ("s20", "s20_compliance", "compliance checklist C1-C10"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="start", default=None, help="stage id to start at")
    args = ap.parse_args()

    started = args.start is None
    record = []
    t_all = time.time()
    for sid, module, desc in STAGES:
        if not started:
            if sid == args.start:
                started = True
            else:
                continue
        t0 = time.time()
        LOG.info("=== %s  %s", sid, desc)
        mod = importlib.import_module(module)
        mod.main()
        dt = time.time() - t0
        record.append({"stage": sid, "module": module, "description": desc,
                       "seconds": round(dt, 1)})
        LOG.info("--- %s finished in %.1fs", sid, dt)

    write_json({"stages": record, "total_seconds": round(time.time() - t_all, 1),
                "env": env_stamp()}, OUT_TABLES / "experiment_log.json")
    LOG.info("pipeline complete in %.1fs", time.time() - t_all)


if __name__ == "__main__":
    main()
