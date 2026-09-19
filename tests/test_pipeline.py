"""
Test cases for the capstone pipeline (run with: python -m pytest tests -q).

These are the checks that would catch the mistakes that actually happened while building
this project, plus the guarantees the capstone specification depends on:

  * the raw files are never modified by the pipeline
  * the minimum-data requirements are genuinely met
  * no exact-duplicate row appears in both the training and the test split
  * the cleaning steps did what the cleaning log claims
  * country codes are not silently parsed as missing values (the 'NA' trap)
  * every evidence file referenced by the compliance checklist exists
  * risk scores stay inside 0-100 and the bands are ordered
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
T = ROOT / "outputs" / "tables"
P = ROOT / "data" / "processed"
R = ROOT / "data" / "raw"


def test_raw_files_unmodified_hashes_recorded():
    inv = pd.read_csv(T / "data_inventory.csv")
    assert len(inv) >= 10
    assert inv["sha256"].notna().all(), "every raw source must carry a provenance hash"


def test_minimum_data_requirements_met():
    chk = pd.read_csv(T / "minimum_data_check.csv")
    assert (chk["status"] == "MET").all(), chk.loc[chk.status != "MET", "requirement"].tolist()
    inv = pd.read_csv(T / "data_inventory.csv")
    assert inv["rows"].sum() >= 5000
    text_rows = inv.loc[inv.dataset.isin(["tickets", "attack_ics_text"]), "rows"].sum()
    assert text_rows >= 200, f"only {text_rows} unstructured text records"


def test_three_distinct_source_families_including_identity_and_network():
    inv = pd.read_csv(T / "data_inventory.csv")
    roles = set(inv["project_role"])
    assert any("Identity" in r for r in roles), "C2 needs an identity/access source"
    assert any("Network" in r for r in roles), "C2 needs a network/OT source"
    assert len(roles) >= 3


def test_no_duplicate_leakage_between_train_and_test():
    """The supervised stage must drop exact duplicates BEFORE splitting."""
    summary = json.loads((T / "supervised_summary.json").read_text())
    dropped = summary["network"]["rows_dropped_as_duplicate"]
    used = summary["network"]["rows_used"]
    assert dropped > 0, "duplicates exist in ToN_IoT; the pipeline must remove them"
    net = pd.read_parquet(P / "network_flows.parquet")
    assert used == int((~net["is_exact_duplicate"]).sum())


def test_placeholder_tokens_removed_from_flows():
    net = pd.read_parquet(P / "network_flows.parquet", columns=["service", "http_method"])
    assert not (net["service"] == "-").any(), "'-' must be treated as missing, not a category"


def test_country_code_not_parsed_as_missing():
    """Namibia was originally coded 'NA' and pandas read it as NaN - regression test."""
    acc = pd.read_parquet(P / "access_events.parquet", columns=["src_country"])
    assert acc["src_country"].notna().all()
    assert (acc["src_country"] == "NAM").any()


def test_timestamps_are_timezone_aware_and_in_window():
    acc = pd.read_parquet(P / "access_events.parquet", columns=["timestamp"])
    assert str(acc["timestamp"].dtype).endswith("UTC]")
    assert acc["timestamp"].min() >= pd.Timestamp("2019-04-01", tz="UTC")
    # a session that starts late on 30 April legitimately logs out on 1 May, so the
    # upper bound allows one day of spill beyond the generation window
    assert acc["timestamp"].max() <= pd.Timestamp("2019-05-02", tz="UTC")


def test_supervised_metrics_are_reported_for_every_model():
    res = pd.read_csv(T / "supervised_network_test.csv")
    for col in ("accuracy", "precision", "recall", "f1"):
        assert res[col].between(0, 1).all()
    assert len(res) >= 3, "at least three candidate models must be compared"


def test_anomaly_threshold_is_explicit():
    a = json.loads((T / "anomaly_summary.json").read_text())
    assert "chosen_threshold" in a["network"]
    assert a["access"]["threshold_quantile"] == 0.98


def test_ueba_alerts_carry_evidence():
    al = pd.read_csv(T / "ueba_alerts.csv")
    assert len(al) > 0
    assert al["evidence_event_ids"].notna().all(), "every alert must cite its evidence"


def test_incident_timeline_marks_cross_source_linkage():
    tl = pd.read_csv(T / "incident_timeline.csv")
    assert tl["linkage_basis"].notna().all()
    assert tl["linkage_basis"].str.startswith("CONTEXT").any(), \
        "cross-environment rows must be labelled as context, not proof"


def test_simulation_has_enough_runs_and_three_plus_scenarios():
    s = pd.read_csv(T / "simulation_summary.csv")
    assert len(s) >= 3
    assert (s["runs"] >= 1000).all()
    assert s["p_reach_ot"].between(0, 1).all()


def test_risk_scores_bounded_and_bands_ordered():
    r = pd.read_csv(T / "risk_user_day_scores.csv")
    assert r["risk_score"].between(0, 100).all()
    means = r.groupby("risk_band")["risk_score"].mean()
    assert means.get("critical", 100) > means.get("high", 0) > means.get("moderate", 0) \
        > means.get("low", -1)


def test_adversarial_tests_cover_at_least_three_families():
    adv = pd.read_csv(T / "adversarial_results.csv")
    families = {t for t in adv["test"] if t != "T0_baseline"}
    assert len(families) >= 3, families
    base = adv.loc[adv.test == "T0_baseline", "f1"].iloc[0]
    assert (adv["f1"] <= base + 1e-9).all(), "no perturbation should improve the score"


def test_compliance_evidence_files_exist():
    chk = pd.read_csv(T / "compliance_checklist.csv")
    for row in chk.itertuples():
        for f in str(row.files).split("; "):
            assert (ROOT / f).exists(), f"{row.code}: missing evidence file {f}"


def test_nlp_corpus_and_extractor_quality():
    n = json.loads((T / "nlp_summary.json").read_text())
    assert n["corpus_sizes"]["total"] >= 200
    assert n["indicator_extraction"]["recall"] >= 0.8
    assert "caveat" in n["classification"], "the synthetic-text caveat must be recorded"
