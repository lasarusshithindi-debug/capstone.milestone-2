"""
Stage 15 (Capstone STEPS 12 and 13) - Predictive security risk score and adversarial testing.

Part 1 - Interpretable daily risk score
--------------------------------------
Every user-day gets a score from 0 to 100 built from six components an analyst can read,
each normalised against the population and weighted:

    failed logins            0.15   authentication pressure on the account
    out-of-hours activity    0.10   work outside the account's normal pattern
    foreign / external src   0.20   access from outside the corporate network
    privileged without MFA   0.20   the control failure that matters most here
    anomaly score            0.20   the Isolation Forest view from stage 09
    data egress volume       0.15   how much data left through the session

Bands: 0-24 low, 25-49 moderate, 50-74 high, 75-100 critical, each with a stated action.
The score is validated against the injected behaviour patterns (ROC-AUC and precision at
the top 20 user-days), not asserted.

Part 2 - Early warning
----------------------
A logistic regression trained on days 1-20 predicts whether an account will trigger a UEBA
alert on the FOLLOWING day, and is tested on days 21-30 - a time-ordered split, so the model
never sees the future.

Part 3 - Four adversarial / robustness tests on the deployed network detector
-----------------------------------------------------------------------------
    T1 sensor drift      Gaussian noise added to numeric features
    T2 evasion           attacker pads and slows flows to look ordinary
    T3 missing data      a share of feature values is lost in collection
    T4 label poisoning   a share of training labels is flipped before retraining

Outputs: outputs/tables/risk_*.csv, adversarial_results.csv, outputs/figures/fig24-26*
"""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_recall_fscore_support, roc_auc_score
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (DATA_PROCESSED, OUT_FIGS, OUT_MODELS, OUT_TABLES, SEED, env_stamp,
                    get_logger, write_json)
from viz import ATTACK_C, CATEGORICAL, NORMAL_C, finish, plt

LOG = get_logger("s15_risk")

WEIGHTS = {"failures": 0.15, "out_of_hours": 0.10, "external_foreign": 0.20,
           "priv_no_mfa": 0.20, "anomaly": 0.20, "egress": 0.15}

# Band cut-points are set from the SCORE DISTRIBUTION rather than from round numbers,
# because every component is a percentile rank: an average account scores about 50, so a
# fixed cut at 50 would place half the workforce in the "high" band. The cut-points below
# are an alerting budget: roughly 0.5% critical, 1.5% high and 8% moderate of all
# user-days, which is about one critical case a week for a 115-account estate.
BAND_QUANTILES = [(0.995, "critical", "Investigate now; consider suspending the account"),
                  (0.980, "high", "Investigate within the shift; verify with the account owner"),
                  (0.900, "moderate", "Review in the daily triage queue"),
                  (0.000, "low", "No action; keep in the baseline")]


def pct_rank(s: pd.Series) -> pd.Series:
    return s.rank(pct=True).fillna(0)


def build_risk(ud: pd.DataFrame, acc: pd.DataFrame) -> pd.DataFrame:
    # privileged actions that happened without MFA, per user-day
    pm = (acc[acc["privileged_action"] & (~acc["mfa_used"])]
          .groupby(["username", "day"], observed=True).size().rename("priv_no_mfa"))
    ud = ud.merge(pm, left_on=["username", "day"], right_index=True, how="left")
    ud["priv_no_mfa"] = ud["priv_no_mfa"].fillna(0)

    comp = pd.DataFrame({
        "failures": pct_rank(ud["failures"]),
        "out_of_hours": pct_rank(ud["out_of_hours"]),
        "external_foreign": pct_rank(ud["foreign"] + ud["external"]),
        "priv_no_mfa": pct_rank(ud["priv_no_mfa"]),
        "anomaly": pct_rank(ud["iso_score"]),
        "egress": pct_rank(ud["bytes_out"]),
    })
    ud["risk_score"] = (100 * sum(comp[k] * w for k, w in WEIGHTS.items())).round(1)
    for k in WEIGHTS:
        ud[f"comp_{k}"] = (100 * comp[k]).round(1)

    cuts = [(float(ud["risk_score"].quantile(q)) if q > 0 else 0.0, name, action)
            for q, name, action in BAND_QUANTILES]

    def band(v):
        for cut, name, action in cuts:
            if v >= cut:
                return name, action
        return "low", cuts[-1][2]
    ud["risk_band"] = [band(v)[0] for v in ud["risk_score"]]
    ud["recommended_action"] = [band(v)[1] for v in ud["risk_score"]]
    ud.attrs["band_cuts"] = cuts

    # the largest single contributor, so the dashboard can say WHY
    comp_scaled = comp.mul(pd.Series(WEIGHTS), axis=1)
    ud["top_driver"] = comp_scaled.idxmax(axis=1).values
    return ud


def main() -> None:
    ud = pd.read_parquet(DATA_PROCESSED / "access_user_day_scored.parquet")
    acc = pd.read_parquet(DATA_PROCESSED / "access_events.parquet")
    alerts = pd.read_csv(OUT_TABLES / "ueba_alerts.csv")

    # ---------------- Part 1: risk score ----------------
    ud = build_risk(ud, acc)
    ud["has_gt"] = (ud["gt"].fillna("") != "").astype(int)
    auc = roc_auc_score(ud["has_gt"], ud["risk_score"])
    top20 = ud.nlargest(20, "risk_score")
    prec_at_20 = float(top20["has_gt"].mean())

    keep = ["username", "role", "employment_type", "day", "risk_score", "risk_band",
            "top_driver", "recommended_action", "failures", "out_of_hours", "priv_no_mfa",
            "foreign", "bytes_out", "iso_score", "gt"] + [f"comp_{k}" for k in WEIGHTS]
    ud[keep].sort_values("risk_score", ascending=False).to_csv(
        OUT_TABLES / "risk_user_day_scores.csv", index=False)
    ud.to_parquet(DATA_PROCESSED / "access_user_day_risk.parquet", index=False)

    band_tbl = (ud.groupby("risk_band", observed=True)
                .agg(user_days=("risk_score", "size"),
                     share=("risk_score", lambda s: len(s) / len(ud)),
                     injected_rows=("has_gt", "sum"),
                     mean_score=("risk_score", "mean")).reset_index()
                .sort_values("mean_score", ascending=False))
    band_tbl.to_csv(OUT_TABLES / "risk_band_summary.csv", index=False)
    LOG.info("risk score ROC-AUC vs injected behaviour = %.3f; precision@20 = %.2f",
             auc, prec_at_20)

    fig, ax = plt.subplots(figsize=(8.2, 3.1))
    ax.hist(ud.loc[ud.has_gt == 0, "risk_score"], bins=40, color=NORMAL_C, alpha=0.8,
            label="ordinary user-days")
    ax.hist(ud.loc[ud.has_gt == 1, "risk_score"], bins=40, color=ATTACK_C, alpha=0.85,
            label="user-days containing injected behaviour")
    for cut, name, _ in ud.attrs['band_cuts'][:-1]:
        ax.axvline(cut, color="#444444", lw=1, ls="--")
        ax.text(cut + 1, ax.get_ylim()[1] * 0.75, name, fontsize=7, color="#444444")
    ax.set_yscale("log")
    ax.set_xlabel("risk score (0-100)"); ax.set_ylabel("user-days (log scale)")
    ax.set_title("Daily risk score distribution and bands")
    ax.legend(fontsize=8)
    finish(fig, ax, OUT_FIGS / "fig24_risk_score_distribution.png")

    # ---------------- Part 2: next-day early warning ----------------
    alerts["day"] = pd.to_datetime(alerts["timestamp"]).dt.date
    alert_days = set(zip(alerts["username"], alerts["day"]))
    ud["alert_today"] = [1 if (u, d) in alert_days else 0
                         for u, d in zip(ud["username"], ud["day"])]
    ud = ud.sort_values(["username", "day"])
    ud["alert_tomorrow"] = ud.groupby("username", observed=True)["alert_today"].shift(-1)
    model_df = ud.dropna(subset=["alert_tomorrow"]).copy()
    model_df["alert_tomorrow"] = model_df["alert_tomorrow"].astype(int)

    feats = ["events", "failures", "out_of_hours", "priv_no_mfa", "foreign", "external",
             "distinct_ips", "bytes_out", "iso_score", "risk_score"]
    days = sorted(model_df["day"].unique())
    cut_day = days[int(len(days) * 0.7)]
    tr = model_df[model_df["day"] < cut_day]
    te = model_df[model_df["day"] >= cut_day]

    sc = StandardScaler().fit(tr[feats])
    lr = LogisticRegression(max_iter=500, class_weight="balanced").fit(sc.transform(tr[feats]),
                                                                      tr["alert_tomorrow"])
    prob = lr.predict_proba(sc.transform(te[feats]))[:, 1]
    fw_auc = roc_auc_score(te["alert_tomorrow"], prob) if te["alert_tomorrow"].nunique() > 1 else np.nan
    k = 20
    topk = te.assign(p=prob).nlargest(k, "p")
    prec_k = float(topk["alert_tomorrow"].mean())
    coefs = pd.DataFrame({"feature": feats, "coefficient": lr.coef_[0]}).sort_values(
        "coefficient", ascending=False)
    coefs.to_csv(OUT_TABLES / "risk_forecast_coefficients.csv", index=False)
    pd.DataFrame([{"train_days": f"< {cut_day}", "test_days": f">= {cut_day}",
                   "train_rows": len(tr), "test_rows": len(te),
                   "positive_rate_test": float(te["alert_tomorrow"].mean()),
                   "roc_auc": fw_auc, f"precision_at_{k}": prec_k}]).to_csv(
        OUT_TABLES / "risk_forecast_metrics.csv", index=False)
    LOG.info("next-day early warning: ROC-AUC=%.3f  precision@%d=%.2f  (base rate %.3f)",
             fw_auc, k, prec_k, te["alert_tomorrow"].mean())

    # ---------------- Part 3: adversarial and robustness tests ----------------
    from s08_supervised import CAT_FEATURES, NUM_FEATURES     # same feature contract

    from sklearn.model_selection import train_test_split

    net = pd.read_parquet(DATA_PROCESSED / "network_flows.parquet")
    net = net[~net["is_exact_duplicate"]]
    rs = np.random.default_rng(SEED)
    # Reproduce EXACTLY the split used in stage 08 and keep only the test portion, so the
    # robustness tests are run on flows the deployed model has never seen.
    _feat = net[NUM_FEATURES + CAT_FEATURES].copy()
    _feat[NUM_FEATURES] = _feat[NUM_FEATURES].fillna(0)
    _feat[CAT_FEATURES] = _feat[CAT_FEATURES].fillna("none")
    _y = np.asarray(net["label"].astype(int))
    _, test_idx = train_test_split(np.arange(len(net)), test_size=0.30,
                                   random_state=SEED, stratify=_y)
    sel = rs.choice(test_idx, size=min(40000, len(test_idx)), replace=False)
    hold = net.iloc[sel].copy()
    X = hold[NUM_FEATURES + CAT_FEATURES].copy()
    # cast to float so the perturbation tests below can write non-integer values
    X[NUM_FEATURES] = X[NUM_FEATURES].fillna(0).astype(float)
    X[CAT_FEATURES] = X[CAT_FEATURES].fillna("none")
    y = np.asarray(hold["label"].astype(int))

    model = joblib.load(OUT_MODELS / "network_binary_best.joblib")
    base_f1 = f1_score(y, model.predict(X))
    results = [{"test": "T0_baseline", "setting": "unmodified held-out flows",
                "f1": base_f1, "recall_on_attacks": float(
                    precision_recall_fscore_support(y, model.predict(X), average="binary",
                                                    zero_division=0)[1]),
                "f1_change_vs_baseline": 0.0}]

    def record(test, setting, Xm, ym=y):
        pred = model.predict(Xm)
        p, r, f1, _ = precision_recall_fscore_support(ym, pred, average="binary", zero_division=0)
        results.append({"test": test, "setting": setting, "f1": f1, "recall_on_attacks": r,
                        "f1_change_vs_baseline": f1 - base_f1})

    # T1 - drift / sensor noise
    for lvl in (0.05, 0.15, 0.30):
        Xm = X.copy()
        noise = rs.normal(1.0, lvl, size=(len(Xm), len(NUM_FEATURES)))
        Xm[NUM_FEATURES] = Xm[NUM_FEATURES].to_numpy() * noise
        record("T1_drift_noise", f"multiplicative Gaussian noise, sigma={lvl}", Xm)

    # T2 - evasion: the attacker pads and slows traffic to resemble ordinary sessions
    for pad, slow in ((1.5, 2.0), (3.0, 5.0), (6.0, 10.0)):
        Xm = X.copy()
        atk = y == 1
        Xm.loc[atk, "duration"] = Xm.loc[atk, "duration"] * slow
        Xm.loc[atk, "src_bytes"] = Xm.loc[atk, "src_bytes"] * pad
        Xm.loc[atk, "dst_bytes"] = Xm.loc[atk, "dst_bytes"] * pad
        Xm.loc[atk, "total_bytes"] = Xm.loc[atk, "src_bytes"] + Xm.loc[atk, "dst_bytes"]
        Xm.loc[atk, "log_duration"] = np.log1p(Xm.loc[atk, "duration"].clip(lower=0))
        Xm.loc[atk, "log_total_bytes"] = np.log1p(Xm.loc[atk, "total_bytes"])
        Xm.loc[atk, "conn_state"] = "sf"          # pretend every session completed cleanly
        record("T2_evasion", f"attack flows padded x{pad} and slowed x{slow}, conn_state=sf", Xm)

    # T3 - missing data in collection
    for frac in (0.10, 0.25, 0.50):
        Xm = X.copy()
        mask = rs.random(size=(len(Xm), len(NUM_FEATURES))) < frac
        vals = np.array(Xm[NUM_FEATURES].to_numpy(dtype=float), copy=True)
        vals[mask] = 0.0
        Xm[NUM_FEATURES] = vals
        cat_mask = rs.random(len(Xm)) < frac
        Xm.loc[cat_mask, "service"] = "none"
        record("T3_missing_data", f"{frac:.0%} of feature values lost", Xm)

    # T4 - label poisoning before retraining
    from s08_supervised import build_pipeline
    train_idx = np.setdiff1d(np.arange(len(net)), test_idx)
    tr_pos = rs.choice(train_idx, size=min(40000, len(train_idx)), replace=False)
    tr_df = net.iloc[tr_pos].copy()
    Xtr = tr_df[NUM_FEATURES + CAT_FEATURES].copy()
    Xtr[NUM_FEATURES] = Xtr[NUM_FEATURES].fillna(0).astype(float)
    Xtr[CAT_FEATURES] = Xtr[CAT_FEATURES].fillna("none")
    ytr = np.asarray(tr_df["label"].astype(int))
    for frac in (0.05, 0.15, 0.30):
        yp = ytr.copy()
        flip = rs.choice(len(yp), size=int(frac * len(yp)), replace=False)
        yp[flip] = 1 - yp[flip]
        poisoned = build_pipeline(RandomForestClassifier(n_estimators=120, min_samples_leaf=2,
                                                         n_jobs=-1, random_state=SEED))
        poisoned.fit(Xtr, yp)
        pred = poisoned.predict(X)
        p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        results.append({"test": "T4_label_poisoning",
                        "setting": f"{frac:.0%} of training labels flipped",
                        "f1": f1, "recall_on_attacks": r, "f1_change_vs_baseline": f1 - base_f1})

    res = pd.DataFrame(results)
    res.to_csv(OUT_TABLES / "adversarial_results.csv", index=False)
    for r in res.itertuples():
        LOG.info("%-20s %-52s F1=%.4f (%+.4f)", r.test, r.setting[:52], r.f1,
                 r.f1_change_vs_baseline)

    fig, ax = plt.subplots(figsize=(8.4, 3.6))
    tests = [t for t in res["test"].unique() if t != "T0_baseline"]
    for i, t in enumerate(tests):
        sub = res[res.test == t]
        ax.plot(range(len(sub)), sub["f1"], marker="o", lw=2,
                color=CATEGORICAL[i % len(CATEGORICAL)], label=t)
    ax.axhline(base_f1, color="#333333", ls="--", lw=1)
    ax.text(0.02, base_f1, " unmodified data", fontsize=7.5, va="bottom", color="#333333")
    ax.set_xticks(range(3)); ax.set_xticklabels(["mild", "moderate", "severe"])
    ax.set_ylabel("F1 on held-out flows")
    ax.set_title("Detector performance under adversarial and robustness tests")
    ax.legend(fontsize=8)
    finish(fig, ax, OUT_FIGS / "fig25_adversarial_tests.png")

    write_json({
        "risk_score": {"weights": WEIGHTS,
                       "bands": [{"min_score": round(c, 1), "band": n, "action": a}
                                 for c, n, a in ud.attrs["band_cuts"]],
                       "roc_auc_vs_injected": float(auc), "precision_at_20": prec_at_20,
                       "band_counts": band_tbl.to_dict(orient="records")},
        "early_warning": {"train_days": str(cut_day), "roc_auc": float(fw_auc),
                          f"precision_at_{k}": prec_k,
                          "test_positive_rate": float(te["alert_tomorrow"].mean()),
                          "top_features": coefs.head(4).to_dict(orient="records")},
        "adversarial": res.to_dict(orient="records"),
        "env": env_stamp(),
    }, OUT_TABLES / "risk_adversarial_summary.json")


if __name__ == "__main__":
    main()
