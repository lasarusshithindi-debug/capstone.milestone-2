"""
Stage 09 (Capstone STEP 6) - Unsupervised anomaly detection.

Two problems, two data situations:

  A. Network flows - labels exist, but they are DELIBERATELY NOT USED for fitting. An
     Isolation Forest is fitted on the features alone, a threshold is set from the score
     distribution, and only then are the labels brought back to measure how good the
     unsupervised ranking was. That is the honest way to show what a detector would do on
     a site where nobody has labelled the traffic.

  B. Remote-access user-days - genuinely unlabelled operational data. Isolation Forest and
     Local Outlier Factor rank each user-day; the four injected behaviour patterns
     (gt_scenario) are used only afterwards, as a check on whether the ranking surfaces
     the behaviour we know is there.

Why these methods: Isolation Forest scales to hundreds of thousands of rows, needs no
distance metric over mixed features and gives a continuous score that can be thresholded
operationally. LOF is included as a contrasting local-density method. DBSCAN is used on the
user-day behaviour space to show peer grouping rather than to flag points, because the
behaviour features have very different scales and DBSCAN is sensitive to that.

Outputs: outputs/tables/anomaly_*.csv, outputs/figures/fig13..fig16*.png
"""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (DATA_PROCESSED, OUT_FIGS, OUT_MODELS, OUT_TABLES, SEED, env_stamp,
                    get_logger, write_json)
from viz import ATTACK_C, CATEGORICAL, NORMAL_C, finish, plt

LOG = get_logger("s09_anomaly")

NET_FEATURES = ["duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
                "total_bytes", "total_pkts", "bytes_ratio", "log_duration",
                "log_total_bytes", "src_port", "dst_port", "is_internal_dst"]

UD_FEATURES = ["events", "logins", "failures", "resource_access", "priv_actions",
               "distinct_ips", "distinct_countries", "distinct_targets", "out_of_hours",
               "foreign", "external", "bytes_out", "mfa_absent", "failure_ratio"]


def network_anomaly() -> dict:
    net = pd.read_parquet(DATA_PROCESSED / "network_flows.parquet")
    net = net[~net["is_exact_duplicate"]].copy()
    rs = np.random.default_rng(SEED)
    pos = rs.choice(len(net), size=min(80000, len(net)), replace=False)
    samp = net.iloc[pos].copy()

    X = samp[NET_FEATURES].fillna(0).to_numpy(dtype=float)
    Xs = StandardScaler().fit_transform(X)

    iso = IsolationForest(n_estimators=300, contamination=0.15, random_state=SEED, n_jobs=-1)
    iso.fit(Xs)                                    # labels never touch this line
    score = -iso.score_samples(Xs)                 # higher = more anomalous
    samp["anomaly_score"] = score

    y = samp["label"].astype(int).to_numpy()
    auc = roc_auc_score(y, score)

    # threshold choice: the 85th percentile of the score, i.e. the 15 per cent of flows an
    # analyst team could realistically triage; reported alongside alternatives
    rows = []
    for q in (0.80, 0.85, 0.90, 0.95, 0.99):
        thr = float(np.quantile(score, q))
        flag = (score >= thr).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(y, flag, average="binary", zero_division=0)
        rows.append({"threshold_quantile": q, "threshold_score": thr,
                     "flagged": int(flag.sum()), "precision": p, "recall": r, "f1": f1})
    thr_tbl = pd.DataFrame(rows)
    thr_tbl.to_csv(OUT_TABLES / "anomaly_network_thresholds.csv", index=False)
    chosen = thr_tbl.iloc[1]                      # the 0.85 row

    # what do the flagged flows look like, by labelled family?
    samp["flagged"] = (score >= chosen["threshold_score"]).astype(int)
    by_type = (samp.groupby("type", observed=True)
               .agg(flows=("label", "size"), flagged=("flagged", "sum"))
               .assign(flagged_share=lambda d: d.flagged / d.flows)
               .sort_values("flagged_share", ascending=False).reset_index())
    by_type.to_csv(OUT_TABLES / "anomaly_network_by_type.csv", index=False)

    fig, ax = plt.subplots(figsize=(8.2, 3.2))
    ax.hist(score[y == 0], bins=60, alpha=0.75, color=NORMAL_C, label="normal-labelled")
    ax.hist(score[y == 1], bins=60, alpha=0.6, color=ATTACK_C, label="attack-labelled")
    ax.axvline(chosen["threshold_score"], color="#333333", lw=1.4, ls="--")
    ax.text(chosen["threshold_score"], ax.get_ylim()[1] * 0.85,
            f"  operating threshold\n  (top 15%)", fontsize=7.5, color="#333333")
    ax.set_title("Isolation Forest scores on network flows (labels shown only for validation)")
    ax.set_xlabel("anomaly score (higher = more unusual)"); ax.set_ylabel("flows")
    ax.legend()
    finish(fig, ax, OUT_FIGS / "fig13_network_anomaly_scores.png")

    fig, ax = plt.subplots(figsize=(8.2, 3.2))
    b = by_type.sort_values("flagged_share")
    ax.barh(b["type"], b["flagged_share"], color=CATEGORICAL[0], height=0.62)
    ax.set_xlabel("share of that activity type flagged by the unsupervised detector")
    ax.set_title("Unsupervised detection rate by labelled activity type")
    finish(fig, ax, OUT_FIGS / "fig14_anomaly_share_by_type.png")

    # ---------------------------------------------------------------------------------
    # Variant B - novelty detection against a known-good baseline.
    # The fully unsupervised run above assumes attacks are RARE. In this capture they are
    # not: 78 per cent of the flows are attack-labelled, so "unusual" mostly means normal
    # office traffic. The realistic OT equivalent is to learn the baseline from a period
    # the site believes to be clean, then score everything else against it.
    # ---------------------------------------------------------------------------------
    norm_idx = np.flatnonzero(y == 0)
    # fit on 60 per cent of the normal traffic only; the remaining normal flows stay in the
    # held-out set so that the evaluation contains both classes
    fit_idx = rs.choice(norm_idx, size=int(0.6 * len(norm_idx)), replace=False)
    scaler_b = StandardScaler().fit(X[fit_idx])
    iso_b = IsolationForest(n_estimators=300, contamination=0.02, random_state=SEED, n_jobs=-1)
    iso_b.fit(scaler_b.transform(X[fit_idx]))
    score_b = -iso_b.score_samples(scaler_b.transform(X))
    held = np.setdiff1d(np.arange(len(samp)), fit_idx)        # never seen during fitting
    auc_b = roc_auc_score(y[held], score_b[held])
    rows_b = []
    for q in (0.50, 0.70, 0.80, 0.90):
        thr_b = float(np.quantile(score_b[held], q))
        flag_b = (score_b[held] >= thr_b).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(y[held], flag_b, average="binary",
                                                      zero_division=0)
        rows_b.append({"threshold_quantile": q, "threshold_score": thr_b,
                       "flagged": int(flag_b.sum()), "precision": p, "recall": r, "f1": f1})
    pd.DataFrame(rows_b).to_csv(OUT_TABLES / "anomaly_network_baseline_thresholds.csv",
                                index=False)

    joblib.dump(iso, OUT_MODELS / "network_isolation_forest.joblib")
    joblib.dump({"model": iso_b, "scaler": scaler_b, "features": NET_FEATURES},
                OUT_MODELS / "network_isolation_forest_baseline.joblib")
    LOG.info("network IF (fully unsupervised): ROC-AUC=%.4f  at 15%% budget "
             "precision=%.3f recall=%.3f", auc, chosen["precision"], chosen["recall"])
    LOG.info("network IF (clean-baseline novelty): ROC-AUC=%.4f on %d held-out flows",
             auc_b, len(held))
    return {"roc_auc_unsupervised": float(auc), "sample_rows": int(len(samp)),
            "attack_share_in_sample": float(y.mean()),
            "chosen_threshold": chosen.to_dict(),
            "thresholds": rows,
            "roc_auc_clean_baseline": float(auc_b),
            "baseline_thresholds": rows_b,
            "interpretation": (
                "Fully unsupervised outlier detection performs below chance here "
                f"(ROC-AUC {auc:.2f}) because attack traffic is the majority class in this "
                "capture. Learning the profile of known-good traffic and scoring novelty "
                f"against it raises ROC-AUC to {auc_b:.2f}. The operational lesson for the "
                "mine is that anomaly detection needs a trusted baseline window, not simply "
                "'whatever is rare today'.")}


def access_anomaly() -> dict:
    ud = pd.read_parquet(DATA_PROCESSED / "access_user_day.parquet").reset_index(drop=True)
    X = ud[UD_FEATURES].fillna(0).to_numpy(dtype=float)
    Xs = StandardScaler().fit_transform(X)

    iso = IsolationForest(n_estimators=400, contamination=0.02, random_state=SEED, n_jobs=-1)
    iso.fit(Xs)
    ud["iso_score"] = -iso.score_samples(Xs)

    lof = LocalOutlierFactor(n_neighbors=25, novelty=False)
    lof.fit_predict(Xs)
    ud["lof_score"] = -lof.negative_outlier_factor_

    # operating threshold: top 2 per cent of user-days - about one alert per working day
    thr = float(np.quantile(ud["iso_score"], 0.98))
    ud["iso_flag"] = (ud["iso_score"] >= thr).astype(int)
    ud["lof_flag"] = (ud["lof_score"] >= np.quantile(ud["lof_score"], 0.98)).astype(int)

    # post-hoc check against the injected behaviour patterns
    ud["has_gt"] = (ud["gt"].fillna("") != "").astype(int)
    def scores(flag_col):
        p, r, f1, _ = precision_recall_fscore_support(ud["has_gt"], ud[flag_col],
                                                      average="binary", zero_division=0)
        return {"method": flag_col.replace("_flag", ""), "flagged": int(ud[flag_col].sum()),
                "precision_vs_injected": p, "recall_vs_injected": r, "f1": f1}
    val = pd.DataFrame([scores("iso_flag"), scores("lof_flag")])
    val["roc_auc_vs_injected"] = [roc_auc_score(ud["has_gt"], ud["iso_score"]),
                                  roc_auc_score(ud["has_gt"], ud["lof_score"])]
    val.to_csv(OUT_TABLES / "anomaly_access_validation.csv", index=False)

    # explain each flagged user-day: which features are far from that role's normal
    role_mean = ud.groupby("role", observed=True)[UD_FEATURES].transform("mean")
    role_sd = ud.groupby("role", observed=True)[UD_FEATURES].transform("std").replace(0, np.nan)
    z = (ud[UD_FEATURES] - role_mean) / role_sd
    def top_reasons(i):
        row = z.iloc[i].dropna().sort_values(ascending=False)
        return "; ".join(f"{k} {v:+.1f} SD vs role mean" for k, v in row.head(3).items() if v > 1.5)
    flagged = ud[ud["iso_flag"] == 1].copy()
    flagged["why_flagged"] = [top_reasons(i) for i in flagged.index]
    cols = ["username", "role", "employment_type", "day", "events", "failures", "priv_actions",
            "distinct_ips", "distinct_countries", "out_of_hours", "foreign", "bytes_out",
            "iso_score", "lof_score", "why_flagged", "gt"]
    flagged = flagged.sort_values("iso_score", ascending=False)[cols]
    flagged.to_csv(OUT_TABLES / "anomaly_access_flagged_user_days.csv", index=False)
    ud.to_parquet(DATA_PROCESSED / "access_user_day_scored.parquet", index=False)

    fig, ax = plt.subplots(figsize=(8.2, 3.3))
    normal_pts = ud[ud["iso_flag"] == 0]
    flag_pts = ud[ud["iso_flag"] == 1]
    ax.scatter(normal_pts["events"], normal_pts["failures"], s=12, alpha=0.35,
               color=NORMAL_C, label="within baseline", edgecolors="none")
    ax.scatter(flag_pts["events"], flag_pts["failures"], s=34, alpha=0.9, color=ATTACK_C,
               label="flagged (top 2%)", edgecolors="white", linewidths=0.5)
    ax.set_xlabel("events in the day"); ax.set_ylabel("failed logins in the day")
    ax.set_title("Remote-access user-days: activity volume vs authentication failures")
    ax.legend()
    finish(fig, ax, OUT_FIGS / "fig15_access_anomaly_scatter.png")

    top10 = flagged.head(10).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8.2, 3.6))
    lbl = top10["username"] + "  " + top10["day"].astype(str)
    ax.barh(lbl, top10["iso_score"], color=CATEGORICAL[1], height=0.62)
    ax.set_title("Ten most anomalous remote-access user-days")
    ax.set_xlabel("Isolation Forest score")
    finish(fig, ax, OUT_FIGS / "fig16_top_anomalous_user_days.png")

    # DBSCAN peer grouping on a compact behaviour space
    small = StandardScaler().fit_transform(ud[["events", "failures", "out_of_hours",
                                               "distinct_targets", "bytes_out"]].fillna(0))
    db = DBSCAN(eps=1.2, min_samples=12).fit(small)
    ud["dbscan_cluster"] = db.labels_
    clus = (ud.groupby("dbscan_cluster", observed=True)
            .agg(user_days=("events", "size"), mean_events=("events", "mean"),
                 mean_failures=("failures", "mean"), mean_ooh=("out_of_hours", "mean"),
                 injected_rows=("has_gt", "sum")).reset_index())
    clus.to_csv(OUT_TABLES / "anomaly_access_dbscan_clusters.csv", index=False)

    joblib.dump(iso, OUT_MODELS / "access_isolation_forest.joblib")
    LOG.info("access IF: flagged=%d of %d  recall vs injected=%.2f  ROC-AUC=%.3f",
             int(ud["iso_flag"].sum()), len(ud), val.loc[0, "recall_vs_injected"],
             val.loc[0, "roc_auc_vs_injected"])
    LOG.info("DBSCAN: %d clusters + %d noise points", (db.labels_ >= 0).sum() and
             len(set(db.labels_) - {-1}), int((db.labels_ == -1).sum()))
    return {"threshold_quantile": 0.98, "threshold_score": thr,
            "flagged_user_days": int(ud["iso_flag"].sum()),
            "validation": val.to_dict(orient="records"),
            "dbscan_clusters": int(len(set(db.labels_) - {-1})),
            "dbscan_noise": int((db.labels_ == -1).sum())}


def main() -> None:
    net = network_anomaly()
    acc = access_anomaly()
    write_json({"network": net, "access": acc, "env": env_stamp()},
               OUT_TABLES / "anomaly_summary.json")


if __name__ == "__main__":
    main()
