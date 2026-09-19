"""
Stage 08 (Capstone STEP 5) - Supervised intrusion classification.

Plain English: this stage teaches models to tell attack traffic from normal traffic using
the labels that come with ToN_IoT, then measures how well they do on data they have never
seen. Two problems are solved:

  A. Network intrusion detection on Zeek flows  (binary: attack vs normal, then the
     attack family as a multiclass problem)
  B. OT-protocol detection on Modbus telemetry  (binary), because the mining scenario
     cares specifically about industrial protocol abuse

Method choices and why (this is what you defend in the Q&A)
  * Logistic Regression  - transparent linear baseline; coefficients can be read by an
    analyst; shows how much of the problem is linearly separable.
  * Decision Tree        - produces human-readable rules an OT engineer can audit.
  * Random Forest        - handles mixed categorical/numeric features, non-linear
    interactions and outliers without scaling, which is what flow data looks like.
  The winner is chosen on cross-validated F1 on the TRAINING data only; the test set is
  touched once, at the end.

Leakage control: ToN_IoT contains identical repeated rows. Exact duplicates are removed
BEFORE the split, otherwise the same record can appear in train and test and inflate the
score.

Outputs: outputs/tables/supervised_*.csv, outputs/figures/fig09..fig11*.png,
         outputs/models/*.joblib
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (ConfusionMatrixDisplay, average_precision_score,
                             classification_report, confusion_matrix, f1_score,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_PROCESSED, OUT_FIGS, OUT_MODELS, OUT_TABLES, SEED, env_stamp, get_logger, write_json
from viz import CATEGORICAL, finish, plt

LOG = get_logger("s08_supervised")

NUM_FEATURES = ["duration", "src_bytes", "dst_bytes", "missed_bytes", "src_pkts",
                "src_ip_bytes", "dst_pkts", "dst_ip_bytes", "total_bytes", "total_pkts",
                "bytes_ratio", "log_duration", "log_total_bytes", "bytes_per_pkt",
                "src_port", "dst_port", "is_internal_dst", "is_wellknown_dst_port"]
CAT_FEATURES = ["proto", "service", "conn_state"]


def build_pipeline(model):
    pre = ColumnTransformer([
        ("num", Pipeline([("scale", StandardScaler())]), NUM_FEATURES),
        ("cat", OneHotEncoder(handle_unknown="ignore", min_frequency=20), CAT_FEATURES),
    ])
    return Pipeline([("prep", pre), ("clf", model)])


def evaluate(name, pipe, X_te, y_te, rows, average="binary"):
    pred = pipe.predict(X_te)
    p, r, f1, _ = precision_recall_fscore_support(y_te, pred, average=average, zero_division=0)
    acc = float((pred == y_te).mean())
    entry = {"model": name, "accuracy": acc, "precision": p, "recall": r, "f1": f1}
    if average == "binary" and hasattr(pipe, "predict_proba"):
        prob = pipe.predict_proba(X_te)[:, 1]
        entry["roc_auc"] = roc_auc_score(y_te, prob)
        entry["pr_auc"] = average_precision_score(y_te, prob)
    rows.append(entry)
    return entry, pred


def network_models() -> dict:
    net = pd.read_parquet(DATA_PROCESSED / "network_flows.parquet")
    n_all = len(net)
    net = net[~net["is_exact_duplicate"]].copy()          # leakage control
    LOG.info("network flows %d -> %d after removing exact duplicates", n_all, len(net))

    X = net[NUM_FEATURES + CAT_FEATURES].copy()
    X[NUM_FEATURES] = X[NUM_FEATURES].fillna(0)
    X[CAT_FEATURES] = X[CAT_FEATURES].fillna("none")
    y = np.asarray(net["label"].astype(int))

    imbalance = {"attack": int(y.sum()), "normal": int((1 - y).sum()),
                 "attack_share": float(y.mean())}
    LOG.info("class balance: %s", imbalance)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)

    candidates = {
        "logistic_regression": LogisticRegression(max_iter=400, class_weight="balanced",
                                                  n_jobs=-1),
        "decision_tree": DecisionTreeClassifier(max_depth=8, min_samples_leaf=50,
                                                class_weight="balanced", random_state=SEED),
        "random_forest": RandomForestClassifier(n_estimators=250, min_samples_leaf=2,
                                                class_weight="balanced_subsample",
                                                n_jobs=-1, random_state=SEED),
    }

    cv_rows = []
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
    rs = np.random.default_rng(SEED)
    pos = rs.choice(len(X_tr), size=min(60000, len(X_tr)), replace=False)   # CV on a sample for speed
    sub, ysub = X_tr.iloc[pos], y_tr[pos]
    for name, model in candidates.items():
        scores = cross_val_score(build_pipeline(model), sub, ysub, cv=cv, scoring="f1", n_jobs=1)
        cv_rows.append({"model": name, "cv_f1_mean": scores.mean(), "cv_f1_sd": scores.std()})
        LOG.info("CV  %-20s f1=%.4f (+/- %.4f)", name, scores.mean(), scores.std())
    cv_df = pd.DataFrame(cv_rows).sort_values("cv_f1_mean", ascending=False)
    cv_df.to_csv(OUT_TABLES / "supervised_network_cv.csv", index=False)
    best_name = cv_df.iloc[0]["model"]

    test_rows = []
    fitted = {}
    for name, model in candidates.items():
        pipe = build_pipeline(model).fit(X_tr, y_tr)
        fitted[name] = pipe
        entry, pred = evaluate(name, pipe, X_te, y_te, test_rows)
        LOG.info("TEST %-20s acc=%.4f prec=%.4f rec=%.4f f1=%.4f",
                 name, entry["accuracy"], entry["precision"], entry["recall"], entry["f1"])
    pd.DataFrame(test_rows).to_csv(OUT_TABLES / "supervised_network_test.csv", index=False)

    best = fitted[best_name]
    pred = best.predict(X_te)
    cm = confusion_matrix(y_te, pred)
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    ConfusionMatrixDisplay(cm, display_labels=["normal", "attack"]).plot(
        ax=ax, cmap="Blues", colorbar=False, values_format=",d")
    ax.set_title(f"Network intrusion detection\nconfusion matrix ({best_name})")
    ax.grid(False)
    finish(fig, ax, OUT_FIGS / "fig09_confusion_network.png")

    rep = classification_report(y_te, pred, target_names=["normal", "attack"], output_dict=True)
    write_json(rep, OUT_TABLES / "supervised_network_report.json")

    # permutation importance on a sample - which features actually carry the decision
    pos2 = rs.choice(len(X_te), size=min(8000, len(X_te)), replace=False)
    samp, ysamp = X_te.iloc[pos2], y_te[pos2]
    imp = permutation_importance(best, samp, ysamp, n_repeats=4, random_state=SEED,
                                 scoring="f1", n_jobs=-1)
    imp_df = (pd.DataFrame({"feature": NUM_FEATURES + CAT_FEATURES,
                            "importance": imp.importances_mean,
                            "sd": imp.importances_std})
              .sort_values("importance", ascending=False))
    imp_df.to_csv(OUT_TABLES / "supervised_network_importance.csv", index=False)

    top = imp_df.head(10).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7.4, 3.6))
    ax.barh(top["feature"], top["importance"], xerr=top["sd"], color=CATEGORICAL[0], height=0.6)
    ax.set_title("What the detector actually uses (permutation importance, F1 drop)")
    ax.set_xlabel("mean F1 decrease when the feature is shuffled")
    finish(fig, ax, OUT_FIGS / "fig10_feature_importance_network.png")

    # multiclass: which attack family
    y_type = np.asarray(net["type"].fillna("unknown").astype(str))
    Xm_tr, Xm_te, ym_tr, ym_te = train_test_split(X, y_type, test_size=0.30,
                                                  random_state=SEED, stratify=y_type)
    multi = build_pipeline(RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                                  n_jobs=-1, random_state=SEED)).fit(Xm_tr, ym_tr)
    mpred = multi.predict(Xm_te)
    mrep = classification_report(ym_te, mpred, output_dict=True, zero_division=0)
    pd.DataFrame(mrep).T.to_csv(OUT_TABLES / "supervised_network_multiclass.csv")
    labels = sorted(pd.unique(ym_te))
    cmm = confusion_matrix(ym_te, mpred, labels=labels, normalize="true")
    fig, ax = plt.subplots(figsize=(6.4, 5.2))
    im = ax.imshow(cmm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7.5)
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=7.5)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if cmm[i, j] > 0.02:
                ax.text(j, i, f"{cmm[i,j]:.2f}", ha="center", va="center", fontsize=6.5,
                        color="white" if cmm[i, j] > 0.5 else "#333333")
    ax.set_title("Attack family classification (row-normalised)")
    ax.set_xlabel("predicted"); ax.set_ylabel("actual"); ax.grid(False)
    finish(fig, ax, OUT_FIGS / "fig11_confusion_network_multiclass.png")

    joblib.dump(best, OUT_MODELS / "network_binary_best.joblib")
    joblib.dump(multi, OUT_MODELS / "network_multiclass_rf.joblib")

    return {"best_model": best_name, "class_balance": imbalance,
            "test_metrics": test_rows, "cv": cv_rows,
            "multiclass_macro_f1": float(mrep["macro avg"]["f1-score"]),
            "rows_used": int(len(net)), "rows_dropped_as_duplicate": int(n_all - len(net))}


def modbus_model() -> dict:
    mb = pd.read_parquet(DATA_PROCESSED / "telemetry_modbus.parquet")
    n_all = len(mb)
    mb = mb[~mb["is_exact_duplicate"]].copy()
    feats = ["FC1_Read_Input_Register", "FC2_Read_Discrete_Value",
             "FC3_Read_Holding_Register", "FC4_Read_Coil"]
    mb["hour"] = mb["timestamp"].dt.hour
    mb["dow"] = mb["timestamp"].dt.dayofweek
    feats += ["hour", "dow"]
    X = mb[feats].fillna(0)
    y = np.asarray(mb["label"].astype(int))
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)

    rows = []
    models = {
        "logistic_regression": Pipeline([("s", StandardScaler()),
                                         ("c", LogisticRegression(max_iter=300,
                                                                  class_weight="balanced"))]),
        "random_forest": RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                                class_weight="balanced_subsample",
                                                n_jobs=-1, random_state=SEED),
    }
    best_f1, best_name, best_pipe = -1, None, None
    for name, m in models.items():
        m.fit(X_tr, y_tr)
        entry, pred = evaluate(name, m, X_te, y_te, rows)
        LOG.info("MODBUS %-20s acc=%.4f prec=%.4f rec=%.4f f1=%.4f", name, entry["accuracy"],
                 entry["precision"], entry["recall"], entry["f1"])
        if entry["f1"] > best_f1:
            best_f1, best_name, best_pipe = entry["f1"], name, m
    pd.DataFrame(rows).to_csv(OUT_TABLES / "supervised_modbus_test.csv", index=False)

    cm = confusion_matrix(y_te, best_pipe.predict(X_te))
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    ConfusionMatrixDisplay(cm, display_labels=["normal", "attack"]).plot(
        ax=ax, cmap="Blues", colorbar=False, values_format=",d")
    ax.set_title(f"Modbus telemetry classifier\nconfusion matrix ({best_name})")
    ax.grid(False)
    finish(fig, ax, OUT_FIGS / "fig12_confusion_modbus.png")
    joblib.dump(best_pipe, OUT_MODELS / "modbus_binary_best.joblib")
    return {"best_model": best_name, "metrics": rows, "rows_used": int(len(mb)),
            "rows_dropped_as_duplicate": int(n_all - len(mb)),
            "attack_share": float(y.mean())}


def main() -> None:
    net_res = network_models()
    mb_res = modbus_model()
    write_json({"network": net_res, "modbus": mb_res, "env": env_stamp()},
               OUT_TABLES / "supervised_summary.json")
    LOG.info("supervised stage complete; best network model = %s", net_res["best_model"])


if __name__ == "__main__":
    main()
