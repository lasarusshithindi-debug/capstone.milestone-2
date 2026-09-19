"""
Stage 14 (Capstone STEP 11) - Text mining and NLP on the unstructured security text.

Two corpora, three tasks:

  Corpus 1 - 320 synthetic maintenance/incident tickets, each with a category label.
      Task A: classification. TF-IDF features + Logistic Regression, evaluated with a
      confusion matrix, precision, recall and F1 on a held-out 30 per cent. A labelled
      corpus is used deliberately so the NLP component can be VALIDATED, not just admired.
      Task B: indicator extraction. Regular expressions plus a gazetteer built from the
      ATT&CK malware list pull IP addresses, accounts, asset IDs, protocols and malware
      names out of free text. The tickets carry an answer key (gt_entities) so precision
      and recall of the extractor are measured, not assumed.

  Corpus 2 - 357 real MITRE ATT&CK for ICS descriptions.
      Task C: topic structure with NMF, and TF-IDF similarity between each ticket and the
      ATT&CK corpus, which is the enrichment step feeding the intelligence product in
      stage 12.

Outputs: outputs/tables/nlp_*.csv, outputs/figures/fig22*, fig23*
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import NMF
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (ConfusionMatrixDisplay, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_RAW, OUT_FIGS, OUT_TABLES, SEED, env_stamp, get_logger, write_json
from viz import CATEGORICAL, finish, plt

LOG = get_logger("s14_nlp")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ASSET_RE = re.compile(r"\bAST-\d{4}\b")
USER_RE = re.compile(r"\b(?:cont|main|ot|it|vend|mine|supe|cont)\w*\d{3}\b")
SITE_RE = re.compile(r"\b(?:PIT-[AB]|PLANT-01|TAILINGS-01|WORKSHOP-01|CAMP-01|HQ-WHK|PORT-WVB)\b")
PROTO_RE = re.compile(r"\b(Modbus/TCP|Modbus|DNP3|MQTT|SSH|RDP|HTTPS|SNMP|OPC ?UA)\b", re.I)

STOP_EXTRA = ["the", "and", "for", "with", "this", "that", "from", "are", "was", "were",
              "has", "have", "been", "not", "but", "can", "may", "will", "its"]


def clean_text(s: str) -> str:
    """Lowercase, strip punctuation that is not part of an indicator, collapse spaces."""
    s = str(s).lower()
    s = re.sub(r"[^a-z0-9\.\-/_ ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def classify_tickets(tk: pd.DataFrame) -> dict:
    X = tk["text"].map(clean_text)
    y = tk["category"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True,
                                  stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ]).fit(X_tr, y_tr)

    pred = pipe.predict(X_te)
    rep = classification_report(y_te, pred, output_dict=True, zero_division=0)
    pd.DataFrame(rep).T.to_csv(OUT_TABLES / "nlp_ticket_classification.csv")

    labels = sorted(pd.unique(y))
    cm = confusion_matrix(y_te, pred, labels=labels)
    fig, ax = plt.subplots(figsize=(5.6, 4.6))
    ConfusionMatrixDisplay(cm, display_labels=labels).plot(ax=ax, cmap="Blues",
                                                           colorbar=False, values_format="d")
    ax.set_title("Ticket classification (held-out 30%)")
    ax.tick_params(axis="x", rotation=35)
    ax.grid(False)
    finish(fig, ax, OUT_FIGS / "fig22_ticket_classification_cm.png")

    # which words drive the security_incident class - an analyst-readable explanation
    vec = pipe.named_steps["tfidf"]
    clf = pipe.named_steps["clf"]
    terms = np.array(vec.get_feature_names_out())
    cls_idx = list(clf.classes_).index("security_incident")
    top_terms = terms[np.argsort(clf.coef_[cls_idx])[-15:]][::-1]
    pd.DataFrame({"class": "security_incident", "top_term": top_terms}).to_csv(
        OUT_TABLES / "nlp_top_terms_security.csv", index=False)

    LOG.info("ticket classifier macro-F1=%.3f accuracy=%.3f",
             rep["macro avg"]["f1-score"], rep["accuracy"])
    return {"macro_f1": rep["macro avg"]["f1-score"], "accuracy": rep["accuracy"],
            "test_rows": int(len(y_te)), "top_security_terms": list(top_terms[:10]),
            "caveat": ("The tickets are generated from a template bank, so the vocabulary of "
                       "each category is highly consistent and the task is far easier than "
                       "real ticket text. Treat this score as evidence that the pipeline "
                       "works end to end, not as an estimate of accuracy on real tickets.")}


def extract_indicators(tk: pd.DataFrame, attack: pd.DataFrame) -> dict:
    malware_names = [n for n in attack.loc[attack.record_class == "malware", "name"].tolist()
                     if len(n) > 3]
    mal_re = re.compile(r"\b(" + "|".join(re.escape(m) for m in malware_names) + r")\b", re.I)

    rows = []
    for t in tk.itertuples():
        text = t.text
        found = {
            "ip": IP_RE.findall(text),
            "asset": ASSET_RE.findall(text),
            "user": USER_RE.findall(text),
            "site": SITE_RE.findall(text),
            "proto": [p if isinstance(p, str) else p[0] for p in PROTO_RE.findall(text)],
            "malware": mal_re.findall(text),
        }
        rows.append({
            "ticket_id": t.ticket_id, "category": t.category,
            **{f"{k}s_found": "|".join(sorted(set(v))) for k, v in found.items()},
            "n_indicators": sum(len(set(v)) for v in found.values()),
            "gt_entities": t.gt_entities,
        })
    ext = pd.DataFrame(rows)
    ext.to_csv(OUT_TABLES / "nlp_extracted_indicators.csv", index=False)

    # measure the extractor against the answer key embedded in the generator
    tp = fp = fn = 0
    for r in ext.itertuples():
        gt = {}
        for part in str(r.gt_entities).split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                gt[k] = v
        predicted = {
            "ip": set(filter(None, r.ips_found.split("|"))),
            "asset": set(filter(None, r.assets_found.split("|"))),
            "user": set(filter(None, r.users_found.split("|"))),
            "site": set(filter(None, r.sites_found.split("|"))),
            "proto": {p.lower() for p in filter(None, r.protos_found.split("|"))},
            "malware": {m.lower() for m in filter(None, r.malwares_found.split("|"))},
        }
        for key, want in gt.items():
            if key not in predicted:
                continue
            want_norm = want.lower() if key in ("proto", "malware") else want
            if want_norm in predicted[key] or any(want_norm in p for p in predicted[key]):
                tp += 1
            else:
                fn += 1
        for key, got in predicted.items():
            extra = len(got) - (1 if key in gt else 0)
            fp += max(extra, 0)
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-9)
    LOG.info("indicator extraction: precision=%.3f recall=%.3f f1=%.3f (tp=%d fp=%d fn=%d)",
             prec, rec, f1, tp, fp, fn)

    counts = {c.replace("s_found", ""): int(ext[c].str.len().gt(0).sum())
              for c in ext.columns if c.endswith("s_found")}
    fig, ax = plt.subplots(figsize=(7.4, 2.9))
    k = list(counts); v = [counts[x] for x in k]
    ax.bar(k, v, color=CATEGORICAL[0], width=0.6)
    for i, val in enumerate(v):
        ax.text(i, val, f"{val}", ha="center", va="bottom", fontsize=8, color="#444444")
    ax.set_title("Tickets containing each indicator type (n = 320)")
    ax.set_ylabel("tickets")
    finish(fig, ax, OUT_FIGS / "fig23_indicator_counts.png")

    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn,
            "tickets_with_any_indicator": int((ext["n_indicators"] > 0).sum()),
            "by_type": counts}


def topics_and_enrichment(tk: pd.DataFrame, attack: pd.DataFrame) -> dict:
    corpus = attack["text"].map(clean_text)
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_df=0.6, stop_words="english",
                          sublinear_tf=True)
    A = vec.fit_transform(corpus)
    nmf = NMF(n_components=6, random_state=SEED, init="nndsvda", max_iter=400).fit(A)
    terms = np.array(vec.get_feature_names_out())
    topic_rows = []
    for i, comp in enumerate(nmf.components_):
        top = terms[np.argsort(comp)[-12:]][::-1]
        topic_rows.append({"topic": f"T{i+1}", "top_terms": ", ".join(top)})
    topics = pd.DataFrame(topic_rows)
    topics.to_csv(OUT_TABLES / "nlp_attack_topics.csv", index=False)

    # enrichment: nearest ATT&CK description for every security ticket
    T = vec.transform(tk["text"].map(clean_text))
    sim = (T @ A.T).toarray()
    best = sim.argmax(axis=1)
    enrich = pd.DataFrame({
        "ticket_id": tk["ticket_id"].values,
        "category": tk["category"].values,
        "ticket_text": tk["text"].values,
        "nearest_attack_id": attack["record_id"].values[best],
        "nearest_attack_name": attack["name"].values[best],
        "nearest_attack_class": attack["record_class"].values[best],
        "similarity": sim.max(axis=1).round(3),
    }).sort_values("similarity", ascending=False)
    enrich.to_csv(OUT_TABLES / "nlp_ticket_attack_enrichment.csv", index=False)

    strong = enrich[enrich.similarity >= 0.15]
    LOG.info("ATT&CK enrichment: %d of %d tickets matched at similarity >= 0.15",
             len(strong), len(enrich))
    return {"topics": topic_rows, "matched_tickets": int(len(strong)),
            "median_similarity": float(enrich["similarity"].median()),
            "top_matches": enrich.head(5)[["ticket_id", "nearest_attack_id",
                                           "nearest_attack_name", "similarity"]]
                                  .to_dict(orient="records")}


def main() -> None:
    tk = pd.read_csv(DATA_RAW / "synthetic_maintenance_tickets.csv")
    attack = pd.read_csv(DATA_RAW / "attack_ics_text.csv")
    LOG.info("corpora: %d tickets, %d ATT&CK ICS descriptions (total %d text records)",
             len(tk), len(attack), len(tk) + len(attack))

    cls = classify_tickets(tk)
    ext = extract_indicators(tk, attack)
    top = topics_and_enrichment(tk, attack)

    write_json({"corpus_sizes": {"tickets": int(len(tk)), "attack_ics": int(len(attack)),
                                 "total": int(len(tk) + len(attack))},
                "classification": cls, "indicator_extraction": ext,
                "topics_and_enrichment": top, "env": env_stamp()},
               OUT_TABLES / "nlp_summary.json")


if __name__ == "__main__":
    main()
