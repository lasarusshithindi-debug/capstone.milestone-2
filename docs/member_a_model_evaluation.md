# Model evaluation report

*Member A deliverable (data and modelling lead). Every figure is read from the pipeline outputs by `src/s17_member_a_pack.py`; nothing is typed in by hand.*

## 1. What was modelled, and why

Three modelling problems were set, each matching a question in the charter:

1. **Network intrusion detection** on ToN_IoT Zeek flows - can an attack flow be separated from ordinary traffic? (charter question 1)
2. **Attack family identification** - if it is an attack, which kind? This decides which playbook an analyst opens.
3. **OT protocol abuse** on Modbus telemetry - the mining-specific case, since Modbus is the protocol that touches physical plant.

## 2. Preparation and leakage control

The flow dataset contains **20,569 exact duplicate rows**. These were removed *before* the train/test split, leaving 190,474 rows. Splitting first would have allowed the same record to appear on both sides of the split and would have inflated every score.

Class balance in the modelling set: **148,434 attack** rows and **42,040 normal** rows, so attacks are 78% of the data. The minority class here is *normal* traffic, which is the opposite of an operational network and matters for the anomaly work in section 5. Class weighting was applied in every classifier so the imbalance does not simply push predictions towards the majority.

Features: 18 numeric flow measures (durations, byte and packet counts, ratios and logarithmic transforms, ports) and 3 categorical fields (`proto`, `service`, `conn_state`), one-hot encoded with rare categories grouped.

## 3. Model selection

Selection used 3-fold cross-validated F1 on the **training data only**. The test set was scored once, at the end.

| Model | CV F1 (mean) | CV F1 (sd) |
|---|---:|---:|
| random_forest | 0.9983 | 0.0001 |
| decision_tree | 0.9924 | 0.0006 |
| logistic_regression | 0.9690 | 0.0015 |

**Random Forest** was selected. The justification is not that it scored highest by a fraction, but that flow data is a mixture of skewed numeric measures and categorical protocol fields with strong interactions, which is exactly the structure a tree ensemble handles without scaling assumptions. Logistic regression is retained as a transparent baseline, and the decision tree as an auditable rule set an OT engineer can read.

## 4. Held-out performance

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.9556 | 0.9934 | 0.9493 | 0.9708 | 0.9944 | 0.9983 |
| decision_tree | 0.9923 | 0.9959 | 0.9942 | 0.9951 | 0.9959 | 0.9977 |
| random_forest | 0.9980 | 0.9987 | 0.9987 | 0.9987 | 1.0000 | 1.0000 |

**Reading these numbers in security terms.** At the Random Forest's operating point, recall of 0.9987 means roughly 13 attack flows in every 10,000 would be missed, and precision of 0.9987 means about 13 false alarms per 10,000 flagged flows. For a SOC, the false-alarm rate is what decides whether the detector is usable at all, which is why precision is reported beside recall rather than accuracy alone.

Logistic regression reaches F1 0.9708, so a large part of this problem is linearly separable, but it misses 5.1% of attacks against 0.1% for the forest. On 211,000 flows that difference is thousands of missed events.

### Attack family identification

Macro-F1 **0.9645** across 10 labelled families.

| Family | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| backdoor | 1.000 | 1.000 | 1.000 | 5,613 |
| ddos | 0.988 | 0.982 | 0.985 | 5,998 |
| dos | 0.994 | 0.982 | 0.988 | 5,698 |
| injection | 0.982 | 0.968 | 0.975 | 5,989 |
| mitm | 0.662 | 0.846 | 0.743 | 312 |
| normal | 0.995 | 0.997 | 0.996 | 12,612 |
| password | 0.996 | 0.989 | 0.992 | 5,959 |
| ransomware | 0.999 | 1.000 | 0.999 | 4,421 |
| scanning | 0.991 | 0.993 | 0.992 | 6,000 |
| xss | 0.963 | 0.986 | 0.975 | 4,541 |

The weakest class is **mitm**, with only 312 test examples. That is a data-volume limitation rather than a modelling failure, and it should be stated as such: a class with a few hundred examples cannot be evaluated with confidence.

### Modbus telemetry (OT protocol)

| Model | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| logistic_regression | 0.6244 | 0.5735 | 0.5917 | 0.5825 |
| random_forest | 0.9901 | 0.9998 | 0.9779 | 0.9887 |

The gap here is the interesting result: logistic regression reaches F1 0.5825 while the forest reaches 0.9887. Register values from a manipulated Modbus device are not high or low in a straight line; they are abnormal in combination, so a linear model cannot separate them and a tree ensemble can.

## 5. What the detector actually uses

Permutation importance (mean F1 drop when a feature is shuffled):

| Feature | Importance | SD |
|---|---:|---:|
| `proto` | 0.0608 | 0.0007 |
| `service` | 0.0008 | 0.0001 |
| `is_internal_dst` | 0.0007 | 0.0002 |
| `dst_port` | 0.0006 | 0.0002 |
| `src_ip_bytes` | 0.0005 | 0.0001 |
| `src_port` | 0.0004 | 0.0001 |
| `is_wellknown_dst_port` | 0.0003 | 0.0001 |
| `bytes_per_pkt` | 0.0002 | 0.0001 |

`proto` dominates. This is worth saying honestly in the defence: the model leans heavily on protocol and connection-state fields rather than on traffic volume, which is also why the evasion test in section 7 barely moves the score - the evasion we simulated changed volume, not protocol.

## 6. Unsupervised detection

Two framings were run on the same data, and the contrast is the main methodological finding of the project.

- **Fully unsupervised** (fit on everything, no labels): ROC-AUC **0.279** - below chance.
- **Novelty detection against a known-good baseline** (fit on normal traffic only, scored on unseen flows): ROC-AUC **0.716**.

Fully unsupervised outlier detection performs below chance here (ROC-AUC 0.28) because attack traffic is the majority class in this capture. Learning the profile of known-good traffic and scoring novelty against it raises ROC-AUC to 0.72. The operational lesson for the mine is that anomaly detection needs a trusted baseline window, not simply 'whatever is rare today'.

Operating points for the fully unsupervised run:

| Alert budget (top %) | Flagged | Precision | Recall |
|---|---:|---:|---:|
| top 20% | 16,000 | 0.565 | 0.145 |
| top 15% | 12,000 | 0.609 | 0.118 |
| top 10% | 8,000 | 0.695 | 0.089 |
| top 5% | 4,000 | 0.720 | 0.046 |
| top 1% | 800 | 0.593 | 0.008 |

Operating points for the clean-baseline run:

| Threshold quantile | Flagged | Precision | Recall |
|---|---:|---:|---:|
| 0.50 | 34,671 | 0.935 | 0.521 |
| 0.70 | 20,795 | 0.974 | 0.326 |
| 0.80 | 13,863 | 0.975 | 0.217 |
| 0.90 | 6,936 | 0.962 | 0.107 |

### Access behaviour (user-days)

| Method | Flagged | Precision vs injected | Recall vs injected | ROC-AUC |
|---|---:|---:|---:|---:|
| iso | 56 | 0.643 | 0.818 | 0.997 |
| lof | 56 | 0.107 | 0.136 | 0.501 |

Isolation Forest separates the injected behaviour almost perfectly; Local Outlier Factor does not beat chance on the same features. The likely reason is that the injected behaviour is globally unusual rather than locally unusual - the accounts concerned sit far from the whole population, not just from their immediate neighbours - and LOF measures local density.

**Threshold.** The operating threshold is the 98th percentile of the score, which flags about 2 per cent of user-days. That is an alerting budget decision, not a statistical one: it is roughly two cases per working day for a 114-account estate.

## 7. Robustness and adversarial testing

| Test | Setting | F1 | Change vs unmodified |
|---|---|---:|---:|
| T0_baseline | unmodified held-out flows | 0.9987 | +0.0000 |
| T1_drift_noise | multiplicative Gaussian noise, sigma=0.05 | 0.9983 | -0.0004 |
| T1_drift_noise | multiplicative Gaussian noise, sigma=0.15 | 0.9953 | -0.0033 |
| T1_drift_noise | multiplicative Gaussian noise, sigma=0.3 | 0.9877 | -0.0110 |
| T2_evasion | attack flows padded x1.5 and slowed x2.0, conn_state=sf | 0.9986 | -0.0001 |
| T2_evasion | attack flows padded x3.0 and slowed x5.0, conn_state=sf | 0.9982 | -0.0005 |
| T2_evasion | attack flows padded x6.0 and slowed x10.0, conn_state=sf | 0.9977 | -0.0010 |
| T3_missing_data | 10% of feature values lost | 0.9906 | -0.0081 |
| T3_missing_data | 25% of feature values lost | 0.9499 | -0.0488 |
| T3_missing_data | 50% of feature values lost | 0.7728 | -0.2258 |
| T4_label_poisoning | 5% of training labels flipped | 0.9979 | -0.0008 |
| T4_label_poisoning | 15% of training labels flipped | 0.9944 | -0.0042 |
| T4_label_poisoning | 30% of training labels flipped | 0.9582 | -0.0405 |

**Interpretation.** Collection reliability is the biggest risk: losing half the fields costs more than a quarter of the F1, so telemetry completeness is itself a security control. Label poisoning has to reach roughly a third of the training set before it does comparable damage, which argues for controlling who can label data. The evasion test is the weakest of the four, because it perturbs volume features while the model relies on protocol fields - a stronger test is recorded as backlog item B02 rather than claimed as a result.

## 8. Predictive risk model

The daily risk score separates the injected behaviour with ROC-AUC **0.988** and precision at the top 20 user-days of **0.75**.

The next-day early-warning model is weak: ROC-AUC **0.528** on a time-ordered split, against a base rate of 0.082. This is reported as a negative result. Alerts in this data are driven by single events rather than by a build-up in the preceding day's behaviour, so there is little for a next-day model to learn. A longer observation window, or event-level rather than day-level features, would be the next thing to try.

## 9. Limitations that must be stated

1. ToN_IoT is a controlled testbed. Scores near 1.0 reflect a clean laboratory capture, not what the same model would achieve on live mining traffic.
2. Attacks are the majority class in the capture, which is unlike any real network and directly explains the unsupervised result in section 6.
3. The access-behaviour results are measured against behaviour that we injected ourselves, so they demonstrate that the method works, not that an attacker was found.
4. The Modbus and flow models are trained on the same testbed environment, so they would need recalibration against site data before any operational use.
