# Data sources, licences and attribution

This folder holds the raw inputs exactly as obtained. Nothing here is modified by the
pipeline; every stage reads these files and writes elsewhere.

## 1. ToN_IoT datasets (real research data)

**Source:** Cyber Range and IoT Labs, UNSW Canberra —
<https://research.unsw.edu.au/projects/toniot-datasets>

Included here:

| Folder | Files | Content |
|---|---|---|
| `ton_iot_gh/Train_Test_IoT_dataset/` | 7 CSVs | IoT/IIoT telemetry (fridge, garage door, GPS tracker, Modbus, motion/light, thermostat, weather), labelled |
| `netrepo/data/TON_IoT_Train_Test_Network.csv` | 1 CSV | Zeek network flow records, 44 fields, labelled |

**Licence, as published by the dataset authors:** "Free use of the TON_IoT datasets for
academic research purposes is hereby granted in perpetuity. Use for commercial purposes is
allowable after asking the author" (Dr Nour Moustafa). The datasets were sponsored by the
Australian Research Data Commons and UNSW Canberra. They are included in this submission
solely for academic assessment of the SAS821S capstone.

**Citations requested by the dataset authors** (the project page asks that all of these be
cited):

1. Moustafa, N. (2021). A new distributed architecture for evaluating AI-based security
   systems at the edge: Network TON_IoT datasets. *Sustainable Cities and Society*, 102994.
2. Booij, T.M., et al. (2021). ToN IoT — The role of heterogeneity and the need for
   standardization of features and attack types in IoT network intrusion datasets.
   *IEEE Internet of Things Journal*.
3. Alsaedi, A., et al. (2020). TON_IoT telemetry dataset: a new generation dataset of IoT
   and IIoT for data-driven Intrusion Detection Systems. *IEEE Access*, 8, 165130–165150.
4. Moustafa, N., et al. (2020). Federated TON_IoT Windows Datasets for Evaluating AI-Based
   Security Applications. *IEEE TrustCom 2020*, 848–855.
5. Moustafa, N., et al. (2020). Data Analytics-Enabled Intrusion Detection: Evaluations of
   ToN_IoT Linux Datasets. *IEEE TrustCom 2020*, 727–735.
6. Moustafa, N. (2019). New Generations of Internet of Things Datasets for Cybersecurity
   Applications based Machine Learning: TON_IoT Datasets. *eResearch Australasia Conference*.
7. Moustafa, N. (2019). A systemic IoT-Fog-Cloud architecture for big-data analytics and
   cyber security systems: a review of fog computing. *arXiv:1906.01055*.
8. Ashraf, J., et al. (2021). IoTBoT-IDS: A Novel Statistical Learning-enabled Botnet
   Detection Framework for Protecting Networks of Smart Cities. *Sustainable Cities and
   Society*, 103041.

**How these copies were obtained.** The official distribution is a SharePoint folder that
cannot be fetched non-interactively, so the two subsets were taken from public GitHub
mirrors and checked against the published row counts and field lists:

```
git clone --depth 1 https://github.com/PengaloGit/ToN_IoT-datasets.git data/raw/ton_iot_gh
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/thawatchai2799/SecurityArchitectureSmartCityIoT.git data/raw/netrepo
cd data/raw/netrepo && git sparse-checkout set data
```

Note the known limitation recorded as defect D01: the flow mirror does **not** carry the
`ts` timestamp column present in the original UNSW release, so joins to that source are made
on address and asset rather than on time.

## 2. MITRE ATT&CK for ICS (real public data)

**Source:** <https://github.com/mitre-attack/attack-stix-data> —
`ics-attack/ics-attack.json`, upstream commit recorded in `attack_bundle/SOURCE_COMMIT.txt`.

**Terms:** MITRE ATT&CK® is made available free of charge; use requires attribution. See
<https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>. © 2026 The MITRE
Corporation. This project uses the ATT&CK for ICS descriptions as an unstructured
security-text corpus and for enrichment; ATT&CK is not affiliated with this work and does
not endorse it.

## 3. Synthetic data generated for this project

| File | Generator | Status |
|---|---|---|
| `synthetic_remote_access_log.csv` | `src/s02_generate_context_and_access.py` | SYNTHETIC |
| `mining_asset_inventory.csv` | `src/s02_generate_context_and_access.py` | SYNTHETIC |
| `mining_user_directory.csv` | `src/s02_generate_context_and_access.py` | SYNTHETIC |
| `synthetic_maintenance_tickets.csv` | `src/s03_generate_tickets.py` | SYNTHETIC |
| `attack_ics_text.csv` | `src/s01_extract_attack_text.py` (extract of the ATT&CK bundle) | derived from real data |

The synthetic files contain no real person, account, credential, address or system. Four
abnormal access patterns were injected deliberately and are recorded in the `gt_scenario`
column so that detection can be validated against known ground truth. Generation is
deterministic: seed 3815.

## 4. Integrity

SHA-256 hashes of every raw file are recorded in `outputs/tables/data_inventory.csv`, so a
marker can confirm that the inputs were not edited after the analysis was run.
