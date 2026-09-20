# AI assistance disclosure

The project charter (section 12) commits the group to disclosing permitted AI assistance
and validating all outputs. This file is that disclosure. It is written to be attached to
the Milestone 2 submission.

## Tool used

Claude (Anthropic), used interactively on 19 September 2026 in a single working session.

## What the AI assistance produced

- The Python pipeline in `src/` (18 stage scripts plus shared helpers), the Streamlit
  console in `app/`, the walkthrough notebook and the test suite in `tests/`.
- The generated documentation in `docs/` and `outputs/`, including the data dictionary,
  model evaluation report, experiment log, executive brief, compliance checklist and these
  presentation notes. Every figure in those documents is read from the pipeline outputs by
  code, not typed in.
- The synthetic data generators (`s02`, `s03`) and the rules inside them.

## What the AI assistance did not do

- It did not supply any data. The ToN_IoT captures come from UNSW Canberra and the ATT&CK
  for ICS corpus from MITRE; both are cited with source URLs and commit hashes.
- It did not invent results. Every number in the reports is produced by running the code,
  and the pipeline reruns end to end in about 135 seconds so any figure can be checked.
- It did not write the project charter (Milestone 1), which the group produced.

## Validation carried out by the group

- `python src/run_all.py` reproduces every output from the raw sources.
- `python -m pytest tests -q` runs 16 test cases covering leakage control, data quality,
  threshold documentation, evidence citation and the compliance evidence files.
- Raw inputs are hashed (SHA-256) in `outputs/tables/data_inventory.csv`, so a marker can
  confirm the inputs were not altered.
- Known defects and limitations are recorded in `docs/known_defects_and_backlog.csv`
  rather than removed, including two errors found and fixed during development (the `NA`
  country-code parsing fault and an inflated adversarial baseline).

## Group responsibility

Both members are responsible for understanding and defending every component, including
those produced with AI assistance. The module ownership and review table in
`contribution_and_review.md` sets out who reviews what before submission.
