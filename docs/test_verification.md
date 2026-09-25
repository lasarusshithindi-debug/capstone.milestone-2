# Test Verification - Sophia-222093471

**Date:** 25 September 2026
**Environment:** [Python 3.14.4], Windows

## What I ran
- `python src/run_all.py` — full pipeline (stages 01–20), to generate the processed data the tests depend on
- `python -m pytest tests -q` — full test suite (16 test cases)

## Results
Pipeline: completed successfully, produced `data/processed/network_flows.parquet`, `access_events.parquet`, and other expected outputs 
Tests: 16 passed, 0 failed (0.63s)
Note: on a first run before the pipeline has generated processed data, 4 tests fail with `FileNotFoundError` because they depend on `network_flows.parquet` and `access_events.parquet` which is the expected pipeline ordering, not a code defect, and resolves once `run_all.py` completes.

## Issues found
After resolving the working directory location, all tests passed after running the full pipeline.