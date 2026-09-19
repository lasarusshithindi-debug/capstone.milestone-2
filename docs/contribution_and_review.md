# Contribution and review record — T08

**Member A:** 222093471 Sophia Kalume — Data and Modelling Lead
**Member B:** 215103815 Lasarus Shithindi — Security Engineering and Intelligence Lead

The charter's RACI allocation is carried through into the code: each module below has a
primary owner, and the partner reviews it. Both members must be able to explain every
module during the oral verification, so the review column is not a formality.

## Module ownership

| Module | File | Owner | Reviewer | Review evidence to record |
|---|---|---|---|---|
| Data acquisition and provenance | `src/s01`, `src/s04` | A | B | B confirms hashes and licence statements |
| Synthetic source generation | `src/s02`, `src/s03` | B | A | A checks the generation rules and the seed |
| Cleaning and features | `src/s06` | A | B | B reads `cleaning_log.csv` and challenges two actions |
| Baselines and EDA | `src/s07` | A | B | B validates the baselines against the scenario |
| Supervised models | `src/s08` | A | B | B checks the leakage control and the metric choice |
| Anomaly detection | `src/s09` | A | B | B interprets the flagged user-days operationally |
| Access analytics (UEBA) | `src/s10` | B | A | A reviews thresholds against the measured baselines |
| Investigation and response | `src/s11` | B | A | A checks that every timeline row cites evidence |
| Intelligence products | `src/s12` | B | A | A checks the ATT&CK mapping confidence labels |
| Simulation | `src/s13` | B | A | A checks the assumption table and sensitivity |
| Text mining | `src/s14` | B | A | A checks the extractor scoring method |
| Risk score and adversarial tests | `src/s15` | A | B | B checks the band cut-points against alert capacity |
| Architecture and compliance | `src/s16`, `src/s20` | Both | Both | joint sign-off |
| Prototype | `app/app.py` | Both | Both | both demonstrate it live |
| Tests and reproducibility | `tests/`, `src/run_all.py` | A | B | B runs the pipeline from a clean checkout |

## Presentation split (10 minutes + 5 Q&A)

| Section | Minutes | Speaker |
|---|---|---|
| Problem, scenario, data sources and their status | 2 | B |
| Pipeline, baselines and data quality | 2 | A |
| Supervised and anomaly results, including the negative result | 2.5 | A |
| Investigation, access analytics and intelligence | 2 | B |
| Simulation, risk, robustness and the prototype demo | 1.5 | Both |

## Contribution evidence still to produce (task T18)

The repository was assembled in one working session, so the commit history does not yet
show both members. Before submission:

1. Initialise the repository and push it to the group's remote.
2. Each member commits the modules they own, from their own machine and account, so the
   history carries both names. Do not back-date or impersonate: commit what you actually
   touched.
3. Record the review notes above as issues or pull-request comments — that is the
   "review at least one component owned by the partner" requirement in section 4.2 of the
   capstone specification.
4. Keep the meeting notes and the signed contribution statement with the submission.
