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

The repository was assembled in one working session under deadline pressure, with AI
assistance (see `ai_assistance_disclosure.md`). The commit history therefore carries one
commit and one author. Before submission:

1. Push the repository to the group's remote.
2. Each member commits the modules they own **from their own account**, so the history
   reflects who actually touched what. Do not back-date commits or commit in the other
   member's name: a history that misstates authorship is worse for the group than a thin
   one, because the oral verification tests it directly.
3. Record the review notes above as issues or pull-request comments — that is the
   "review at least one component owned by the partner" requirement in section 4.2.
4. Keep the meeting notes and the signed contribution statement with the submission.

## If a member is unwell near the deadline

The specification (section 4.2) lets the Facilitator adjust individual marks on
contribution evidence, and it expects both members to speak at the presentation and answer
questions individually. That makes illness a matter to raise with the Facilitator, in
writing and early, rather than something to work around silently.

Practical sequence:

1. **Tell the Facilitator before the deadline**, naming the milestone affected and what the
   group proposes (submit on time with a note, or request an accommodation). A short,
   factual message is enough.
2. **Submit the technical work on time.** The pipeline, prototype and evidence are complete
   and belong to the group, so nothing is gained by holding the submission back.
3. **State in the contribution record what actually happened** — that the implementation
   was completed jointly under time pressure while one member was unwell. That sentence is
   defensible. A contribution statement that divides the work evenly when it was not is not
   defensible, and it is the member who signs it who carries that.
4. **The recovering member still has to be able to explain the whole solution** for the
   oral verification. `member_a_model_evaluation.md`, `member_a_data_dictionary.md`,
   `experiment_log.csv` and `presentation_speaker_notes.md` exist so that catching up is a
   reading task rather than a rebuilding task.
