# CERT r4.2: Temporal Insider-Threat Detection

## 1. Objective
Evaluate an Isolation Forest baseline for ranking suspicious user-day
activity using the CERT r4.2 synthetic enterprise dataset.

## 2. Dataset
- Sources: logon, device, file, email, and HTTP.
- Total events: 32,770,222.
- User-day records: 330,452.
- Unique users: 1,000.
- Date range: 2010-01-02 to 2011-05-17.
- Preparation script: `scripts/prepare_cert_r42.py`.
- Feature file: `data/processed/cert_r42_5source_user_day.csv`.

Raw data and derived datasets remain local. Verify the dataset licence
before distributing any data or derived artefacts.

## 3. Chronological Split
| Split | Date range | Records |
|---|---|---:|
| Train | 2010-01-02 to 2010-12-17 | 239,854 |
| Validation | 2010-12-18 to 2011-03-02 | 45,138 |
| Test | 2011-03-03 to 2011-05-17 | 45,460 |

## 4. Label Caveats
Two label definitions were evaluated: scenario-interval labels and
target-insider event-day labels. The answer-key audit matched 7,323 event
IDs to source events, with no missing IDs or timestamp/type mismatches.
Fifty rows had an event user different from the scenario target and were
excluded from target-insider event-day labels.

Labels represent known incident evidence, not exhaustive ground truth.
An unlabelled user-day must not automatically be treated as benign.

## 5. Baseline Method
- Model: Isolation Forest with 200 trees.
- Random seed: `42`.
- Input: 17 numeric features transformed using `log1p`.
- Training uses records labelled normal in the training period.
- Validation data is used for threshold selection.
- Alert-budget thresholds are selected on validation and applied unchanged
  to the test set.
- User IDs, dates, labels, and scenario metadata are excluded from features.

## 6. Test Results

### Scenario-interval labels
| Metric | Result |
|---|---:|
| ROC-AUC | 0.8363 |
| Average precision | 0.00821 |
| Test prevalence | 0.2618% |
| Recall | 85.71% |
| Precision | 1.055% |
| True positives | 102 |
| False positives | 9,564 |

### Target-insider event-day labels
| Metric | Result |
|---|---:|
| ROC-AUC | 0.8446 |
| Average precision | 0.00576 |
| Test prevalence | 0.1408% |
| Recall | 89.06% |
| Precision | 0.556% |
| True positives | 57 |
| False positives | 10,194 |

Both experiments show a high-recall, high-false-alert trade-off.
ROC-AUC alone is insufficient to establish operational usefulness.
Precision, average precision, and analyst alert capacity must also be considered.

## 7. Single-Feature Ranking Baselines
| Method | ROC-AUC | Average precision |
|---|---:|---:|
| Isolation Forest, 17 features | 0.8363 | 0.00821 |
| Off-hours count | 0.6227 | 0.00345 |
| Event count | 0.5895 | 0.00313 |
| Email count | 0.5026 | 0.00270 |
| HTTP count | 0.5147 | 0.00269 |

The multifeature baseline outperformed these single-feature ranking baselines
in this experiment. Further evaluation is needed before claiming generalisation
to real-world insider-threat activity.

## 8. Reproduction Commands

Run from the repository root using the virtual environment:

- `.venv/bin/python scripts/prepare_cert_r42.py`
- `.venv/bin/python scripts/evaluate_cert_r42.py`
- `.venv/bin/python scripts/evaluate_cert_r42_alert_budgets.py`
- `.venv/bin/python scripts/compare_cert_r42_ranking_baselines.py`
- `.venv/bin/python scripts/evaluate_cert_r42_target_eventday.py`
- `.venv/bin/python scripts/evaluate_cert_r42_target_eventday_alert_budgets.py`

Re-running data preparation requires the local CERT r4.2 source logs.
Check the dataset licence before publishing dataset-derived artefacts.

## 9. Experiment Outputs

CSV reports are stored under `reports/experiment_results/`:

- `cert_r42_isolation_forest.csv`
- `cert_r42_alert_budget_sensitivity.csv`
- `cert_r42_ranking_baselines.csv`
- `cert_r42_target_eventday_isolation_forest.csv`
- `cert_r42_target_eventday_alert_budget_sensitivity.csv`
- `cert_r42_label_definition_comparison.csv`

## 10. Limitations and Next Steps

- Labels may not capture every malicious user-day.
- The false-alert volume is high.
- Synthetic-data results do not establish effectiveness in real enterprises.
- Compare additional anomaly-detection and supervised baselines.
- Evaluate precision-recall curves and practical alert budgets.
- Investigate user-specific behaviour and temporal drift.
- Confirm dataset licensing before publishing derived artefacts.
