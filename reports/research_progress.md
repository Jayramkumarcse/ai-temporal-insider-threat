# Research Progress: AI-Based Temporal Behavioral Analysis for Insider Threat Detection

**Date:** 15 October 2026
**Status:** Initial implementation and synthetic experiments completed

## 1. Research Objective

Investigate whether temporal behavioral analysis can identify anomalous
user activity and provide useful early-warning signals for potential
insider threats.

The system produces behavioral anomaly indicators for investigation.
An anomaly score does not establish malicious intent.

## 2. Development Environment

- Environment: Ubuntu on Windows Subsystem for Linux 2
- Python: 3.14.4
- PyTorch: 2.14.0+cpu
- NumPy: 2.5.3
- Pandas: 3.0.6
- scikit-learn: 1.9.1
- Automated tests: 295 passed

## 3. Dataset and Processing

The tracked raw dataset contains 3,788 synthetic security events.
The repository preprocessing pipeline performs cleaning, normalization,
and temporal enrichment, producing:

`data/interim/clean_events.json`

The processed dataset is generated locally and is excluded from Git
by the existing data-directory ignore rules.

The primary experiment contains one known injected anomaly:

- User: USR-003
- Target window: 16 September 2026, 02:00 UTC
- Events: 56 in the target hour
- Sensitive accesses: 51
- Bytes transferred: 850,000,000

## 4. Temporal Window Comparison

The composite behavioral scoring approach was evaluated using
1-, 2-, 4-, 6-, 8-, 12-, and 24-hour windows with a threshold of 0.30.

| Window (hours) | Target score | Target rank | Non-target alerts | Detected |
|---:|---:|---:|---:|---|
| 1 | 0.705929 | 1 | 0 | Yes |
| 2 | 0.705929 | 1 | 0 | Yes |
| 4 | 0.705929 | 1 | 0 | Yes |
| 6 | 0.705929 | 1 | 0 | Yes |
| 8 | 0.705929 | 1 | 0 | Yes |
| 12 | 0.777810 | 1 | 0 | Yes |
| 24 | 0.772817 | 1 | 0 | Yes |

The highest target score occurred with a 12-hour window. The 24-hour
window had the largest reported ratio between the target score and
the highest non-target score.

These measures describe separation in this dataset; they do not
demonstrate that longer windows are generally superior.

## 5. Threshold Sensitivity

The experiment evaluated 3,000 hourly results at thresholds from
0.20 to 0.70.

| Threshold | Total alerts | Non-target alerts | Target detected |
|---:|---:|---:|---|
| 0.20 | 61 | 60 | Yes |
| 0.25 | 9 | 8 | Yes |
| 0.30 | 1 | 0 | Yes |
| 0.35 | 1 | 0 | Yes |
| 0.40 | 1 | 0 | Yes |
| 0.45 | 1 | 0 | Yes |
| 0.50 | 1 | 0 | Yes |
| 0.60 | 1 | 0 | Yes |
| 0.70 | 1 | 0 | Yes |

The target composite score was 0.705929. Raising the threshold from
0.20 to 0.30 substantially reduced the alert count while retaining
the target detection.

This is an exploratory sensitivity analysis, not an independent
estimate of the operational false-positive rate.

## 6. Scenario Window Comparison

Four controlled synthetic scenarios were evaluated at seven window
sizes each, for 28 combinations in total.

| Scenario | Detections | Highest target score | Best-scoring window |
|---|---:|---:|---:|
| Sensitive access burst | 7/7 | 0.438959 | 12 hours |
| Large transfer | 7/7 | 0.404198 | 24 hours |
| Off-hours, new device | 7/7 | 0.352221 | 12 hours |
| Short anomaly burst | 7/7 | 0.543888 | 12 hours |

Each injected target ranked first, and the evaluation reported zero
non-target alerts at the configured threshold of 0.30.

The off-hours/new-device scenario had the lowest maximum target score.
It should receive additional testing near the detection threshold.

## 7. Time-of-Day Comparison

The short anomaly burst was tested at 00:00, 02:00, 06:00, 10:00,
14:00, 18:00, and 22:00 UTC, using seven window sizes per hour.

All 49 combinations detected the injected target and ranked it first.
The highest target score was approximately 0.574041 at 14:00 UTC
with a one-hour window. The lowest mean target score by anomaly time
was approximately 0.507454 at 18:00 UTC.

These results show consistency across the tested controlled
configurations. They do not establish generalization to real
workplace schedules or unseen behavior.

## 8. LSTM Autoencoder

The LSTM autoencoder was trained on six-hour sequences containing
five behavioral features.

| Dataset split | Sequences |
|---|---:|
| Training | 815 |
| Validation | 240 |
| Test | 240 |
| Total | 1,295 |

Training used 20 epochs. The reconstruction threshold was selected
from validation data and was 0.1304134876.

### Exact-window evaluation

| Metric | Result |
|---|---:|
| True positives | 1 |
| False positives | 5 |
| True negatives | 234 |
| False negatives | 0 |
| Precision | 0.166667 |
| Recall | 1.000000 |
| F1 | 0.285714 |

The target anomaly had a reconstruction score of 146.4574 and ranked
third among the 240 test sequences.

### Context-window evaluation

| Metric | Result |
|---|---:|
| True positives | 6 |
| False positives | 0 |
| True negatives | 234 |
| False negatives | 0 |
| Precision | 1.000000 |
| Recall | 1.000000 |
| F1 | 1.000000 |

The six context-positive sequences overlap and contain the same
underlying injected anomaly. They are not six independent incidents.
The context metrics must not replace the exact-window results.

## 9. Model Comparison

The Round 10 comparison reproduced the following results.

| Model | Alerts | Precision | Recall | F1 | Target rank |
|---|---:|---:|---:|---:|---:|
| Hourly Isolation Forest | 1 | 1.000000 | 1.000000 | 1.000000 | 1 |
| Statistical / Hybrid | 2 | 0.500000 | 1.000000 | 0.666667 | 1 |
| LSTM autoencoder | 6 | 0.166667 | 1.000000 | 0.285714 | 3 |

In this experiment, Hourly Isolation Forest produced the fewest alerts
and the highest exact-window F1 score. The LSTM provided a
sequence-reconstruction signal that can be inspected over time, but
generated five non-target alerts under the exact-window definition.

The results are specific to this dataset, labeling scheme, temporal
representation, and threshold-selection protocol.

## 10. Multi-Seed Scenario Robustness Experiment

### Experimental design

The scenario-window evaluation was repeated across five synthetic background-generation seeds: 7, 21, 42, 84, and 123. Four controlled anomaly scenarios were tested at seven temporal window sizes (1, 2, 4, 6, 8, 12, and 24 hours), using a fixed alert threshold of 0.30.

The experiment comprised 140 evaluations. Scenario definitions, target user, evaluation dates, window sizes, minimum-history setting, and threshold were held constant while the synthetic background generator seed varied.

### Results

- Target detection: 136 of 140 evaluations (97.1%).
- Target ranking: first in all 140 evaluations.
- Non-target alerts: zero across the evaluated runs.
- All 20 evaluations for each window size from 1 through 8 hours detected the target.
- At 12 hours and 24 hours, detection was 3/5 for the large-transfer scenario and 5/5 for each of the other three scenarios.
- The four missed detections occurred for the large-transfer scenario with seeds 84 and 123 at 12-hour and 24-hour windows.

The missed targets still ranked first, illustrating that relative anomaly ranking and fixed-threshold alerting measure different things. In these runs, the target ranked above other windows but did not reach the configured alert threshold.

### Interpretation and limitations

These results suggest that detection sensitivity can depend on temporal-window size and generated background activity, particularly for the large-transfer scenario. However, this remains an exploratory synthetic-data experiment: five seeds and four controlled scenarios are not sufficient to establish real-world generalization. Zero non-target alerts in this experiment does not establish that the method would have zero false alerts on operational telemetry.

### Reproducibility

The experiment is implemented in `scripts/run_multi_seed_experiment.py`. The five seeds, four scenarios, seven window sizes, and threshold are defined in that script. Raw per-run results and scenario/window summary statistics are saved separately from the original baseline experiment outputs.

### Extended 20-seed evaluation

The experiment was expanded to seeds 1–20, retaining the four controlled synthetic scenarios, seven window sizes, and threshold of 0.30. This produced 560 evaluations.

- Target detection: 545/560 (97.3%).
- Target ranked first: 560/560.
- Non-target alerts: zero in these controlled runs.
- Detection was 80/80 for each window size from 1 to 8 hours, 74/80 (92.5%) for 12 hours, and 71/80 (88.75%) for 24 hours.
- By scenario, detection was 133/140 (95.0%) for large transfer, 134/140 (95.7%) for off-hours new device, 138/140 (98.6%) for sensitive access burst, and 140/140 (100%) for short anomaly burst.

The 15 missed detections occurred at 12-hour and 24-hour windows. The target still ranked first in each case, but its score was below the configured threshold of 0.30. This distinguishes relative anomaly ranking from threshold-based detection.

The results are from synthetic background variation and four controlled scenarios. Twenty seeds improve the robustness assessment relative to the initial five-seed study but do not establish generalization to real-world telemetry.

The extended experiment outputs are saved in:
- `reports/experiment_results/extended_multi_seed_scenario_results.csv`
- `reports/experiment_results/extended_multi_seed_scenario_summary.csv`

## 11. Limitations

1. The data is synthetic; real organizational telemetry has not yet
   been evaluated.
2. The primary dataset contains one known injected anomaly.
3. Scenario experiments use controlled injected behaviors and do not
   constitute independent real-world incident validation.
4. A window not labeled as anomalous is not necessarily proven benign.
5. The models use different temporal representations, complicating
   direct comparisons.
6. Overlapping LSTM sequences create correlated observations.
7. Threshold sensitivity should be evaluated on held-out data and
   calibrated using validation data, not selected from test results.
8. An anomaly score indicates unusual behavior, not malicious intent.
9. Twenty seeds across four controlled scenarios provide a broader but still limited assessment of background variation; they do not establish robustness to population changes or unseen scenarios.

## 12. Next Research Steps

1. Expand anomaly variants and strengths, add target users and scenario designs, and test additional seeds beyond the 20 evaluated.
2. Use a clearly separated training, validation, and test protocol.
3. Select thresholds on validation data and freeze them before testing.
4. Compare models using explicitly documented and comparable labels.
5. Report precision, recall, F1, false alerts per user/day, and
   detection delay where the data supports those metrics.
6. Evaluate performance on additional scenarios and, when available
   and appropriate, an independent real-world or public dataset.
7. Record software versions, seeds, configurations, and result files.
8. Avoid interpreting synthetic-scenario success as proof of
   operational insider-threat detection.

## 13. Reproducibility Artifacts

Current experiment result files:

- `reports/experiment_results/multi_seed_scenario_results.csv`
- `reports/experiment_results/multi_seed_scenario_summary.csv`
- `scripts/run_multi_seed_experiment.py`
- `reports/experiment_results/temporal_window_comparison.csv`
- `reports/experiment_results/threshold_sensitivity.csv`
- `reports/experiment_results/scenario_window_comparison.csv`
- `reports/experiment_results/time_of_day_comparison.csv`
- `reports/round10/round10_model_comparison.md`
- `reports/lstm/round9_lstm_experiment.md`

The local processed dataset is generated from `data/raw/events.json`
using the repository's preprocessing pipeline.
