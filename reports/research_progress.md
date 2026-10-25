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

## Multi-Seed Threshold Sensitivity (20-Seed Study)

### Method

Evaluated 20 seeds (1–20), four synthetic scenarios, and seven temporal-window sizes (1, 2, 4, 6, 8, 12, and 24 hours). This produced 560 seed–scenario–window configurations. Each scored configuration was tested against thresholds 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.60, and 0.70, for 5,040 threshold-case rows.

The experiment reuses the temporal-window scores and changes the alert threshold. Target detection is determined by whether the target composite score meets or exceeds the threshold. Non-target alerts count scored windows other than the exact designated target window that meet or exceed the threshold.

### Results

| Threshold | Target detections | Detection rate | Non-target alert windows | Evaluations with one or more non-target alerts |
|---:|---:|---:|---:|---:|
| 0.20 | 559/560 | 99.82% | 2,736 | 304/560 (54.29%) |
| 0.25 | 552/560 | 98.57% | 336 | 148/560 (26.43%) |
| 0.30 | 545/560 | 97.32% | 0 | 0/560 (0%) |
| 0.35 | 428/560 | 76.43% | 0 | 0/560 (0%) |
| 0.40 | 202/560 | 36.07% | 0 | 0/560 (0%) |
| 0.45 | 156/560 | 27.86% | 0 | 0/560 (0%) |
| 0.50 | 148/560 | 26.43% | 0 | 0/560 (0%) |
| 0.60 | 8/560 | 1.43% | 0 | 0/560 (0%) |
| 0.70 | 0/560 | 0.00% | 0 | 0/560 (0%) |

At threshold 0.30, detection rates by scenario were:

- `large_transfer`: 133/140 (95.0%).
- `off_hours_new_device`: 134/140 (95.71%).
- `sensitive_access_burst`: 138/140 (98.57%).
- `short_anomaly_burst`: 140/140 (100%).

### Interpretation

Threshold 0.30 is a candidate threshold for subsequent validation on this synthetic dataset. At 0.25, seven more target cases were detected than at 0.30, but 336 non-target window alerts were generated. At 0.35, detection fell to 76.43%.

### Limitations

Non-target windows are defined as windows other than the exact designated target window; they are not individually verified benign examples. Window observations overlap across temporal-window sizes, so the 228,240 non-target window evaluations are not independent observations. The results therefore do not establish a real-world false-positive rate or a production-ready threshold. Further calibration on labeled, held-out real telemetry is required.

### Artifacts

- Raw rows: `reports/experiment_results/extended_multi_seed_threshold_sensitivity_results.csv`
- Overall summary: `reports/experiment_results/extended_multi_seed_threshold_sensitivity_summary.csv`
- Summary by window: `reports/experiment_results/extended_multi_seed_threshold_sensitivity_by_window.csv`
- Figure: `reports/figures/extended_multi_seed_threshold_sensitivity.png`
- Experiment runner: `scripts/run_multi_seed_threshold_sensitivity.py`
- Plotting script: `scripts/plot_threshold_sensitivity_multi_seed.py`

## Held-Out Evaluation of the Window-Aware Threshold Policy

### Protocol

Thresholds were selected using development seeds 1–20. The candidate policy uses threshold 0.30 for windows of 1–8 hours and threshold 0.25 for windows of 12–24 hours. The fixed thresholds 0.25 and 0.30 provide comparison baselines.

The candidate policy was evaluated on seeds 21–40, producing 560 seed–scenario–window cases and 5,040 rows across nine threshold settings. This is a held-out-seed synthetic evaluation, not validation on real organizational telemetry.

### Development and held-out comparison

| Cohort | Policy | Target detections | Non-target alerts |
|---|---|---:|---:|
| Development, seeds 1–20 | Fixed 0.25 | 552/560 (98.57%) | 336 |
| Development, seeds 1–20 | Fixed 0.30 | 545/560 (97.32%) | 0 |
| Development, seeds 1–20 | Window-aware | 552/560 (98.57%) | 0 |
| Held-out, seeds 21–40 | Fixed 0.25 | 549/560 (98.04%) | 372 |
| Held-out, seeds 21–40 | Fixed 0.30 | 539/560 (96.25%) | 0 |
| Held-out, seeds 21–40 | Window-aware | 549/560 (98.04%) | 0 |

### Held-out results by window

- 1 hour: 80/80 detections (100%).
- 2 hours: 80/80 (100%).
- 4 hours: 80/80 (100%).
- 6 hours: 80/80 (100%).
- 8 hours: 80/80 (100%).
- 12 hours: 75/80 (93.75%).
- 24 hours: 74/80 (92.50%).

### Held-out results by scenario

- `large_transfer`: 137/140 (97.86%).
- `off_hours_new_device`: 132/140 (94.29%).
- `sensitive_access_burst`: 140/140 (100%).
- `short_anomaly_burst`: 140/140 (100%).

### Interpretation

On held-out seeds, the window-aware policy detected 10 more target cases than fixed threshold 0.30, with no observed non-target alerts. It matched fixed threshold 0.25's target detection count while avoiding that threshold's 372 non-target alerts in the held-out cohort.

### Limitations

These results are evidence for further investigation, not proof of production readiness. Non-target windows are not individually verified benign examples. Window observations overlap across window sizes, so they are not all independent observations. Zero observed non-target alerts in this synthetic experiment does not establish a zero real-world false-positive rate. Additional validation on labeled, appropriately held-out telemetry is necessary.

### Artifacts

- Raw results: `reports/experiment_results/holdout_seed21_40_threshold_sensitivity_results.csv`
- Overall summary: `reports/experiment_results/holdout_seed21_40_threshold_sensitivity_summary.csv`
- By-window summary: `reports/experiment_results/holdout_seed21_40_threshold_sensitivity_by_window.csv`

## 60-Seed Window-Aware Policy Comparison

### Evaluation protocol

The candidate threshold policy was selected on development seeds 1–20: threshold 0.30 for windows of 1–8 hours and threshold 0.25 for windows of 12–24 hours. It was applied unchanged to seeds 21–40 and 41–60.

Each cohort comprises four scenarios and seven window sizes, yielding 560 seed–scenario–window cases per cohort. Each underlying run was evaluated at nine thresholds. The comparison script validates input row counts, seed membership, duplicate cases, target-score flags, and threshold monotonicity before generating its outputs.

### Cohort comparison

| Cohort | Policy | Target detections | Non-target alerts |
|---|---|---:|---:|
| Development, 1–20 | Fixed 0.25 | 552/560 (98.57%) | 336 |
| Development, 1–20 | Fixed 0.30 | 545/560 (97.32%) | 0 |
| Development, 1–20 | Window-aware | 552/560 (98.57%) | 0 |
| Held-out, 21–40 | Fixed 0.25 | 549/560 (98.04%) | 372 |
| Held-out, 21–40 | Fixed 0.30 | 539/560 (96.25%) | 0 |
| Held-out, 21–40 | Window-aware | 549/560 (98.04%) | 0 |
| Replication, 41–60 | Fixed 0.25 | 551/560 (98.39%) | 348 |
| Replication, 41–60 | Fixed 0.30 | 540/560 (96.43%) | 0 |
| Replication, 41–60 | Window-aware | 551/560 (98.39%) | 0 |

### Combined results: seeds 1–60

| Policy | Target detections | Detection rate | Non-target alerts |
|---|---:|---:|---:|
| Fixed threshold 0.25 | 1,652/1,680 | 98.33% | 1,056 |
| Fixed threshold 0.30 | 1,624/1,680 | 96.67% | 0 |
| Window-aware candidate | 1,652/1,680 | 98.33% | 0 |

### Window-specific candidate results

- 1 hour: 240/240 (100%).
- 2 hours: 240/240 (100%).
- 4 hours: 240/240 (100%).
- 6 hours: 240/240 (100%).
- 8 hours: 240/240 (100%).
- 12 hours: 226/240 (94.17%).
- 24 hours: 226/240 (94.17%).

### Interpretation

Across all 60 seeds, the window-aware policy matches fixed threshold 0.25's 1,652 target detections, while producing zero observed non-target alerts in the evaluated synthetic windows. It detects 28 more target cases than fixed threshold 0.30, which also produced zero observed non-target alerts in this experiment.

### Limitations

The results are from synthetic data. Non-target windows are not individually verified benign examples, and window observations overlap across window sizes. Zero observed non-target alerts does not establish a zero real-world false-positive rate or production readiness. Evaluation on appropriately labeled, held-out real telemetry is needed.

### Artifacts

- Comparison script: `scripts/compare_window_aware_policy_cohorts.py`
- Cohort summary: `reports/experiment_results/window_aware_policy_cohort_comparison.csv`
- By-window summary: `reports/experiment_results/window_aware_policy_by_window.csv`
- By-scenario summary: `reports/experiment_results/window_aware_policy_by_scenario.csv`
- Raw replication: `reports/experiment_results/replication_seed41_60_threshold_sensitivity_results.csv`
- Replication summary: `reports/experiment_results/replication_seed41_60_threshold_sensitivity_summary.csv`
- Replication by-window data: `reports/experiment_results/replication_seed41_60_threshold_sensitivity_by_window.csv`

## Score Component Ablation Study

### Experimental design

Ten scoring variants were evaluated across 60 synthetic seeds, four scenarios, seven window sizes, and nine thresholds, for 151,200 raw variant-threshold rows. The full composite combines temporal and context scores equally. The temporal signal weights deviation coverage at 0.50, zero-variance deviation coverage at 0.30, and magnitude at 0.20. The context signal equally averages sensitive-access, transfer, device, and IP signals.

Variants included temporal-only and context-only scoring, removal of each temporal component, and removal of each context component. Remaining component weights were renormalized following removal.

For each variant, the threshold was selected using seeds 1–20 by maximizing target detection among the tested thresholds with zero observed non-target alerts. That threshold was then held fixed for seeds 21–40 and 41–60.

### Results

| Variant | Threshold | Development detection | Held-out detection | Replication detection | Combined detection |
|---|---:|---:|---:|---:|---:|
| Full composite | 0.30 | 97.32% | 96.25% | 96.43% | 96.67% |
| Temporal only | 0.60 | 23.04% | 24.46% | 24.64% | 24.05% |
| Context only | 0.20 | 81.07% | 80.71% | 80.71% | 80.83% |
| No temporal deviation | 0.30 | 78.39% | 78.04% | 77.32% | 77.92% |
| No temporal zero-variance | 0.35 | 77.86% | 76.96% | 76.96% | 77.26% |
| No temporal magnitude | 0.30 | 96.43% | 95.00% | 95.36% | 95.60% |
| No sensitive-access context | 0.30 | 60.54% | 59.46% | 59.46% | 59.82% |
| No transfer context | 0.30 | 77.14% | 76.07% | 77.14% | 76.79% |
| No device context | 0.30 | 97.68% | 97.14% | 97.14% | 97.32% |
| No IP context | 0.30 | 98.04% | 97.50% | 97.68% | 97.74% |

All variants had zero observed non-target alerts at their selected threshold across the three cohorts.

### Interpretation

Removing temporal deviation, zero-variance deviation, sensitive-access context, or transfer context substantially reduced detection under the tested setup. Removing IP context improved detection modestly in all three cohorts; removing device context also improved it slightly. Context-only scoring outperformed temporal-only scoring at the selected zero-alert thresholds, but remained below the full composite.

These findings describe this scoring design and synthetic benchmark. Ablation reweights the remaining components, and each threshold was selected using a finite grid on the development cohort. Thus, the results are not isolated causal measures of feature importance.

### Limitations

Synthetic non-target windows are not individually verified benign cases, and temporal windows overlap. Zero observed alerts do not establish a zero real-world false-positive rate. Further validation on appropriately labeled, held-out real telemetry is required before making operational claims.

### Artifacts

- Runner: `scripts/run_score_component_ablation.py`
- Threshold selector: `scripts/summarize_score_component_ablation.py`
- Plotter: `scripts/plot_score_component_ablation.py`
- Raw rows: `reports/experiment_results/score_component_ablation_60_seed_results.csv`
- Summary: `reports/experiment_results/score_component_ablation_60_seed_summary.csv`
- By-window: `reports/experiment_results/score_component_ablation_60_seed_by_window.csv`
- By-scenario: `reports/experiment_results/score_component_ablation_60_seed_by_scenario.csv`
- Selected thresholds: `reports/experiment_results/score_component_ablation_selected_thresholds.csv`
- Figure: `reports/figures/score_component_ablation_selected_thresholds.png`
