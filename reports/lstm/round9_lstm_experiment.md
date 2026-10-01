# Round 9 — LSTM Temporal Sequence Anomaly Detection

## 1. Experiment Objective

Evaluate whether an LSTM autoencoder can identify anomalous temporal behavior from fixed-length sequences of hourly user-behavior windows.

The experiment focuses on behavioral anomaly detection and temporal localization. It does not classify a user as malicious.

---

## 2. Temporal Representation

Each timestep represents one anchored 1-hour behavioral window for a single user.

Sequence length:

- 6 consecutive hourly windows

Sequence features:

1. `event_count`
2. `sensitive_access_count`
3. `bytes_transferred`
4. `unique_devices`
5. `unique_ips`

Therefore, each sequence has shape:

`6 × 5`

Sequences are constructed independently for each user and ordered chronologically.

---

## 3. Dataset Split

The sequence dataset contains 1,295 sequences.

Chronological split:

| Split | Date range | Sequences |
|---|---|---:|
| Training | Sep 6–12, 2026 | 815 |
| Validation | Sep 13–14, 2026 | 240 |
| Test | Sep 15–16, 2026 | 240 |

The split is chronological to avoid using future observations during model training.

The known synthetic anomaly occurs for:

- User: `USR-003`
- Date: `2026-09-16`
- Anomalous window: `02:00 UTC`

The anomalous target sequence is therefore contained only in the held-out test set.

---

## 4. Feature Scaling

Feature scaling is fitted using training sequences only.

The same fitted scaler is reused for validation and test data.

`bytes_transferred` is transformed using:

`log1p(bytes_transferred)`

before standardization because the feature contains a highly skewed distribution with predominantly zero values and a large anomalous transfer.

---

## 5. LSTM Autoencoder

Model:

- Input size: 5
- Hidden size: 16
- Sequence length: 6
- Encoder: LSTM
- Decoder: Linear layer
- Reconstruction objective: Mean Squared Error

The model reconstructs the complete input sequence.

For each sequence, reconstruction error is calculated as the mean squared reconstruction error across all timesteps and features.

---

## 6. Training Configuration

Training configuration:

- Optimizer: Adam
- Learning rate: `0.001`
- Batch size: `32`
- Epochs: `20`
- Random seed: `42`
- Loss function: MSE

The model is trained only on the chronological training split.

---

## 7. Threshold Selection

The anomaly threshold is selected using the maximum reconstruction error observed on the validation set.

Validation reconstruction-error statistics:

- Mean: `0.0160323642`
- Median: `0.0107042957`
- 95th percentile: `0.0521652475`
- 99th percentile: `0.0859286487`
- Maximum / threshold: `0.1304134876`

No test observations are used to select the threshold.

---

## 8. Exact-Window Evaluation

Default sequence-level ground truth labels a sequence as anomalous only when its target window exactly matches the known anomalous window.

Results:

| Metric | Value |
|---|---:|
| True Positive | 1 |
| False Positive | 5 |
| True Negative | 234 |
| False Negative | 0 |
| Precision | 0.1667 |
| Recall | 1.0000 |
| F1 | 0.2857 |

The target anomaly produced a reconstruction score of approximately:

`146.4574`

compared with the validation threshold:

`0.1304`

The target sequence was ranked `3 / 240` by reconstruction score.

---

## 9. Context-Window Evaluation

Because the sequences overlap temporally, an anomalous 02:00 window appears inside six consecutive six-hour sequences.

A context-level label therefore treats a sequence as positive when its six-hour input contains the known anomalous timestep.

Results:

| Metric | Value |
|---|---:|
| True Positive | 6 |
| False Positive | 0 |
| True Negative | 234 |
| False Negative | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 | 1.0000 |

This result is specific to the current synthetic anomaly scenario and should not be interpreted as generalized real-world model performance.

---

## 10. Temporal Localization

Per-timestep reconstruction errors were inspected for the six overlapping sequences containing the known anomalous 02:00 window.

The maximum reconstruction error occurred at the timestep corresponding to the known anomalous window in each overlapping sequence.

This indicates that, in this synthetic experiment, the LSTM reconstruction error provides temporal localization in addition to sequence-level anomaly scoring.

---

## 11. Target Anomaly Characteristics

The anomalous target window contains substantially elevated behavioral activity:

- Event count: `56`
- Sensitive accesses: `51`
- Bytes transferred: `850,000,000`
- Unique devices: `2`
- Unique IPs: `2`

The target sequence's final timestep therefore differs strongly from the normal training distribution.

---

## 12. Interpretation

The LSTM autoencoder successfully reconstructs normal temporal behavior learned from the training period and produces substantially higher reconstruction error for the held-out synthetic anomaly.

The exact-window evaluation produces five false positives because overlapping sequences continue to contain the anomalous timestep in their historical context.

Consequently, exact-target evaluation and context-window evaluation represent different operational definitions of an alert.

The context result demonstrates that the model detected the temporal region surrounding the synthetic anomaly without generating false positives among the remaining test sequences in this experiment.

---

## 13. Limitations

This experiment has important limitations:

1. The dataset is synthetic.
2. Only one known anomalous user-day is used as ground truth.
3. The anomaly is intentionally structured and highly distinctive.
4. The experiment does not establish real-world insider-threat detection performance.
5. The validation threshold is based on a single synthetic dataset.
6. Overlapping sequences create correlated observations.
7. Context-window evaluation should not be interpreted as six independent anomalies.
8. Detection of anomalous behavior does not establish malicious intent.

---

## 14. Reproducibility

The experiment uses:

- fixed random seed: `42`
- deterministic chronological data splitting
- training-only feature scaling
- fixed sequence length: `6`
- fixed feature set
- fixed LSTM architecture
- fixed training configuration
- validation-derived anomaly threshold

The experiment is implemented within the repository's `models` and `evaluation` modules and protected by automated tests.

---

## 15. Research Status

Round 9 establishes the initial LSTM sequence autoencoder baseline.

The next stage should compare this sequence-based approach against the previously implemented statistical, Isolation Forest, and hybrid behavioral scoring approaches using consistent temporal evaluation definitions.
