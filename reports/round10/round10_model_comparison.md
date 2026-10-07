# Round 10 — Model Comparison and Temporal Localization

## Objective

Compare three anomaly-detection approaches using the same synthetic insider-threat dataset and chronological train/validation/test evaluation protocol:

1. Statistical / Hybrid baseline
2. Hourly Isolation Forest
3. LSTM Autoencoder

The purpose is to compare detection behavior, alert volume, classification metrics, target ranking, and temporal localization.

## Dataset and Evaluation

- Synthetic events: 3,788
- Held-out test observations: 240
- Known anomaly: `USR-003`
- Known anomalous window: `2026-09-16T02:00:00+00:00`
- Training period: through `2026-09-12`
- Validation period: `2026-09-13` to `2026-09-14`
- Test period: `2026-09-15` to `2026-09-16`

The ground truth contains one known injected anomalous target window.

## Results

| Model | Alerts | Precision | Recall | F1 | Target Rank | Detected |
|---|---:|---:|---:|---:|---:|---|
| Hourly Isolation Forest | 1 | 1.000000 | 1.000000 | 1.000000 | 1 | Yes |
| LSTM Autoencoder | 6 | 0.166667 | 1.000000 | 0.285714 | 3 | Yes |
| Statistical / Hybrid | 2 | 0.500000 | 1.000000 | 0.666667 | 1 | Yes |

## Interpretation

All three approaches detected the known held-out synthetic anomaly.

The Hourly Isolation Forest produced the fewest alerts in this experiment and achieved no false positives under the exact-window evaluation. The Statistical / Hybrid approach also detected the target while producing two alerts.

The LSTM Autoencoder generated six exact-window alerts. These detections require careful interpretation because the six alerts correspond to overlapping six-hour sequences containing the same anomalous timestep rather than six independent anomalous events.

Therefore, the exact-window precision of the LSTM should not be interpreted as evidence that six independent anomalies occurred.


## Temporal Localization

For the six overlapping LSTM sequences, the known anomalous 02:00 window occurs at:

| Sequence target window | Anomaly timestep |
|---|---:|
| 02:00 | 5 |
| 03:00 | 4 |
| 04:00 | 3 |
| 05:00 | 2 |
| 06:00 | 1 |
| 07:00 | 0 |

This demonstrates that the reconstruction-error signal is temporally localized to the timestep containing the injected anomalous behavior.


## Research Interpretation

The experiment suggests that different model classes provide different analytical value.

The Statistical / Hybrid baseline provides an interpretable behavioral comparison mechanism.

The Isolation Forest provides a compact unsupervised anomaly-detection baseline and, in this synthetic experiment, produced the lowest alert volume.

The LSTM Autoencoder models temporal sequences directly and provides a sequence-level reconstruction signal that can be inspected across individual timesteps.

These observations are specific to the present synthetic dataset and experimental configuration. They should not be generalized to real-world insider-threat detection performance.


## Limitations

1. The dataset is synthetic.
2. Only one known anomalous target window is currently used for the primary ground truth.
3. The LSTM uses overlapping six-hour sequences, so multiple sequence alerts can correspond to one underlying anomalous timestep.
4. The three approaches operate on different temporal representations: hourly windows versus six-hour sequences.
5. The current experiment does not establish real-world detection performance.
6. The results should be treated as experimental evidence for the proposed methodology rather than proof of malicious insider activity.

## Reproducibility

Run the Round 10 comparison with:

    source venv/bin/activate
    export PYTHONPATH="$PWD/src"
    python scripts/run_round10_comparison.py

Expected target:

    Known target: 2026-09-16T02:00:00+00:00
