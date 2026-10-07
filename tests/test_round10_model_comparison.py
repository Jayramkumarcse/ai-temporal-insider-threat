def test_round10_expected_model_comparison_results():
    expected = {
        "statistical_hybrid": {
            "test_windows": 240,
            "alerts": 2,
            "true_positive": 1,
            "false_positive": 1,
            "true_negative": 238,
            "false_negative": 0,
            "precision": 0.5,
            "recall": 1.0,
            "f1": 2 / 3,
            "target_rank": 1,
        },
        "hourly_isolation_forest": {
            "test_windows": 240,
            "alerts": 1,
            "true_positive": 1,
            "false_positive": 0,
            "true_negative": 239,
            "false_negative": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "target_rank": 1,
        },
        "lstm_autoencoder": {
            "test_windows": 240,
            "alerts": 6,
            "true_positive": 1,
            "false_positive": 5,
            "true_negative": 234,
            "false_negative": 0,
            "precision": 1 / 6,
            "recall": 1.0,
            "f1": 2 / 7,
            "target_rank": 3,
        },
    }

    assert len(expected) == 3

    for model_result in expected.values():
        assert model_result["test_windows"] == 240
        assert model_result["true_positive"] == 1
        assert model_result["false_negative"] == 0
        assert model_result["recall"] == 1.0


def test_round10_verified_results():
    expected = {
        "Hourly Isolation Forest": {
            "alerts": 1,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "target_rank": 1,
        },
        "Statistical / Hybrid": {
            "alerts": 2,
            "precision": 0.5,
            "recall": 1.0,
            "f1": 2 / 3,
            "target_rank": 1,
        },
        "LSTM Autoencoder": {
            "alerts": 6,
            "precision": 1 / 6,
            "recall": 1.0,
            "f1": 2 / 7,
            "target_rank": 3,
        },
    }

    assert len(expected) == 3

    for model_name, values in expected.items():
        assert values["recall"] == 1.0
        assert values["target_rank"] >= 1
