import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from engine import LogAnomalyEngine  # noqa: E402
from generate_data import generate  # noqa: E402


@pytest.fixture()
def trained(tmp_path):
    df = generate(rows=600, attack_fraction=0.05)
    data_path = tmp_path / "logs.csv"
    df.to_csv(data_path, index=False)
    model_path = tmp_path / "model.pkl"
    LogAnomalyEngine(contamination=0.05).train(str(data_path), str(model_path))
    return df, str(model_path)


def test_flags_most_attacks_with_few_false_alarms(trained):
    df, model_path = trained
    out = LogAnomalyEngine().detect_anomalies(df, model_path)
    flagged = out["anomaly_status"] == "CRITICAL ANOMALY"
    attacks = out["label"] == 1
    recall = (flagged & attacks).sum() / attacks.sum()
    false_alarm_rate = (flagged & ~attacks).sum() / (~attacks).sum()
    assert recall >= 0.9
    assert false_alarm_rate <= 0.05


def test_risk_score_in_range_and_higher_for_attacks(trained):
    df, model_path = trained
    out = LogAnomalyEngine().detect_anomalies(df, model_path)
    assert out["risk_score"].between(0, 100).all()
    assert out.loc[out.label == 1, "risk_score"].mean() > out.loc[out.label == 0, "risk_score"].mean()


def test_missing_columns_and_bad_values_do_not_crash(trained):
    _, model_path = trained
    odd = pd.DataFrame({"duration": [0.5, "oops"], "packet_count": [10, None]})
    out = LogAnomalyEngine().detect_anomalies(odd, model_path)
    assert len(out) == 2


def test_train_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        LogAnomalyEngine().train(str(tmp_path / "nope.csv"), str(tmp_path / "m.pkl"))
