import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from engine import FEATURES  # noqa: E402
from evaluate import (  # noqa: E402
    NSL_KDD_COLUMNS,
    add_one_hot,
    build_feature_sets,
    category_levels,
    load_nsl_kdd,
    run_ocsvm,
    score_predictions,
)
from generate_data import generate  # noqa: E402


def make_rows():
    rows = []
    for attack, src, dst, failed, count in [
        ("normal", 100, 200, 0, 5),
        ("neptune", 0, 0, 0, 200),
        ("guess_passwd", 126, 179, 3, 1),
    ]:
        r = {c: 0 for c in NSL_KDD_COLUMNS}
        r.update(
            protocol_type="tcp", service="http", flag="SF", attack=attack,
            src_bytes=src, dst_bytes=dst, num_failed_logins=failed,
            count=count, level=10,
        )
        rows.append(r)
    return pd.DataFrame(rows, columns=NSL_KDD_COLUMNS)


def test_loader_maps_labels_and_pipeline_features(tmp_path):
    path = tmp_path / "tiny.txt"
    make_rows().to_csv(path, header=False, index=False)
    df = load_nsl_kdd(str(path))
    assert df["label"].tolist() == [0, 1, 1]
    assert df["byte_size"].tolist() == [300, 0, 305]
    assert df["packet_count"].tolist() == [5, 200, 1]
    assert df["failed_logins"].tolist() == [0, 0, 3]


def test_score_predictions_perfect_and_imperfect():
    perfect = score_predictions([0, 0, 1, 1], [0, 0, 1, 1], [1, 2, 8, 9])
    assert perfect["f1"] == 1.0 and perfect["roc_auc"] == 1.0
    miss = score_predictions([0, 0, 1, 1], [0, 0, 1, 0], [1, 2, 8, 9])
    assert miss["recall"] == 0.5 and miss["precision"] == 1.0
    assert (miss["tn"], miss["fp"], miss["fn"], miss["tp"]) == (2, 0, 1, 1)


def test_one_hot_uses_training_categories_only():
    train = pd.DataFrame(
        {"protocol_type": ["tcp", "udp"], "service": ["http", "ftp"], "flag": ["SF", "SF"]}
    )
    test = pd.DataFrame(
        {"protocol_type": ["tcp", "icmp"], "service": ["http", "telnet"], "flag": ["SF", "S0"]}
    )
    out = add_one_hot(test, category_levels(train))
    assert out["protocol_type=tcp"].tolist() == [1, 0]
    assert out["protocol_type=udp"].tolist() == [0, 0]
    assert "protocol_type=icmp" not in out.columns  # unseen in training: no column
    assert out["service=ftp"].tolist() == [0, 0]  # known category, absent in test
    flag_cols = [c for c in out.columns if c.startswith("flag=")]
    assert out[flag_cols].sum().sum() == 1  # only the SF row; S0 was never seen


def test_feature_set_sizes():
    levels = {"protocol_type": ["tcp", "udp"], "service": ["ftp", "http", "smtp"], "flag": ["S0", "SF"]}
    sets = build_feature_sets(levels)
    assert sets["mapped4"] == FEATURES
    assert len(sets["numeric38"]) == 38
    assert len(sets["numeric38_protocol"]) == 38 + 2
    assert len(sets["numeric38_all_cat"]) == 38 + 2 + 2 + 3


def test_ocsvm_flags_injected_attacks():
    df = generate(rows=400, attack_fraction=0.05)
    train_normal = df[df["label"] == 0]
    flagged, risk = run_ocsvm(FEATURES, train_normal, df, nu=0.05, n_train=300)
    scores = score_predictions(df["label"], flagged, risk)
    assert scores["recall"] >= 0.9
    assert scores["roc_auc"] >= 0.95


def test_autoencoder_scores_attacks_higher():
    from extra_models import AutoencoderDetector

    df = generate(rows=600, attack_fraction=0.05)
    normal = df[df["label"] == 0][FEATURES]
    ae = AutoencoderDetector(contamination=0.05, max_iter=30).fit(normal)
    scores = score_predictions(df["label"], ae.predict(df[FEATURES]), ae.score(df[FEATURES]))
    assert scores["roc_auc"] >= 0.9


def test_random_forest_references():
    from extra_models import random_forest_cv_scores, random_forest_scores

    df = generate(rows=600, attack_fraction=0.1)
    X, y = df[FEATURES].to_numpy(), df["label"].to_numpy()
    flagged, proba = random_forest_scores(X[:400], y[:400], X[400:], n_estimators=30)
    assert score_predictions(y[400:], flagged, proba)["roc_auc"] >= 0.9
    flagged, proba = random_forest_cv_scores(X, y, folds=3, n_estimators=30)
    assert len(proba) == len(y) and score_predictions(y, flagged, proba)["roc_auc"] >= 0.9
