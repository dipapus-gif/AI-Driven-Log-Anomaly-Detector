import pytest

import detector as D
import features as F
import simulate as S

NOW = 1_790_000_000


@pytest.fixture(scope="module")
def trained():
    sim = S.simulate(seed=7, now=NOW)
    base = F.Baseline.from_events(sim["history"])
    train = F.build_windows(sim["history"], base)
    det = D.ThreatDetector().fit([f for _, f, _ in train], base)
    live = F.build_windows(sim["live"], base)
    return sim, det, train, live


def test_needs_enough_history():
    with pytest.raises(ValueError, match="at least"):
        D.ThreatDetector().fit([{name: 0.0 for name in F.FEATURES}] * 5, F.Baseline())


def test_every_malicious_source_is_flagged_and_normal_traffic_mostly_is_not(trained):
    sim, det, train, live = trained
    risk, flagged = det.score([f for _, f, _ in live])
    flagged_sources = {m["src_ip"] for (m, _, _), fl in zip(live, flagged) if fl}
    attackers = {"10.0.1.13", "10.0.1.12", S.SCAN_IP, S.BRUTE_IP}   # beacon, exfil, scan, brute force
    assert attackers <= flagged_sources
    assert flagged_sources - attackers <= {S.BACKUP_IP, S.ADMIN_IP}  # only the benign oddities besides
    _, train_flagged = det.score([f for _, f, _ in train])
    assert train_flagged.mean() < 0.06                               # quiet on its own history


def test_scores_are_zero_to_one_hundred(trained):
    _, det, _, live = trained
    risk, _ = det.score([f for _, f, _ in live])
    assert (risk >= 0).all() and (risk <= 100).all()


def test_explanations_name_the_features_that_deviate(trained):
    _, det, _, live = trained
    scan = next(f for m, f, _ in live if m["src_ip"] == S.SCAN_IP)
    explained = {e["feature"] for e in det.explain(scan)}
    assert explained & {"distinct_dsts", "distinct_ports", "src_external", "rare_port_ratio"}
    assert all(e["label"] and e["direction"] in ("high", "low") for e in det.explain(scan))


def test_model_roundtrips_through_bytes(trained):
    _, det, _, live = trained
    again = D.ThreatDetector.from_bytes(det.to_bytes())
    rows = [f for _, f, _ in live]
    assert list(again.score(rows)[0]) == list(det.score(rows)[0])
    assert again.threshold == det.threshold and again.baseline.ports == det.baseline.ports


def test_incompatible_saved_model_is_refused(trained):
    import io
    import joblib
    _, det, _, _ = trained
    buffer = io.BytesIO()
    joblib.dump({"version": 0, "features": ["old"]}, buffer)
    with pytest.raises(ValueError, match="incompatible"):
        D.ThreatDetector.from_bytes(buffer.getvalue())


def test_simulation_is_reproducible_and_stays_in_the_past():
    a, b = S.simulate(seed=3, now=NOW), S.simulate(seed=3, now=NOW)
    assert a["live"] == b["live"] and a["history"] == b["history"]
    assert max(e["ts"] for e in a["live"]) <= NOW and min(e["ts"] for e in a["history"]) > 0
