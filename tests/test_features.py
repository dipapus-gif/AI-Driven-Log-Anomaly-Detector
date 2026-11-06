import json
import random

import pytest

import features as F

NOW = 1_790_000_000.0  # fixed "current time" so tests are deterministic


def ev(ts, src="10.0.1.5", dst="10.0.0.10", port=443, size=1000, user="alice", action="allow", host="ws1"):
    return F.normalize_event(
        {"ts": ts, "src_ip": src, "dst_ip": dst, "dst_port": port, "bytes": size,
         "username": user, "action": action, "host": host}, NOW)


# ---- normalization ---------------------------------------------------------

def test_aliases_and_types_are_normalized():
    e = F.normalize_event(
        {"timestamp": "2026-09-20T10:00:00Z", "source_ip": "10.0.0.7", "dest_ip": "8.8.8.8",
         "dport": "53", "size": "120.0", "user": "Bob", "result": "FAILED"}, NOW)
    assert e["src_ip"] == "10.0.0.7" and e["dst_ip"] == "8.8.8.8" and e["dst_port"] == 53
    assert e["bytes"] == 120 and e["username"] == "Bob"
    assert e["action"] == "failure" and e["event_type"] == "auth"


@pytest.mark.parametrize(
    "raw",
    [
        {"ts": NOW, "src_ip": "not-an-ip"},          # bad address
        {"src_ip": "10.0.0.1"},                      # no timestamp
        {"ts": NOW + 10 * 86400, "src_ip": "10.0.0.1"},  # far future
        {"ts": 5, "src_ip": "10.0.0.1"},             # before 2000
        "just a string",
    ],
)
def test_unusable_records_are_rejected(raw):
    assert F.normalize_event(raw, NOW) is None


def test_untrusted_fields_are_cleaned_and_capped():
    e = F.normalize_event(
        {"ts": NOW, "src_ip": "10.0.0.1", "dst_port": 99999, "bytes": -5,
         "message": "a\nb\x00c" + "x" * 1000, "username": "u" * 500}, NOW)
    assert e["dst_port"] is None and e["bytes"] == 0
    assert "\n" not in e["message"] and "\x00" not in e["message"] and len(e["message"]) == 300
    assert len(e["username"]) == 64


def test_millisecond_timestamps_are_understood():
    assert F.normalize_event({"ts": (NOW - 100) * 1000, "src_ip": "10.0.0.1"}, NOW)["ts"] == pytest.approx(NOW - 100)


# ---- raw line formats ------------------------------------------------------

def test_parse_json_kv_and_sshd_lines():
    j = F.parse_line(json.dumps({"ts": NOW - 5, "src_ip": "203.0.113.9", "dst_port": 22}), NOW)
    assert j["src_ip"] == "203.0.113.9"

    kv = F.parse_line(f'ts={NOW - 5} src=10.0.0.2 dst=1.1.1.1 dport=443 bytes=900 user="jo smith" action=allow', NOW)
    assert kv["dst_port"] == 443 and kv["username"] == "jo smith" and kv["action"] == "allow"

    ssh = F.parse_line(
        "<34>Sep 20 02:11:01 bastion sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2",
        NOW)
    assert ssh["src_ip"] == "203.0.113.5" and ssh["username"] == "admin"
    assert ssh["action"] == "failure" and ssh["dst_port"] == 22 and ssh["host"] == "bastion"
    ok = F.parse_line("Sep 20 02:12:01 bastion sshd[9]: Accepted publickey for dave from 10.0.1.14 port 5000 ssh2", NOW)
    assert ok["action"] == "success"


def test_unparseable_lines_are_none():
    assert F.parse_line("", NOW) is None
    assert F.parse_line("random text with no structure", NOW) is None
    assert F.parse_line("Sep 20 02:11:01 host cron[1]: job started", NOW) is None


def test_parse_payload_variants_and_reject_count():
    one = {"ts": NOW - 1, "src_ip": "10.0.0.1"}
    for body in (json.dumps([one, one]), json.dumps({"events": [one, one]}),
                 json.dumps(one) + "\n" + json.dumps(one)):
        events, rejected = F.parse_payload(body.encode(), NOW)
        assert len(events) == 2 and rejected == 0
    events, rejected = F.parse_payload(b'{"ts": %f, "src_ip": "10.0.0.1"}\ngarbage line\n' % (NOW - 1), NOW)
    assert len(events) == 1 and rejected == 1


# ---- addresses -------------------------------------------------------------

def test_internal_vs_external_addresses():
    assert F.is_internal("10.1.2.3") and F.is_internal("192.168.0.9") and F.is_internal("127.0.0.1")
    assert not F.is_internal("8.8.8.8")
    assert not F.is_internal("203.0.113.9")      # documentation range counts as public on purpose
    assert F.subnet("10.1.2.3") == "10.1.2.0/24"


# ---- features --------------------------------------------------------------

def beacon_window():
    rng = random.Random(1)
    return [ev(NOW - 900 + i * 60 + rng.uniform(-2, 2), dst="198.51.100.7", port=8443, size=312 + rng.randint(-3, 3))
            for i in range(14)]


def human_window():
    rng, t, out = random.Random(2), NOW - 900, []
    while t < NOW - 20:
        t += rng.expovariate(1 / 45.0) + 1
        out.append(ev(t, size=rng.lognormvariate(8, 1)))
    return out


def test_beaconing_has_low_timing_entropy_and_steady_sizes():
    base = F.Baseline()
    beacon = F.window_features(beacon_window(), base)
    human = F.window_features(human_window(), base)
    assert beacon["timing_cv"] < 0.1 < human["timing_cv"]
    assert beacon["timing_entropy"] < human["timing_entropy"]
    assert beacon["size_cv"] < 0.05 < human["size_cv"]


def test_off_hours_is_relative_to_each_users_own_pattern():
    day = [ev(1_789_948_800 + h * 3600 + m, user="alice") for h in (9, 10, 11, 14, 15) for m in range(0, 600, 20)]
    night_worker = [ev(1_789_948_800 + h * 3600 + m, user="nina") for h in (1, 2, 3) for m in range(0, 600, 20)]
    base = F.Baseline.from_events(day + night_worker)
    at = lambda hour, user: base.off_hours(user, 1_789_948_800 + hour * 3600)
    assert at(10, "alice") < 0.2 and at(3, "alice") > 0.8      # alice at 3am is odd
    assert at(3, "nina") < 0.2                                  # nina at 3am is normal
    assert at(10, "stranger") < at(20, "stranger")              # unknown users use the account-wide pattern


def test_rare_ports_and_new_external_subnets_use_the_baseline():
    base = F.Baseline.from_events([ev(NOW - i, dst="10.0.0.10", port=443) for i in range(200)])
    normal = F.window_features([ev(NOW - i, dst="10.0.0.10", port=443) for i in range(5)], base)
    odd = F.window_features([ev(NOW - i, dst="198.51.100.9", port=31337) for i in range(5)], base)
    assert normal["rare_port_ratio"] == 0 and odd["rare_port_ratio"] == 1
    assert normal["foreign_dst_ratio"] == 0 and odd["foreign_dst_ratio"] == 1 and odd["new_subnet_ratio"] == 1


def test_failed_login_and_scan_features():
    window = [ev(NOW - i, src="203.0.113.9", dst=f"10.0.0.{i}", port=22 + i, action="failure") for i in range(20)]
    f = F.window_features(window, F.Baseline())
    assert f["failed_logins"] == 20 and f["fail_ratio"] == 1
    assert f["distinct_ports"] == 20 and f["distinct_dsts"] == 20 and f["src_external"] == 1


def test_windows_need_enough_events_and_are_grouped_by_source():
    events = [ev(NOW - 100 + i, src="10.0.0.1") for i in range(5)] + [ev(NOW - 100, src="10.0.0.2")] * 2
    windows = F.build_windows(events, F.Baseline())
    assert [m["src_ip"] for m, _, _ in windows] == ["10.0.0.1"]      # 2 events is too few
    assert set(windows[0][1]) == set(F.FEATURES)


def test_baseline_roundtrips_through_a_dict():
    base = F.Baseline.from_events([ev(NOW - i, port=443) for i in range(100)])
    again = F.Baseline.from_dict(base.to_dict())
    assert again.ports == base.ports and again.subnets == base.subnets and again.hours == base.hours
