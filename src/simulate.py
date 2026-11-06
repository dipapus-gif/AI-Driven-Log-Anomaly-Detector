"""A traffic simulator for demos and tests.

Produces a few days of normal activity for a small office, then an hour of
"live" traffic (ending at 03:00 UTC) containing:

  malicious:  C2 beaconing, an SSH brute force, a data exfiltration, a port scan
  benign but unusual:  a nightly backup that is three times its usual size, and an
                       admin's off-hours maintenance session

The benign oddities are what the investigator agent should recognise and clear.
Documentation address ranges (RFC 5737) stand in for attacker infrastructure.
"""

import random
import time

BEACON_IP = "198.51.100.77"
BRUTE_IP = "203.0.113.9"
EXFIL_IP = "192.0.2.50"
SCAN_IP = "198.51.100.200"
BACKUP_IP = "10.0.0.30"
ADMIN_IP = "10.0.1.14"

# Who is who, for the demo account. Edit via PUT /api/platform/config.
DEMO_CONFIG = {
    "directory": {
        "alice": {"groups": ["Staff"], "service_account": False},
        "bob": {"groups": ["Staff"], "service_account": False},
        "carol": {"groups": ["Finance"], "service_account": False},
        "dave": {"groups": ["Domain Admins", "Change Managers"], "service_account": False},
        "backup_svc": {"groups": ["Backup Operators"], "service_account": True},
    },
    "known_jobs": [
        {
            "name": "Nightly file-server backup",
            "user": "backup_svc",
            "hosts": ["bkp-01", BACKUP_IP],
            "hours": [1, 4],
            "dst_ports": [445],
            "internal_only": True,
        },
        {
            "name": "Monthly patch window",
            "user": "dave",
            "hosts": ["ws-dave", ADMIN_IP],
            "hours": [1, 4],
            "dst_ports": [22, 443, 5432],
            "internal_only": True,
        },
    ],
    "thresholds": {"alert": 70, "isolate": 90},
}

_USERS = {
    # name: (ip, host, first working hour, last working hour)
    "alice": ("10.0.1.11", "ws-alice", 9, 17),
    "bob": ("10.0.1.12", "ws-bob", 8, 16),
    "carol": ("10.0.1.13", "ws-carol", 10, 18),
    "dave": (ADMIN_IP, "ws-dave", 9, 17),
}
_DESTINATIONS = [  # ip, port, weight
    ("10.0.0.10", 443, 5), ("10.0.0.20", 5432, 2), ("10.0.0.40", 445, 2),
    ("10.0.0.53", 53, 4), ("10.0.0.5", 22, 1),
    ("142.250.80.46", 443, 4), ("151.101.1.69", 443, 3), ("104.18.32.7", 443, 2),
]


def _event(ts, src, dst, port, size, user, host, action="allow", etype="network", msg=None):
    return {
        "ts": round(ts, 3), "src_ip": src, "dst_ip": dst, "dst_port": port, "proto": "tcp",
        "bytes": int(size), "username": user, "host": host, "action": action,
        "event_type": etype, "message": msg,
    }


def _live_start(now):
    """The most recent 02:00 UTC whose following hour is already in the past."""
    start = (now // 86400) * 86400 + 2 * 3600
    return start if start + 3600 <= now else start - 86400


def _workday(rng, day_start, user, ip, host, first, last):
    events, t = [], day_start + first * 3600 + rng.uniform(0, 900)
    events.append(_event(t, ip, "10.0.0.5", 443, 900, user, host, "success", "auth"))
    weights = [w for *_, w in _DESTINATIONS]
    while t < day_start + last * 3600:
        t += rng.expovariate(1 / 130.0) + 1
        dst, port, _ = rng.choices(_DESTINATIONS, weights)[0]
        size = rng.lognormvariate(8.2, 1.0)
        if rng.random() < 0.012:
            events.append(_event(t, ip, "10.0.0.5", 443, 400, user, host, "failure", "auth"))
        events.append(_event(t, ip, dst, port, size, user, host))
    return events


def _backup(rng, start, scale):
    events, t = [], start
    for _ in range(int(60 * (1 if scale == 1 else 1.5))):
        t += rng.uniform(25, 35)
        events.append(_event(t, BACKUP_IP, "10.0.0.40", 445, rng.gauss(8e6, 6e5) * scale,
                             "backup_svc", "bkp-01", msg="backup job chunk"))
    return events


def simulate(seed=7, days=2, now=None):
    """Returns {"history": [...], "live": [...], "config": {...}, "truth": {...}}."""
    rng = random.Random(seed)
    now = now or time.time()
    live_start = _live_start(now)
    history = []
    for d in range(days, 0, -1):
        day = live_start - 2 * 3600 - d * 86400 + 86400 - 86400  # midnight UTC of each past day
        day = ((live_start - d * 86400) // 86400) * 86400
        for user, (ip, host, first, last) in _USERS.items():
            history.extend(_workday(rng, day, user, ip, host, first, last))
        history.extend(_backup(rng, day + 2 * 3600, scale=1))
    history.sort(key=lambda e: e["ts"])

    live = []
    # --- benign but unusual ---------------------------------------------------
    live.extend(_backup(rng, live_start, scale=3))
    t = live_start + 10 * 60
    for _ in range(12):
        t += rng.uniform(40, 90)
        dst, port = rng.choice([("10.0.0.5", 22), ("10.0.0.20", 5432), ("10.0.0.10", 443)])
        live.append(_event(t, ADMIN_IP, dst, port, rng.uniform(800, 4000), "dave", "ws-dave",
                           "success", "auth", "maintenance login"))
    # --- malicious --------------------------------------------------------------
    t = live_start + 5 * 60                      # C2 beacon from carol's workstation
    for _ in range(40):
        t += 60 + rng.uniform(-3, 3)
        live.append(_event(t, "10.0.1.13", BEACON_IP, 8443, 312 + rng.randint(-4, 4),
                           "carol", "ws-carol", msg="POST /updates/check"))
    t = live_start + 10 * 60                     # SSH brute force from outside
    names = ["root", "admin", "oracle", "test", "ubuntu", "postgres", "git", "deploy"]
    for i in range(120):
        t += rng.uniform(2.5, 4.5)
        live.append(_event(t, BRUTE_IP, "10.0.0.5", 22, 220, rng.choice(names), "bastion",
                           "failure", "auth", "Failed password"))
    live.append(_event(t + 3, BRUTE_IP, "10.0.0.5", 22, 220, "admin", "bastion",
                       "success", "auth", "Accepted password"))
    t = live_start + 20 * 60                     # port scan from outside
    for i in range(60):
        t += rng.uniform(0.5, 2.0)
        live.append(_event(t, SCAN_IP, f"10.0.0.{rng.randint(1, 60)}",
                           rng.choice([21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432]),
                           60, None, None, "deny", "network"))
    t = live_start + 30 * 60                     # exfiltration from bob's workstation
    for _ in range(25):
        t += rng.uniform(15, 50)
        live.append(_event(t, "10.0.1.12", EXFIL_IP, 443, rng.gauss(6e7, 8e6),
                           "bob", "ws-bob", msg="TLS upload"))
    live.sort(key=lambda e: e["ts"])

    return {
        "history": history,
        "live": live,
        "config": DEMO_CONFIG,
        "truth": {
            "malicious": [BEACON_IP, BRUTE_IP, EXFIL_IP, SCAN_IP, "10.0.1.13", "10.0.1.12"],
            "benign_unusual": [BACKUP_IP, ADMIN_IP],
        },
    }
