"""Turn raw logs into events, and windows of events into detection features.

Pipeline:  raw line / JSON  ->  normalize_event  ->  group_windows  ->  window_features

Everything here treats log content as untrusted: fields are validated, control
characters are stripped and lengths are capped before anything is stored or shown.
All hours are UTC.
"""

import ipaddress
import json
import math
import re
import time
from collections import Counter
from datetime import datetime, timezone

import numpy as np

WINDOW_SECONDS = 15 * 60
MIN_WINDOW_EVENTS = 3

FEATURES = [
    "event_count",
    "log_bytes_total",
    "log_size_std",
    "size_cv",
    "timing_cv",
    "timing_entropy",
    "fail_ratio",
    "failed_logins",
    "distinct_ports",
    "distinct_dsts",
    "rare_port_ratio",
    "foreign_dst_ratio",
    "new_subnet_ratio",
    "src_external",
    "off_hours",
]

FEATURE_LABELS = {
    "event_count": "number of events",
    "log_bytes_total": "total bytes transferred",
    "log_size_std": "spread of event sizes",
    "size_cv": "variation in packet size",
    "timing_cv": "irregularity of request timing",
    "timing_entropy": "randomness of request timing",
    "fail_ratio": "share of logins that failed",
    "failed_logins": "failed logins",
    "distinct_ports": "distinct destination ports",
    "distinct_dsts": "distinct destinations",
    "rare_port_ratio": "share of traffic to unusual ports",
    "foreign_dst_ratio": "share of traffic to unfamiliar external addresses",
    "new_subnet_ratio": "share of traffic to never-seen subnets",
    "src_external": "source is outside the network",
    "off_hours": "activity at unusual hours for this user",
}

_INTERNAL = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def is_internal(ip) -> bool:
    """True for private/loopback/link-local space. (The documentation ranges such as
    203.0.113.0/24 count as public here, which is what makes them usable in demos.)"""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in _INTERNAL)


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def subnet(ip) -> str:
    """/24 for IPv4, /64 for IPv6."""
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def clean_text(value, limit):
    if value is None:
        return None
    text = _CONTROL.sub(" ", str(value)).strip()
    return text[:limit] or None


# ---- normalization ---------------------------------------------------------

_ALIASES = {
    "ts": ("ts", "timestamp", "time", "@timestamp", "datetime", "date"),
    "src_ip": ("src_ip", "src", "source_ip", "source", "client_ip", "srcip", "saddr", "remote_ip"),
    "dst_ip": ("dst_ip", "dst", "dest_ip", "destination_ip", "destination", "dstip", "daddr"),
    "dst_port": ("dst_port", "dport", "dest_port", "destination_port", "port", "dpt"),
    "proto": ("proto", "protocol"),
    "bytes": ("bytes", "size", "length", "bytes_out", "len", "bytes_sent"),
    "username": ("username", "user", "account", "usr"),
    "host": ("host", "hostname", "device", "computer"),
    "action": ("action", "outcome", "result", "status"),
    "event_type": ("event_type", "type", "category"),
    "message": ("message", "msg", "raw"),
}
_SUCCESS = {"success", "succeeded", "accepted", "ok", "logon", "login_success"}
_FAILURE = {"failure", "failed", "fail", "denied_login", "login_failed", "invalid", "error_auth"}
_ALLOW = {"allow", "allowed", "permit", "permitted", "pass", "accept"}
_DENY = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected"}


def _first(raw, name):
    for key in _ALIASES[name]:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def parse_ts(value, now=None):
    """Epoch seconds from a number or ISO-8601 string; None if unusable."""
    now = now or time.time()
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            ts = float(value)
        else:
            text = str(value).strip()
            try:
                ts = float(text)
            except ValueError:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                ts = parsed.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None
    if ts > 1e12:  # milliseconds
        ts /= 1000.0
    if not math.isfinite(ts) or ts < 946684800 or ts > now + 86400:
        return None
    return ts


def normalize_event(raw, now=None):
    """Validate one raw record. Returns a clean event dict, or None if it can't be used
    (no timestamp, or no valid source address)."""
    if not isinstance(raw, dict):
        return None
    raw = {str(k).lower(): v for k, v in raw.items()}
    ts = parse_ts(_first(raw, "ts"), now)
    src = valid_ip(_first(raw, "src_ip") or "")
    if ts is None or src is None:
        return None

    dst = valid_ip(_first(raw, "dst_ip") or "")
    port = None
    try:
        port_val = _first(raw, "dst_port")
        if port_val is not None:
            port = int(port_val)
            port = port if 0 <= port <= 65535 else None
    except (ValueError, TypeError):
        port = None
    size = None
    try:
        size_val = _first(raw, "bytes")
        if size_val is not None:
            size = min(max(int(float(size_val)), 0), 10**12)
    except (ValueError, TypeError):
        size = None

    action_raw = str(_first(raw, "action") or "").strip().lower()
    if action_raw in _SUCCESS:
        action = "success"
    elif action_raw in _FAILURE:
        action = "failure"
    elif action_raw in _ALLOW:
        action = "allow"
    elif action_raw in _DENY:
        action = "deny"
    else:
        action = "other"
    event_type = clean_text(_first(raw, "event_type"), 16)
    if event_type:
        event_type = event_type.lower()
    else:
        event_type = "auth" if action in ("success", "failure") else "network"

    return {
        "ts": ts,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "proto": (clean_text(_first(raw, "proto"), 16) or "").lower() or None,
        "bytes": size,
        "username": clean_text(_first(raw, "username"), 64),
        "host": clean_text(_first(raw, "host"), 100),
        "action": action,
        "event_type": event_type,
        "message": clean_text(_first(raw, "message"), 300),
    }


# ---- raw line parsing ------------------------------------------------------

_KV = re.compile(r'([A-Za-z_][\w.-]*)=("([^"]*)"|\S+)')
_SYSLOG = re.compile(
    r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SSHD = re.compile(
    r"(?P<res>Failed|Accepted)\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)


def _syslog_ts(text, now):
    year = datetime.fromtimestamp(now, timezone.utc).year
    for y in (year, year - 1):
        try:
            parsed = datetime.strptime(f"{y} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        ts = parsed.replace(tzinfo=timezone.utc).timestamp()
        if ts <= now + 86400:
            return ts
    return None


def parse_line(line, now=None):
    """Parse one log line: JSON, key=value (firewall style) or sshd syslog.
    Returns a normalized event, or None."""
    now = now or time.time()
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            return normalize_event(json.loads(line), now)
        except ValueError:
            return None
    match = _SYSLOG.match(line)
    if match:
        ssh = _SSHD.search(match["msg"])
        if not ssh:
            return None
        ts = _syslog_ts(match["ts"], now)
        if ts is None:
            return None
        return normalize_event(
            {
                "ts": ts, "src_ip": ssh["ip"], "dst_port": 22, "username": ssh["user"],
                "host": match["host"], "action": "failure" if ssh["res"] == "Failed" else "success",
                "proto": "tcp", "message": match["msg"],
            },
            now,
        )
    if "=" in line:
        fields = {m[1]: (m[3] if m[2].startswith('"') else m[2]) for m in _KV.finditer(line)}
        return normalize_event(fields, now)
    return None


def parse_payload(body: bytes, now=None):
    """Parse an ingest request body: a JSON object/array, {"events": [...]}, or
    newline-delimited lines in any supported format. Returns (events, rejected)."""
    now = now or time.time()
    text = body.decode("utf-8", errors="replace").strip()
    records = None
    if text[:1] in "[{":
        try:
            data = json.loads(text)
            records = data.get("events", [data]) if isinstance(data, dict) else data
            if not isinstance(records, list):
                records = None
        except ValueError:
            records = None  # probably newline-delimited JSON
    events, rejected = [], 0
    items = records if records is not None else text.splitlines()
    for item in items:
        event = normalize_event(item, now) if isinstance(item, dict) else (
            parse_line(item, now) if isinstance(item, str) else None
        )
        if event:
            events.append(event)
        elif item not in ("", None):
            rejected += 1
    return events, rejected


# ---- baseline --------------------------------------------------------------

def _hour(ts):
    return int(ts // 3600) % 24


class Baseline:
    """What 'normal' looks like for an account, learned from its history:
    each user's hours of activity, the ports in common use, and the subnets
    that are talked to."""

    MIN_USER_EVENTS = 30

    def __init__(self, hours=None, ports=None, subnets=None):
        self.hours = hours or {}      # username or "*" -> 24 counts
        self.ports = set(ports or [])
        self.subnets = set(subnets or [])

    @classmethod
    def from_events(cls, events):
        hours = {"*": [0.0] * 24}
        ports, subnets = Counter(), set()
        for e in events:
            h = _hour(e["ts"])
            hours["*"][h] += 1
            if e.get("username"):
                hours.setdefault(e["username"], [0.0] * 24)[h] += 1
            if e.get("dst_port") is not None:
                ports[e["dst_port"]] += 1
            if e.get("dst_ip"):
                subnets.add(subnet(e["dst_ip"]))
        cutoff = max(2, int(0.002 * len(events)))
        return cls(hours, {p for p, c in ports.items() if c >= cutoff}, subnets)

    def off_hours(self, username, ts) -> float:
        """0 at the hour this user is usually busiest, rising toward 1 for hours they
        have never been active."""
        hist = self.hours.get(username)
        if not hist or sum(hist) < self.MIN_USER_EVENTS:
            hist = self.hours.get("*")
        if not hist or sum(hist) == 0:
            return 0.0
        total = sum(hist)
        probs = [(c + 0.5) / (total + 12) for c in hist]
        return float(1.0 - probs[_hour(ts)] / max(probs))

    def to_dict(self):
        return {"hours": self.hours, "ports": sorted(self.ports), "subnets": sorted(self.subnets)}

    @classmethod
    def from_dict(cls, data):
        return cls(data.get("hours"), data.get("ports"), data.get("subnets"))


# ---- windows and features --------------------------------------------------

def bucket(ts, size=WINDOW_SECONDS) -> int:
    return int(ts // size)


def group_windows(events, size=WINDOW_SECONDS):
    """Group events by (source address, time bucket)."""
    groups = {}
    for e in events:
        groups.setdefault((e["src_ip"], bucket(e["ts"], size)), []).append(e)
    return groups


def _most_common(values):
    values = [v for v in values if v]
    return Counter(values).most_common(1)[0][0] if values else None


def window_meta(src_ip, bucket_id, events, size=WINDOW_SECONDS):
    ts = [e["ts"] for e in events]
    username = _most_common(e.get("username") for e in events)
    host = _most_common(e.get("host") for e in events)
    return {
        "src_ip": src_ip,
        "bucket": bucket_id,
        "window_start": bucket_id * size,
        "window_end": (bucket_id + 1) * size,
        "first_ts": min(ts),
        "last_ts": max(ts),
        "username": username,
        "host": host,
        "n_events": len(events),
    }


def _entropy(values):
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values()) if total else 0.0


def window_features(events, baseline):
    """The detection features for one window of events."""
    n = len(events)
    ts = sorted(e["ts"] for e in events)
    sizes = np.array([e["bytes"] or 0 for e in events], dtype=float)
    intervals = np.diff(ts)

    mean_size = sizes.mean() if n else 0.0
    size_std = sizes.std() if n else 0.0
    size_cv = size_std / mean_size if mean_size > 0 else 0.0

    if len(intervals) >= 2:
        mean_gap = intervals.mean()
        timing_cv = float(intervals.std() / mean_gap) if mean_gap > 0 else 0.0
        # Intervals bucketed on a log scale: steady beacons land in one or two
        # buckets (low entropy); human traffic spreads out (high entropy).
        buckets = np.round(np.log1p(intervals) * 4).astype(int).tolist()
        timing_entropy = _entropy(buckets) / math.log2(len(intervals))
    else:
        timing_cv, timing_entropy = 1.0, 1.0

    auth = [e for e in events if e["action"] in ("success", "failure")]
    failures = sum(1 for e in auth if e["action"] == "failure")

    ports = [e["dst_port"] for e in events if e["dst_port"] is not None]
    dsts = [e["dst_ip"] for e in events if e["dst_ip"]]
    rare_ports = sum(1 for p in ports if baseline.ports and p not in baseline.ports)
    external_dsts = [d for d in dsts if not is_internal(d)]
    unknown_subnets = sum(1 for d in dsts if baseline.subnets and subnet(d) not in baseline.subnets)
    foreign_new = sum(1 for d in external_dsts if baseline.subnets and subnet(d) not in baseline.subnets)

    values = {
        "event_count": float(n),
        "log_bytes_total": math.log1p(float(sizes.sum())),
        "log_size_std": math.log1p(float(size_std)),
        "size_cv": float(size_cv),
        "timing_cv": float(timing_cv),
        "timing_entropy": float(timing_entropy),
        "fail_ratio": failures / len(auth) if auth else 0.0,
        "failed_logins": float(failures),
        "distinct_ports": float(len(set(ports))),
        "distinct_dsts": float(len(set(dsts))),
        "rare_port_ratio": rare_ports / len(ports) if ports else 0.0,
        "foreign_dst_ratio": foreign_new / len(dsts) if dsts else 0.0,
        "new_subnet_ratio": unknown_subnets / len(dsts) if dsts else 0.0,
        "src_external": 0.0 if is_internal(events[0]["src_ip"]) else 1.0,
        "off_hours": float(np.mean([baseline.off_hours(e.get("username"), e["ts"]) for e in events])),
    }
    return {k: float(np.nan_to_num(v)) for k, v in values.items()}


def build_windows(events, baseline, size=WINDOW_SECONDS, min_events=MIN_WINDOW_EVENTS):
    """List of (meta, features, events) for every window with enough events."""
    out = []
    for (src, b), group in sorted(group_windows(events, size).items(), key=lambda kv: kv[0][1]):
        if len(group) >= min_events:
            out.append((window_meta(src, b, group, size), window_features(group, baseline), group))
    return out


def brief(event):
    """A compact, display-safe view of an event (for the UI and for agent prompts)."""
    stamp = datetime.fromtimestamp(event["ts"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "time": stamp,
        "src": event.get("src_ip"),
        "dst": event.get("dst_ip"),
        "port": event.get("dst_port"),
        "proto": event.get("proto"),
        "bytes": event.get("bytes"),
        "user": event.get("username"),
        "host": event.get("host"),
        "action": event.get("action"),
        "msg": (event.get("message") or "")[:160] or None,
    }
