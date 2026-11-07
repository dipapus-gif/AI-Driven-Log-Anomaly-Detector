#!/usr/bin/env python3
"""Write realistic log lines to a file, so you can try the whole pipeline without a real network.

It only writes text. Nothing here touches the network; the tailer ships the file for you.

  # 1. two days of normal activity (timestamps in the past), to learn from
  python scripts/log_generator.py normal --file lab.log --hours 48

  # 2. ship it:   INGEST_TOKEN=lad_... python src/tailer.py --url https://APP/api/ingest --from-start --once lab.log
  # 3. in the dashboard, Log sources -> Train baseline

  # 4. then run something suspicious (events are stamped "now"):
  python scripts/log_generator.py attack brute  --file lab.log
  python scripts/log_generator.py attack exfil  --file lab.log
  python scripts/log_generator.py attack beacon --file lab.log
  python scripts/log_generator.py attack scan   --file lab.log

  # keep a trickle of normal traffic flowing while the tailer runs
  python scripts/log_generator.py live --file lab.log

Addresses come from the reserved documentation ranges (RFC 5737), so they can't belong to anyone.
"""

import argparse
import json
import random
import sys
import time

USERS = [("alice", "ws-alice", "10.0.1.11"), ("bob", "ws-bob", "10.0.1.12"), ("carol", "ws-carol", "10.0.1.13"),
         ("dave", "ws-dave", "10.0.1.14")]
SERVERS = [("10.0.0.10", 443), ("10.0.0.10", 445), ("10.0.0.20", 443), ("10.0.0.30", 22), ("10.0.0.5", 53)]
ATTACKER = "203.0.113.77"


def event(ts, src, user="", host="", dst="", port=0, size=0, action="allow", kind="network", message=""):
    return {"ts": round(ts, 3), "src_ip": src, "dst_ip": dst, "dst_port": port, "proto": "tcp", "bytes": int(size),
            "username": user, "host": host, "action": action, "event_type": kind, "message": message}


def normal_events(ts, rng):
    """One person doing ordinary work at time ts."""
    user, host, ip = rng.choice(USERS)
    dst, port = rng.choice(SERVERS)
    out = [event(ts, ip, user, host, dst, port, rng.lognormvariate(7.5, 1.0))]
    if rng.random() < 0.15:
        out.append(event(ts + 1, ip, user, host, "10.0.0.20", 22, 0, "success", "auth", f"login {user}"))
    if rng.random() < 0.02:
        out.append(event(ts + 2, ip, user, host, "10.0.0.20", 22, 0, "failure", "auth", f"mistyped password {user}"))
    return out


def business_hour(ts):
    hour = time.gmtime(ts).tm_hour
    return 8 <= hour < 18


def history(hours, rng, now):
    """Normal working-hours activity for the last `hours` hours (quiet at night)."""
    events, ts = [], now - hours * 3600
    while ts < now - 60:
        busy = business_hour(ts)
        events += normal_events(ts, rng)
        ts += rng.uniform(20, 70) if busy else rng.uniform(600, 1500)
    return events


def attack(kind, rng, now):
    if kind == "brute":
        names = ["admin", "root", "test", "ubuntu", "oracle", "git", "deploy", "postgres"]
        start = now - 170
        out = [event(start + i * 1.4, ATTACKER, rng.choice(names), "bastion", "10.0.0.30", 22, 0, "failure", "auth",
                     "Failed password for invalid user") for i in range(120)]
        out.append(event(now - 3, ATTACKER, "admin", "bastion", "10.0.0.30", 22, 0, "success", "auth", "Accepted password for admin"))
        return out
    if kind == "exfil":
        return [event(now - 600 + i * 45, "10.0.1.12", "bob", "ws-bob", "192.0.2.50", 443, rng.uniform(40e6, 90e6))
                for i in range(12)]
    if kind == "beacon":
        return [event(now - 2400 + i * 60 + rng.uniform(-0.6, 0.6), "10.0.1.13", "carol", "ws-carol", "192.0.2.77", 8443, 312)
                for i in range(40)]
    if kind == "scan":
        return [event(now - 120 + i * 0.5, "198.51.100.200", "", "", "10.0.0.5", 1 + i * 7, 0, "deny")
                for i in range(110)]
    raise ValueError(kind)


def emit(events, handle):
    for e in sorted(events, key=lambda x: x["ts"]):
        handle.write(json.dumps(e) + "\n")
    handle.flush()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("normal", "attack", "live"):
        p = sub.add_parser(name)
        p.add_argument("--file", default="-", help="append to this file (default: standard output)")
        p.add_argument("--seed", type=int, default=None)
    sub.choices["normal"].add_argument("--hours", type=float, default=48)
    sub.choices["attack"].add_argument("kind", choices=["brute", "exfil", "beacon", "scan"])
    args = ap.parse_args(argv)
    rng, now = random.Random(args.seed), time.time()
    handle = sys.stdout if args.file == "-" else open(args.file, "a", encoding="utf-8")
    try:
        if args.mode == "normal":
            emit(history(args.hours, rng, now), handle)
        elif args.mode == "attack":
            emit(attack(args.kind, rng, now), handle)
            print(f"Wrote a simulated {args.kind} attack.", file=sys.stderr)
        else:
            print("Writing normal traffic every few seconds. Ctrl+C to stop.", file=sys.stderr)
            while True:
                emit(normal_events(time.time(), rng) if business_hour(time.time()) or rng.random() < .1 else [], handle)
                time.sleep(rng.uniform(2, 6))
    except KeyboardInterrupt:
        pass
    finally:
        if handle is not sys.stdout:
            handle.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
