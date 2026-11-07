#!/usr/bin/env python3
"""Generate realistic sshd log lines so you can try the whole pipeline end to end.

Run these on a machine you own. Nothing is sent anywhere: lines are written to a file
that the tailer then ships to your ingest endpoint.

  python tools/scenario.py normal --out /tmp/auth.log          # days of ordinary logins, back-dated
  python tools/scenario.py attack --out /tmp/auth.log          # a live SSH brute force, then a success

Timestamps are written in UTC, which is how the server reads syslog lines. If you ship a real
server's /var/log/auth.log, make sure that server logs in UTC (timedatectl set-timezone UTC).
"""

import argparse
import random
import sys
import time
from datetime import datetime, timezone

HOST = "bastion"
STAFF = {  # user: (usual source address, first hour, last hour)
    "alice": ("10.0.1.11", 9, 17),
    "bob": ("10.0.1.12", 8, 16),
    "carol": ("10.0.1.13", 10, 18),
    "dave": ("10.0.1.14", 9, 17),
}
ATTACKER = "203.0.113.9"            # reserved documentation address
GUESSES = ["admin", "root", "test", "oracle", "git", "postgres", "ubuntu", "deploy", "user", "ftp"]


def line(ts, host, ok, user, ip, invalid=False):
    stamp = datetime.fromtimestamp(ts, timezone.utc).strftime("%b %e %H:%M:%S")
    word = "Accepted" if ok else "Failed"
    who = f"invalid user {user}" if invalid else user
    return (f"{stamp} {host} sshd[{random.randint(1000, 60000)}]: {word} password for {who} "
            f"from {ip} port {random.randint(30000, 65000)} ssh2")


def normal(hours, now):
    """Working-hours sessions from each person's usual address: a few logins close together
    (people reconnect), the occasional typo. Bursts of 3+ lines are what make a window count."""
    rows = []
    start = int(now) - hours * 3600
    for quarter in range(start - start % 900, int(now), 900):
        hour = datetime.fromtimestamp(quarter, timezone.utc).hour
        for user, (ip, first, last) in STAFF.items():
            if first <= hour <= last and random.random() < 0.55:
                base = quarter + random.randint(0, 600)
                for k in range(random.randint(3, 5)):
                    ts = base + k * random.randint(10, 60)
                    if random.random() < 0.08:
                        rows.append((ts - 5, line(ts - 5, HOST, False, user, ip)))
                    rows.append((ts, line(ts, HOST, True, user, ip)))
    return [text for _, text in sorted(rows)]


def attack(count, delay):
    """A password-guessing run from one outside address that ends with a successful login.
    Each line is stamped with the moment it is produced, like a real log."""
    for _ in range(count):
        yield line(time.time(), HOST, False, random.choice(GUESSES), ATTACKER, invalid=True)
        time.sleep(delay)
    yield line(time.time(), HOST, True, "admin", ATTACKER)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    n = sub.add_parser("normal", help="write back-dated, ordinary activity")
    n.add_argument("--hours", type=int, default=96)
    a = sub.add_parser("attack", help="write a live brute-force attack, line by line")
    a.add_argument("--count", type=int, default=80, help="failed attempts")
    a.add_argument("--delay", type=float, default=0.4, help="seconds between attempts (in real time)")
    for p in (n, a):
        p.add_argument("--out", required=True, help="file to append to (the tailer follows it)")
        p.add_argument("--seed", type=int)
    args = parser.parse_args(argv)
    if args.seed is not None:
        random.seed(args.seed)
    now = time.time()
    with open(args.out, "a") as out:
        if args.mode == "normal":
            rows = normal(args.hours, now)
            out.write("\n".join(rows) + "\n")
            print(f"Wrote {len(rows)} ordinary login lines covering the last {args.hours} hours to {args.out}")
        else:
            for text in attack(args.count, args.delay):
                out.write(text + "\n")
                out.flush()
            print(f"Wrote {args.count} failed logins and one success from {ATTACKER} to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
