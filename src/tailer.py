#!/usr/bin/env python3
"""Ship logs to the platform's ingest endpoint, continuously.

  python src/tailer.py --url https://YOUR-APP/api/ingest /var/log/auth.log
  journalctl -f -t sshd | python src/tailer.py --url https://YOUR-APP/api/ingest -

The ingest token comes from the INGEST_TOKEN environment variable (preferred, so it
doesn't show up in process listings) or a prompt. Create one in the dashboard.

Formats understood by the server: JSON lines, key=value (firewall style) and sshd syslog.
The tailer follows a file like `tail -F`: it survives log rotation and truncation, only
sends complete lines, batches them, and retries with backoff if the server is
unreachable (nothing is lost while it retries, up to a bounded backlog).
"""

import argparse
import getpass
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BACKLOG_LINES = 100_000
MAX_LINE_BYTES = 8192


class FileFollower:
    """Reads new complete lines appended to a file, across rotation and truncation."""

    def __init__(self, path, from_start=False):
        self.path, self.from_start = path, from_start
        self._file, self._inode, self._partial, self._first = None, None, b"", True

    def _open(self):
        try:
            handle = open(self.path, "rb")
        except OSError:
            return False
        self._file, self._inode = handle, os.fstat(handle.fileno()).st_ino
        if self._first and not self.from_start:
            handle.seek(0, os.SEEK_END)   # a fresh start only ships new lines
        self._first = False
        return True

    def read_lines(self):
        if self._file is None and not self._open():
            return []
        try:
            current = os.stat(self.path)
        except OSError:
            return []                       # file vanished mid-rotation; keep the old handle until it reappears
        if current.st_ino != self._inode:   # rotated: finish the old file, then switch to the new one
            lines = self._drain()
            self._file.close()
            self._file, self._partial = None, b""
            self._first = False
            self._open()
            return lines + self._drain()
        if current.st_size < self._file.tell():   # truncated in place
            self._file.seek(0)
            self._partial = b""
        return self._drain()

    def _drain(self):
        if self._file is None:
            return []
        data = self._partial + self._file.read()
        *complete, self._partial = data.split(b"\n")
        if len(self._partial) > MAX_LINE_BYTES:
            self._partial = b""             # a runaway line with no newline: drop it
        return [ln.decode("utf-8", "replace")[:MAX_LINE_BYTES] for ln in complete if ln.strip()]


class FatalError(Exception):
    pass


def send_batch(url, token, lines, timeout=20, opener=urllib.request.urlopen):
    """POST one batch. Returns (ok, retry_after_seconds_or_None, message). Raises FatalError for bad credentials."""
    request = urllib.request.Request(
        url, data="\n".join(lines).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain; charset=utf-8",
                 "User-Agent": "log-anomaly-tailer"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            return True, None, response.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise FatalError("The server rejected the ingest token. Create a new one in the dashboard.") from exc
        if exc.code == 413 and len(lines) > 1:
            return False, 0, "too large"
        if exc.code in (429, 500, 502, 503, 504):
            retry = exc.headers.get("Retry-After", "")
            return False, int(retry) if retry.isdigit() else None, f"HTTP {exc.code}"
        raise FatalError(f"The server refused the logs (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, OSError) as exc:
        return False, None, f"network error ({type(exc).__name__})"


def run(sources, url, token, batch_size=500, interval=2.0, once=False, log=print, sleep=time.sleep, opener=urllib.request.urlopen):
    backlog, delay = [], 1.0
    while True:
        for source in sources:
            backlog.extend(source())
        if len(backlog) > MAX_BACKLOG_LINES:
            log(f"Backlog full: dropping the {len(backlog) - MAX_BACKLOG_LINES} oldest lines.")
            backlog = backlog[-MAX_BACKLOG_LINES:]
        while backlog:
            batch = backlog[:batch_size]
            ok, retry, message = send_batch(url, token, batch, opener=opener)
            if ok:
                del backlog[:len(batch)]
                delay = 1.0
                log(f"Sent {len(batch)} lines. {message[:120]}")
            elif message == "too large":
                batch_size = max(1, len(batch) // 2)
            else:
                log(f"Could not send ({message}); retrying in {retry or delay:.0f}s. {len(backlog)} lines waiting.")
                if once:
                    return 1
                sleep(retry or delay)
                delay = min(delay * 2, 60)
                break
        if once:
            return 0
        sleep(interval)


def stdin_source():
    """Lines from a pipe, read on a background thread so the main loop never blocks."""
    lines = queue.Queue()

    def reader():
        for line in sys.stdin:
            if line.strip():
                lines.put(line.rstrip("\n")[:MAX_LINE_BYTES])

    threading.Thread(target=reader, daemon=True).start()

    def drain():
        out = []
        while True:
            try:
                out.append(lines.get_nowait())
            except queue.Empty:
                return out

    return drain


def main(argv=None):
    parser = argparse.ArgumentParser(description="Ship log files or piped logs to the ingest endpoint.")
    parser.add_argument("files", nargs="+", help="log file(s) to follow, or - to read standard input")
    parser.add_argument("--url", required=True, help="ingest endpoint, e.g. https://your-app/api/ingest")
    parser.add_argument("--from-start", action="store_true", help="also send what is already in the files")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between checks")
    parser.add_argument("--once", action="store_true", help="send what is available, then exit")
    parser.add_argument("--allow-insecure", action="store_true", help="allow http:// (only for local testing)")
    args = parser.parse_args(argv)

    parts = urllib.parse.urlsplit(args.url)
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (args.allow_insecure or (parts.scheme == "http" and local)):
        parser.error("use an https:// URL (the token is sent with every request).")
    token = os.environ.get("INGEST_TOKEN") or getpass.getpass("Ingest token: ")

    sources = [stdin_source() if f == "-" else FileFollower(f, args.from_start or args.once).read_lines for f in args.files]
    try:
        return run(sources, args.url, token, args.batch_size, args.interval, args.once,
                   log=lambda m: print(m, file=sys.stderr))
    except FatalError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
