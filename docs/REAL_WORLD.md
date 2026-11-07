# Trying it on real logs

You can run the whole pipeline on your own machine in about ten minutes. Only test against systems you own.

## 1. Create a token
Sign in, open **Log sources**, name a token and press **Create token**. Copy it now, it is shown once.

## 2. Send some ordinary activity (the baseline)
The model learns what is normal before it can spot what is not. It needs roughly two days of activity, at least 40 busy 15-minute windows.

**Fastest: generated logs.**
```bash
python tools/scenario.py normal --out ./auth.log          # four days of ordinary logins, back-dated
INGEST_TOKEN=lad_... python src/tailer.py --url https://YOUR-APP/api/ingest --once ./auth.log
```
Then press **Train baseline on stored events** (Log sources page, or the banner on Overview).

**Real server:** point the tailer at its log instead, and let it run for a day or two before training.
```bash
INGEST_TOKEN=lad_... python src/tailer.py --url https://YOUR-APP/api/ingest --from-start /var/log/auth.log
```
The server reads syslog timestamps as UTC. On the machine being monitored run `timedatectl set-timezone UTC`, or ship JSON lines with a `ts` field.

## 3. Run an attack
Keep the tailer running (without `--once`), then in another terminal:
```bash
python tools/scenario.py attack --out ./auth.log
```
This appends 60 failed SSH logins from `203.0.113.9` and then a success. Within about a minute **Incidents** shows a brute-force alert with the analyst's investigation, and **Approvals** shows a proposed block waiting for you.

**Against a real SSH server you own:** from a second device, try a wrong password a few dozen times (`for i in $(seq 40); do ssh -o PreferredAuthentications=password baduser@your-server; done`). Do not do this against anyone else's machine.

## 4. What approving does
By default approval is a dry run: it is recorded but nothing is blocked. To act for real, set `RESPONSE_WEBHOOK_URL` (and `RESPONSE_WEBHOOK_TOKEN`) on the server to an endpoint of yours that talks to your firewall or EDR. Every approval posts `{action, target, incident}` there.

## What is and isn't covered
- Works: sshd auth logs, JSON lines, key=value firewall logs, direct webhooks.
- Not yet: Windows event logs, cloud audit logs, and parsers for specific vendor formats. Convert those to JSON lines (`ts`, `src_ip`, `username`, `action`, ...) and post them.
- Free hosting limits apply: the serverless backend processes each ingest batch in under a minute, and storage is capped per account.
