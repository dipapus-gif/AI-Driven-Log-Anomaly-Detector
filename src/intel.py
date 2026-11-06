"""Threat-intelligence lookups for the investigator agent.

Providers (each optional, enabled by an environment variable):
  ABUSEIPDB_API_KEY    AbuseIPDB abuse-confidence score
  VIRUSTOTAL_API_KEY   VirusTotal engine verdicts

With neither configured, only a small built-in demo feed is consulted (it knows the
simulator's attacker addresses) and answers say so, so a result is never mistaken
for live intelligence. Private addresses are never sent to a third party.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import features as F
from simulate import BEACON_IP, BRUTE_IP, EXFIL_IP, SCAN_IP

CACHE_SECONDS = 3600
TIMEOUT_SECONDS = 6

# Documentation address ranges (RFC 5737) stand in for attacker infrastructure.
DEMO_FEED = {
    BEACON_IP: ("malicious", 95, "known command-and-control server"),
    BRUTE_IP: ("malicious", 90, "mass SSH password-guessing source"),
    EXFIL_IP: ("suspicious", 70, "address seen receiving large bulk uploads"),
    SCAN_IP: ("malicious", 85, "internet-wide port scanner"),
}


def _http_json(url, headers):
    """GET a JSON document. Raises on any network or HTTP problem."""
    request = urllib.request.Request(url, headers={**headers, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 (fixed https hosts)
        return json.loads(response.read(1_000_000))


class IntelClient:
    def __init__(self, http=_http_json, environ=None, clock=time.time):
        self._http = http
        self._env = os.environ if environ is None else environ
        self._clock = clock
        self._cache = {}

    # ---- configuration -----------------------------------------------------

    def providers(self):
        names = []
        if self._env.get("ABUSEIPDB_API_KEY"):
            names.append("abuseipdb")
        if self._env.get("VIRUSTOTAL_API_KEY"):
            names.append("virustotal")
        return names

    @property
    def mode(self):
        return "live" if self.providers() else "demo-feed"

    # ---- lookups -----------------------------------------------------------

    def check_ip(self, ip):
        ip = F.valid_ip(str(ip or ""))
        if ip is None:
            return {"ip": None, "scope": "invalid", "reputation": "unknown", "score": None,
                    "sources": [], "note": "Not a valid IP address."}
        if F.is_internal(ip):
            return {"ip": ip, "scope": "internal", "reputation": "internal", "score": None, "sources": [],
                    "note": "Private address. Not sent to external services."}
        cached = self._cache.get(ip)
        if cached and self._clock() - cached[0] < CACHE_SECONDS:
            return cached[1]
        result = self._lookup(ip)
        self._cache[ip] = (self._clock(), result)
        return result

    def _lookup(self, ip):
        sources = []
        if ip in DEMO_FEED:
            verdict, score, why = DEMO_FEED[ip]
            sources.append({"name": "demo-feed", "live": False, "reputation": verdict, "score": score,
                            "summary": f"Demo feed: {why}."})
        for name, query in (("abuseipdb", self._abuseipdb), ("virustotal", self._virustotal)):
            if name in self.providers():
                try:
                    sources.append(query(ip))
                except Exception as exc:  # a provider outage must not stop the investigation
                    sources.append({"name": name, "live": True, "error": type(exc).__name__,
                                    "summary": f"{name} lookup failed."})

        usable = [s for s in sources if "score" in s]
        live_ok = any(s["live"] for s in usable)
        top = max((s["score"] for s in usable), default=None)
        if top is None:
            reputation = "unknown"
            note = ("No threat-intel provider answered." if self.providers()
                    else "No threat-intel provider is configured (set ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY).")
        elif top >= 50:
            reputation, note = "malicious", ""
        elif top >= 20:
            reputation, note = "suspicious", ""
        else:
            reputation, note = "clean", ("" if live_ok else "Only the demo feed was consulted.")
        return {"ip": ip, "scope": "external", "reputation": reputation, "score": top,
                "sources": sources, "note": note}

    def _abuseipdb(self, ip):
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        data = self._http(f"https://api.abuseipdb.com/api/v2/check?{query}",
                          {"Key": self._env["ABUSEIPDB_API_KEY"]})["data"]
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        rep = "malicious" if score >= 50 else "suspicious" if score >= 20 else "clean"
        return {"name": "abuseipdb", "live": True, "reputation": rep, "score": score,
                "summary": f"AbuseIPDB confidence {score}/100 from {reports} reports in 90 days "
                           f"({data.get('countryCode') or '?'}, {data.get('isp') or 'unknown ISP'})."}

    def _virustotal(self, ip):
        stats = self._http(f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}",
                           {"x-apikey": self._env["VIRUSTOTAL_API_KEY"]})["data"]["attributes"]["last_analysis_stats"]
        bad, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        score = min(100, bad * 20 + sus * 5)
        rep = "malicious" if bad >= 3 else "suspicious" if bad >= 1 or sus >= 2 else "clean"
        return {"name": "virustotal", "live": True, "reputation": rep, "score": score,
                "summary": f"VirusTotal: {bad} engines say malicious, {sus} suspicious, out of {total}."}
