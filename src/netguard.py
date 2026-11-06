"""Safe outbound webhooks.

Alert webhooks are URLs a user types in, and the server then sends requests to them.
Unchecked, that lets a user make the server call internal services or cloud metadata
endpoints (server-side request forgery). So:

  * https only, port 443 only, no credentials in the URL
  * every address the host name resolves to must be a public one
  * the connection is made to the address that was checked (so a DNS answer that
    changes between the check and the connection can't redirect it)
  * redirects are never followed
"""

import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse

TIMEOUT_SECONDS = 8


class WebhookError(Exception):
    pass


def check_webhook_url(url):
    """Return a user-facing problem with this URL, or None if it is acceptable."""
    if not isinstance(url, str) or len(url) > 500:
        return "Webhook URL must be text of at most 500 characters."
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return "That doesn't look like a valid URL."
    if parts.scheme != "https":
        return "Webhook URL must start with https://."
    if not parts.hostname or parts.username or parts.password:
        return "Webhook URL must have a host name and no embedded credentials."
    if port not in (None, 443):
        return "Webhook URL must use the standard HTTPS port (443)."
    try:
        literal = ipaddress.ip_address(parts.hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        return "Webhook URL must point to a public address."
    if parts.hostname.lower() in ("localhost",) or parts.hostname.lower().endswith((".local", ".internal")):
        return "Webhook URL must point to a public address."
    return None


def public_addresses(host, resolver=socket.getaddrinfo):
    """Resolve a host and require that every address is public."""
    try:
        infos = resolver(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WebhookError("Could not resolve the webhook host.") from exc
    addresses = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise WebhookError("The webhook host resolves to a non-public address.")
        addresses.append(str(ip))
    if not addresses:
        raise WebhookError("The webhook host has no addresses.")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-checked IP while still verifying the certificate for the host name."""

    def __init__(self, host, ip, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def post_json(url, payload, headers=None, resolver=socket.getaddrinfo):
    """POST a JSON body; returns the HTTP status. Raises WebhookError on any problem."""
    problem = check_webhook_url(url)
    if problem:
        raise WebhookError(problem)
    parts = urllib.parse.urlsplit(url)
    ip = public_addresses(parts.hostname, resolver)[0]
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    body = json.dumps(payload).encode()
    conn = _PinnedHTTPSConnection(parts.hostname, ip, context=ssl.create_default_context(), timeout=TIMEOUT_SECONDS)
    try:
        conn.request("POST", path, body, {"Content-Type": "application/json",
                                          "User-Agent": "log-anomaly-detector", **(headers or {})})
        response = conn.getresponse()
        response.read(2000)
        return response.status
    except (OSError, http.client.HTTPException) as exc:
        raise WebhookError(f"Could not reach the webhook ({type(exc).__name__}).") from exc
    finally:
        conn.close()
