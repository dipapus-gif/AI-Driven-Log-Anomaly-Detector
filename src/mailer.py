"""Outgoing email for account verification and password reset. Standard library only.

Configuration (environment variables). Set EMAIL_FROM plus ONE provider:
  RESEND_API_KEY                        send through Resend's HTTPS API
  SMTP_HOST [SMTP_PORT] SMTP_USER SMTP_PASSWORD
                                        send through any SMTP server (STARTTLS, port 587 by default),
                                        for example Gmail with an app password
  EMAIL_PROVIDER=console                development only: print the message to the server log
                                        (ignored on Vercel, where the log is not private)
  APP_BASE_URL                          public address used in links, e.g. https://your-app.vercel.app
                                        (falls back to VERCEL_PROJECT_PRODUCTION_URL; the request's Host
                                        header is never trusted)

With no provider, email features are off: sign-up does not ask for an email and nobody is gated.
"""

import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage


def provider() -> str:
    if not os.environ.get("EMAIL_FROM"):
        return ""
    if os.environ.get("RESEND_API_KEY"):
        return "resend"
    if os.environ.get("SMTP_HOST"):
        return "smtp"
    if os.environ.get("EMAIL_PROVIDER") == "console" and not os.environ.get("VERCEL"):
        return "console"
    return ""


def base_url() -> str:
    url = os.environ.get("APP_BASE_URL", "").strip()
    if not url and os.environ.get("VERCEL_PROJECT_PRODUCTION_URL"):
        url = "https://" + os.environ["VERCEL_PROJECT_PRODUCTION_URL"]
    return url.rstrip("/") if url.startswith(("https://", "http://")) else ""


def configured() -> bool:
    """True only when there is both a way to send and a trustworthy address to link to."""
    return bool(provider() and base_url())


def send_email(to: str, subject: str, text: str) -> None:
    """Send one plain-text message. Raises on failure so callers can decide what to tell the user."""
    sender, kind = os.environ["EMAIL_FROM"], provider()
    if kind == "resend":
        body = json.dumps({"from": sender, "to": [to], "subject": subject, "text": text}).encode()
        req = urllib.request.Request(
            "https://api.resend.com/emails", data=body, method="POST",
            headers={"Authorization": "Bearer " + os.environ["RESEND_API_KEY"],
                     "Content-Type": "application/json", "User-Agent": "log-anomaly-detector/1.0"},
        )
        urllib.request.urlopen(req, timeout=10).read()
    elif kind == "smtp":
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, to, subject
        msg.set_content(text)
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587")), timeout=10) as s:
            s.starttls(context=ssl.create_default_context())
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
    elif kind == "console":
        print(f"[email to {to}] {subject}\n{text}\n", flush=True)
    else:
        raise RuntimeError("No email provider is configured.")


def verify_message(link: str):
    return ("Confirm your email address",
            f"Confirm this email address for your Log Anomaly Detector account:\n\n{link}\n\n"
            "The link works once and expires in 24 hours. If you didn't create an account, ignore this message.")


def reset_message(link: str):
    return ("Reset your password",
            f"Someone asked to reset the password for your Log Anomaly Detector account. To choose a new one:\n\n{link}\n\n"
            "The link works once and expires in 1 hour. If this wasn't you, ignore this message; your password is unchanged.")
