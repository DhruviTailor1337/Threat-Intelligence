"""
Alerting Module
Sends Slack / email notifications when new CRITICAL threats are detected or blocked.
"""

import os
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from pymongo import MongoClient
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Config (set via environment variables or .env) ─────────────────────────────
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO    = os.getenv("ALERT_EMAIL_TO", "")

# ── MongoDB ────────────────────────────────────────────────────────────────────
client    = MongoClient("mongodb://localhost:27017/")
db        = client["threat_intelligence"]
block_log = db["block_log"]


# ── Slack ──────────────────────────────────────────────────────────────────────

def send_slack(message: str):
    if not SLACK_WEBHOOK_URL:
        logger.warning("Slack webhook not configured, skipping.")
        return
    payload = {"text": message}
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Slack alert sent.")
    except Exception as e:
        logger.error(f"Slack send failed: {e}")


# ── Email ──────────────────────────────────────────────────────────────────────

def send_email(subject: str, body: str):
    if not (SMTP_USER and ALERT_EMAIL_TO):
        logger.warning("Email not configured, skipping.")
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.send_message(msg)
        logger.info("Email alert sent.")
    except Exception as e:
        logger.error(f"Email send failed: {e}")


# ── Alert on new blocks ────────────────────────────────────────────────────────

def alert_new_blocks(since_minutes: int = 5):
    """Find blocks in the last N minutes and send alerts."""
    since = datetime.utcnow() - timedelta(minutes=since_minutes)
    new_blocks = list(block_log.find({
        "action":    "BLOCK",
        "rolled_back": False,
        "timestamp": {"$gte": since}
    }))

    if not new_blocks:
        return

    lines = [f"🚨 *TIP Alert — {len(new_blocks)} new block(s) in the last {since_minutes}min*\n"]
    for b in new_blocks:
        lines.append(f"  • `{b['indicator']}` — {b.get('reason', 'N/A')} @ {b['timestamp'].strftime('%H:%M:%S UTC')}")

    message = "\n".join(lines)
    send_slack(message)
    send_email(
        subject=f"[TIP ALERT] {len(new_blocks)} threats auto-blocked",
        body="\n".join(lines)
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    alert_new_blocks(since_minutes=60)
