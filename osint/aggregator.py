"""
Threat Intelligence Aggregator
Collects malicious IPs and domains from multiple OSINT feeds
"""

import requests
import json
import hashlib
import logging
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# ── Logging Setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/aggregator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── MongoDB Connection ─────────────────────────────────────────────────────────
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["indicators"]
collection.create_index("indicator", unique=True)  # Deduplication

# ── Helper ─────────────────────────────────────────────────────────────────────

def make_doc(indicator: str, ioc_type: str, source: str, tags: list, risk_score: int) -> dict:
    return {
        "indicator": indicator,
        "type": ioc_type,           # "ip" | "domain" | "url"
        "source": source,
        "tags": tags,
        "risk_score": risk_score,   # 0-100
        "first_seen": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        "blocked": False
    }


def upsert(doc: dict):
    """Insert or update (refresh last_seen) an indicator."""
    try:
        collection.update_one(
            {"indicator": doc["indicator"]},
            {"$setOnInsert": {k: v for k, v in doc.items() if k != "last_seen"}, "$set": {"last_seen": datetime.utcnow()}},
            upsert=True
        )
        logger.debug(f"Upserted: {doc['indicator']}")
    except Exception as e:
        logger.error(f"DB error for {doc['indicator']}: {e}")


# ── Feed 1 : AlienVault OTX ────────────────────────────────────────────────────

def fetch_alienvault_otx(api_key: str = "DEMO"):
    """
    Pulls the latest malicious IPs from AlienVault OTX IPv4 reputation feed.
    In demo mode we pull the public CSV instead of the API.
    """
    logger.info("Fetching AlienVault OTX feed …")
    url = "https://reputation.alienvault.com/reputation.data"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("#")
            ip = parts[0].strip()
            tags = [t.strip() for t in parts[1].split(",")] if len(parts) > 1 else []
            doc = make_doc(ip, "ip", "AlienVault_OTX", tags, risk_score=75)
            upsert(doc)
            count += 1
        logger.info(f"AlienVault OTX: {count} indicators ingested.")
    except Exception as e:
        logger.error(f"AlienVault OTX fetch failed: {e}")


# ── Feed 2 : Abuse.ch URLhaus ──────────────────────────────────────────────────

def fetch_urlhaus():
    """Downloads the URLhaus CSV (malicious URLs / domains)."""
    logger.info("Fetching Abuse.ch URLhaus feed …")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            mal_url = parts[2].strip().strip('"')
            threat_type = parts[4].strip().strip('"')
            doc = make_doc(mal_url, "url", "URLhaus", [threat_type], risk_score=80)
            upsert(doc)
            count += 1
        logger.info(f"URLhaus: {count} indicators ingested.")
    except Exception as e:
        logger.error(f"URLhaus fetch failed: {e}")


# ── Feed 3 : Emerging Threats Blocklist ───────────────────────────────────────

def fetch_emerging_threats():
    """Downloads Proofpoint Emerging Threats compromised IP list."""
    logger.info("Fetching Emerging Threats feed …")
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ip = line.strip()
            doc = make_doc(ip, "ip", "EmergingThreats", ["compromised"], risk_score=70)
            upsert(doc)
            count += 1
        logger.info(f"Emerging Threats: {count} indicators ingested.")
    except Exception as e:
        logger.error(f"Emerging Threats fetch failed: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

def run_all_feeds(api_key: str = "DEMO"):
    logger.info("===== Starting OSINT Aggregation Run =====")
    fetch_alienvault_otx(api_key)
    fetch_urlhaus()
    fetch_emerging_threats()
    total = collection.count_documents({})
    logger.info(f"===== Aggregation complete. Total unique indicators in DB: {total} =====")


if __name__ == "__main__":
    import os
    os.makedirs("logs", exist_ok=True)
    run_all_feeds()
