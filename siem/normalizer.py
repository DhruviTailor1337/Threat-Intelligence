"""
Threat Normalizer & Risk Scorer
Reads raw indicators from MongoDB, enriches them with risk scores,
and pushes normalized documents to Elasticsearch (SIEM).
"""

import logging
import os
from datetime import datetime
from pymongo import MongoClient

# ── Elasticsearch (optional) ───────────────────────────────────────────────────
try:
    from elasticsearch import Elasticsearch, helpers
    es = Elasticsearch("http://localhost:9200")
    es.info()  # test connection
    ES_AVAILABLE = True
except Exception:
    es = None
    ES_AVAILABLE = False

# ── Logging ────────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/normalizer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

if not ES_AVAILABLE:
    logger.warning("Elasticsearch not available — skipping SIEM sync (simulation mode).")

# ── Connections ────────────────────────────────────────────────────────────────
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["threat_intelligence"]
collection = db["indicators"]

# ── Risk Scoring Rules ─────────────────────────────────────────────────────────

TAG_SCORES = {
    "malware":          20,
    "botnet":           15,
    "phishing":         15,
    "ransomware":       25,
    "exploit":          20,
    "c2":               25,
    "compromised":      10,
    "scanner":           5,
    "spam":              5,
}

def compute_risk_score(doc: dict) -> int:
    base = doc.get("risk_score", 50)
    bonus = sum(TAG_SCORES.get(t.lower(), 0) for t in doc.get("tags", []))
    return min(base + bonus, 100)


def normalize(doc: dict) -> dict:
    return {
        "_index": "threat-indicators",
        "_id": str(doc["_id"]),
        "_source": {
            "indicator":    doc["indicator"],
            "type":         doc["type"],
            "source":       doc["source"],
            "tags":         doc["tags"],
            "risk_score":   compute_risk_score(doc),
            "first_seen":   doc["first_seen"].isoformat() if isinstance(doc["first_seen"], datetime) else doc["first_seen"],
            "last_seen":    doc["last_seen"].isoformat() if isinstance(doc["last_seen"], datetime) else doc["last_seen"],
            "blocked":      doc.get("blocked", False),
            "severity":     severity_label(compute_risk_score(doc)),
        }
    }


def severity_label(score: int) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 50: return "MEDIUM"
    return "LOW"


# ── Push to Elasticsearch ──────────────────────────────────────────────────────

def create_index_if_missing():
    if not ES_AVAILABLE:
        return
    if not es.indices.exists(index="threat-indicators"):
        es.indices.create(index="threat-indicators", body={
            "mappings": {
                "properties": {
                    "indicator":  {"type": "keyword"},
                    "type":       {"type": "keyword"},
                    "source":     {"type": "keyword"},
                    "tags":       {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "severity":   {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen":  {"type": "date"},
                    "blocked":    {"type": "boolean"},
                }
            }
        })
        logger.info("Created Elasticsearch index: threat-indicators")


def push_to_elasticsearch(batch_size: int = 500):
    if not ES_AVAILABLE:
        logger.warning("Skipping Elasticsearch push — ES not running.")
        return
    create_index_if_missing()
    cursor = collection.find({})
    docs = [normalize(d) for d in cursor]
    if not docs:
        logger.warning("No indicators found in MongoDB.")
        return
    success, errors = helpers.bulk(es, docs, raise_on_error=False)
    logger.info(f"Elasticsearch bulk push: {success} OK, {len(errors)} errors.")
    if errors:
        for e in errors[:5]:
            logger.error(f"ES error: {e}")


# ── Update risk scores back into MongoDB ───────────────────────────────────────

def update_risk_scores_in_mongo():
    """Recompute and persist risk scores so the enforcer can query HIGH/CRITICAL."""
    logger.info("Updating risk scores in MongoDB ...")
    updated = 0
    for doc in collection.find({}):
        new_score = compute_risk_score(doc)
        new_severity = severity_label(new_score)
        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"risk_score": new_score, "severity": new_severity}}
        )
        updated += 1
    logger.info(f"Updated risk scores for {updated} indicators.")


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    update_risk_scores_in_mongo()
    push_to_elasticsearch()
    logger.info("Normalization and SIEM sync complete.")