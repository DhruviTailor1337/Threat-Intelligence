"""
Dynamic Security Policy Enforcer
Monitors MongoDB for HIGH/CRITICAL indicators and automatically
blocks them via iptables (Linux) or simulated mode (cross-platform demo).
Includes a full rollback mechanism.
"""

import os
import time
import logging
import platform
import subprocess
from datetime import datetime
from pymongo import MongoClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/enforcer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = 30   # how often to scan for new threats
RISK_THRESHOLD        = 70   # block anything >= this score
SIMULATE              = (platform.system() != "Linux") or (os.geteuid() != 0)

# ── MongoDB ────────────────────────────────────────────────────────────────────
client     = MongoClient("mongodb://localhost:27017/")
db         = client["threat_intelligence"]
indicators = db["indicators"]
block_log  = db["block_log"]        # audit trail of every rule change

# ── Core firewall helpers ──────────────────────────────────────────────────────

def _run(cmd: list) -> bool:
    """Execute a shell command. Returns True on success."""
    if SIMULATE:
        logger.info(f"[SIMULATE] Would run: {' '.join(cmd)}")
        return True
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr.decode().strip()}")
        return False


def block_ip(ip: str, reason: str = "") -> bool:
    """Add an iptables DROP rule for the given IP."""
    ok = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        block_log.insert_one({
            "action":    "BLOCK",
            "indicator": ip,
            "type":      "ip",
            "reason":    reason,
            "rule":      f"iptables -A INPUT -s {ip} -j DROP",
            "timestamp": datetime.utcnow(),
            "rolled_back": False
        })
        indicators.update_one({"indicator": ip}, {"$set": {"blocked": True}})
        logger.warning(f"BLOCKED IP: {ip} — {reason}")
    return ok


def unblock_ip(ip: str) -> bool:
    """Remove the iptables DROP rule for the given IP (rollback)."""
    ok = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        block_log.update_many(
            {"indicator": ip, "action": "BLOCK", "rolled_back": False},
            {"$set": {"rolled_back": True, "rollback_time": datetime.utcnow()}}
        )
        indicators.update_one({"indicator": ip}, {"$set": {"blocked": False}})
        logger.info(f"UNBLOCKED IP (rollback): {ip}")
    return ok


# ── Main enforcement loop ──────────────────────────────────────────────────────

def enforce_once():
    """Single enforcement pass: find unblocked HIGH/CRITICAL IPs and block them."""
    query = {
        "type":      "ip",
        "risk_score": {"$gte": RISK_THRESHOLD},
        "blocked":   False
    }
    targets = list(indicators.find(query))
    if not targets:
        logger.info("No new high-risk IPs to block.")
        return 0

    count = 0
    for doc in targets:
        ip     = doc["indicator"]
        score  = doc.get("risk_score", 0)
        tags   = ", ".join(doc.get("tags", []))
        reason = f"Risk={score} Tags=[{tags}] Source={doc.get('source','?')}"
        if block_ip(ip, reason):
            count += 1

    logger.info(f"Enforcement pass complete: {count} IPs blocked.")
    return count


def daemon_loop():
    """Continuous monitoring daemon."""
    logger.info(f"Policy Enforcer started. Simulate={SIMULATE}, Threshold={RISK_THRESHOLD}, Poll={POLL_INTERVAL_SECONDS}s")
    while True:
        try:
            enforce_once()
        except Exception as e:
            logger.error(f"Enforcer error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)


# ── Rollback helpers ───────────────────────────────────────────────────────────

def rollback_ip(ip: str):
    """SOC analyst manually rolls back a specific IP block."""
    logger.info(f"Manual rollback requested for: {ip}")
    unblock_ip(ip)


def rollback_last_n(n: int = 5):
    """Rollback the most recent N block actions."""
    recent = list(
        block_log.find({"action": "BLOCK", "rolled_back": False})
                 .sort("timestamp", -1)
                 .limit(n)
    )
    if not recent:
        logger.info("No recent blocks to rollback.")
        return
    for entry in recent:
        rollback_ip(entry["indicator"])


def print_block_log(limit: int = 20):
    """Print recent block log entries for review."""
    print("\n── Recent Block Log ──────────────────────────────────────")
    for e in block_log.find().sort("timestamp", -1).limit(limit):
        status = "ROLLED_BACK" if e.get("rolled_back") else "ACTIVE"
        print(f"  [{status}] {e['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | {e['indicator']} | {e.get('reason','')}")
    print("─────────────────────────────────────────────────────────\n")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    os.makedirs("logs", exist_ok=True)

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "once":
            enforce_once()
        elif cmd == "rollback" and len(sys.argv) > 2:
            rollback_ip(sys.argv[2])
        elif cmd == "rollback-last":
            n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            rollback_last_n(n)
        elif cmd == "log":
            print_block_log()
        else:
            print("Usage: enforcer.py [once | rollback <IP> | rollback-last [N] | log]")
    else:
        daemon_loop()
