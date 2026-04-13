# Threat-Intelligence
# 🛡️ Threat Intelligence Platform (TIP)
### Infotact Technical Internship — Finance & Banking Cybersecurity Project

---

## 📌 Overview

An end-to-end **Threat Intelligence Platform** that:
1. **Ingests** malicious IPs, domains, and URLs from 3 public OSINT feeds
2. **Normalizes** and risk-scores every indicator in MongoDB
3. **Syncs** to an ELK Stack (Elasticsearch + Kibana) SIEM for visual analysis
4. **Automatically blocks** HIGH/CRITICAL IPs via `iptables` (or simulated mode)
5. **Alerts** SOC analysts via Slack and email
6. **Rolls back** false-positive blocks with a single command

---

## 🗂️ Project Structure

```
threat_intelligence_platform/
├── osint/
│   └── aggregator.py          # OSINT feed ingestion (AlienVault, URLhaus, EmergingThreats)
├── siem/
│   ├── normalizer.py          # Risk scoring + Elasticsearch sync
│   └── logstash.conf          # Logstash MongoDB→ES pipeline
├── enforcer/
│   ├── enforcer.py            # Dynamic iptables policy enforcer + rollback
│   └── alerting.py            # Slack / email alerting module
├── dashboard/
│   └── kibana_dashboard.ndjson # Kibana dashboard import file
├── tests/
│   └── test_tip.py            # Pytest unit tests
├── docker-compose.yml         # MongoDB + ELK Stack
├── main.py                    # Orchestration runner
├── requirements.txt
└── README.md
```

---

## ⚙️ Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.10+ | Core language |
| Docker + Docker Compose | Latest | MongoDB & ELK Stack |
| Linux (root) | Any distro | iptables enforcement (optional) |

---

## 🚀 Quick Start

### Step 1 — Clone & Install dependencies
```bash
git clone https://github.com/YOUR_USERNAME/threat-intelligence-platform.git
cd threat-intelligence-platform
pip install -r requirements.txt
```

### Step 2 — Start MongoDB + ELK Stack
```bash
docker-compose up -d
# Wait ~60 seconds for Elasticsearch to initialize
```

### Step 3 — Configure environment (optional)
```bash
cp .env.example .env
# Edit .env with your API keys and Slack webhook
```

### Step 4 — Run the full pipeline (one shot)
```bash
python main.py --once
```

### Step 5 — Import Kibana Dashboard
```
Open http://localhost:5601
→ Stack Management → Saved Objects → Import
→ Select: dashboard/kibana_dashboard.ndjson
```

---

## 🔄 4-Week Development Roadmap

### Week 1 — OSINT Ingestion & Database Design
- [x] Set up Linux environment + Python venv
- [x] `osint/aggregator.py` — connects to AlienVault OTX, URLhaus, EmergingThreats
- [x] MongoDB schema with deduplication via unique index on `indicator`
- [x] Logs all ingestion activity to `logs/aggregator.log`

### Week 2 — Normalization & SIEM Integration
- [x] `siem/normalizer.py` — tag-based risk scoring engine (0–100)
- [x] Severity labels: LOW / MEDIUM / HIGH / CRITICAL
- [x] Elasticsearch bulk push with index mapping
- [x] `siem/logstash.conf` — Logstash MongoDB→ES live sync pipeline
- [x] Kibana dashboard JSON export (5 panels)

### Week 3 — Dynamic Policy Enforcement Engine
- [x] `enforcer/enforcer.py` — daemon polls MongoDB every 30s
- [x] Auto-blocks IPs with `risk_score >= 70` via `iptables`
- [x] Full simulation mode for non-root / Windows environments
- [x] Every block action logged to `block_log` collection (audit trail)
- [x] MongoDB `blocked` flag updated after each action

### Week 4 — Alerting, Rollback & Final Reporting
- [x] `enforcer/alerting.py` — Slack webhook + SMTP email alerts
- [x] Rollback commands: `python enforcer/enforcer.py rollback <IP>`
- [x] Batch rollback: `python enforcer/enforcer.py rollback-last 5`
- [x] Block log viewer: `python enforcer/enforcer.py log`
- [x] `tests/test_tip.py` — 8 unit tests covering all modules
- [x] `main.py` — scheduled hourly pipeline runner

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Expected output:
```
tests/test_tip.py::TestRiskScoring::test_base_score_no_tags        PASSED
tests/test_tip.py::TestRiskScoring::test_ransomware_tag_adds_25    PASSED
tests/test_tip.py::TestRiskScoring::test_score_capped_at_100       PASSED
tests/test_tip.py::TestRiskScoring::test_severity_critical         PASSED
tests/test_tip.py::TestRiskScoring::test_severity_high             PASSED
tests/test_tip.py::TestRiskScoring::test_severity_medium           PASSED
tests/test_tip.py::TestRiskScoring::test_severity_low              PASSED
tests/test_tip.py::TestEnforcer::test_block_ip_simulate            PASSED
tests/test_tip.py::TestEnforcer::test_unblock_ip_simulate          PASSED
tests/test_tip.py::TestEnforcer::test_enforce_once_no_targets      PASSED
tests/test_tip.py::TestEnforcer::test_enforce_once_blocks_high_risk PASSED
tests/test_tip.py::TestAggregator::test_emerging_threats_parse     PASSED
tests/test_tip.py::TestAggregator::test_skips_comments             PASSED
```

---

## 🔒 Rollback Mechanism

```bash
# Rollback a specific IP
python enforcer/enforcer.py rollback 1.2.3.4

# Rollback last 5 blocked IPs
python enforcer/enforcer.py rollback-last 5

# View full block audit log
python enforcer/enforcer.py log
```

---

## 📊 MongoDB Schema

```json
{
  "indicator":  "1.2.3.4",
  "type":       "ip",
  "source":     "AlienVault_OTX",
  "tags":       ["malware", "botnet"],
  "risk_score": 90,
  "severity":   "CRITICAL",
  "first_seen": "2024-01-15T10:00:00Z",
  "last_seen":  "2024-01-15T12:30:00Z",
  "blocked":    true
}
```

---

## 🌐 OSINT Feeds Used

| Feed | URL | Type |
|------|-----|------|
| AlienVault OTX | reputation.alienvault.com | Malicious IPs |
| Abuse.ch URLhaus | urlhaus.abuse.ch | Malicious URLs |
| Emerging Threats | rules.emergingthreats.net | Compromised IPs |

---

## 🔑 Environment Variables (.env)

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your_app_password
ALERT_EMAIL_TO=soc@yourcompany.com
```

---

## 📋 PCI-DSS Compliance Notes

- All firewall rule changes are logged with timestamps in `block_log`
- Rollback mechanism provides SOC analysts with false-positive correction
- MongoDB stores immutable `first_seen` timestamp for each indicator
- ELK Stack provides audit-ready searchable event history

---

## 👨‍💻 Author

Infotact Internship — Finance & Banking Cybersecurity Track  
Bengaluru, Karnataka
