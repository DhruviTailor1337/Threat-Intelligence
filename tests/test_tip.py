"""
Unit Tests – Threat Intelligence Platform
Run with: pytest tests/
"""

import pytest
from unittest.mock import MagicMock, patch

# ───────────────────────────────────────────────────────────────────────────────
# Normalizer tests
# ───────────────────────────────────────────────────────────────────────────────

from siem.normalizer import compute_risk_score, severity_label

class TestRiskScoring:
    def test_base_score_no_tags(self):
        doc = {"risk_score": 50, "tags": []}
        assert compute_risk_score(doc) == 50

    def test_ransomware_tag_adds_25(self):
        doc = {"risk_score": 60, "tags": ["ransomware"]}
        assert compute_risk_score(doc) == 85

    def test_score_capped_at_100(self):
        doc = {"risk_score": 90, "tags": ["ransomware", "c2", "malware"]}
        assert compute_risk_score(doc) == 100

    def test_severity_critical(self):
        assert severity_label(90) == "CRITICAL"

    def test_severity_high(self):
        assert severity_label(75) == "HIGH"

    def test_severity_medium(self):
        assert severity_label(55) == "MEDIUM"

    def test_severity_low(self):
        assert severity_label(30) == "LOW"


# ───────────────────────────────────────────────────────────────────────────────
# Enforcer tests
# ───────────────────────────────────────────────────────────────────────────────

class TestEnforcer:

    @patch("enforcer.enforcer.SIMULATE", True)
    @patch("enforcer.enforcer.indicators")
    @patch("enforcer.enforcer.block_log")
    def test_block_ip_simulate(self, mock_log, mock_col):
        from enforcer.enforcer import block_ip
        result = block_ip("1.2.3.4", "Test block")
        assert result is True
        mock_col.update_one.assert_called_once()
        mock_log.insert_one.assert_called_once()

    @patch("enforcer.enforcer.SIMULATE", True)
    @patch("enforcer.enforcer.indicators")
    @patch("enforcer.enforcer.block_log")
    def test_unblock_ip_simulate(self, mock_log, mock_col):
        from enforcer.enforcer import unblock_ip
        result = unblock_ip("1.2.3.4")
        assert result is True
        mock_log.update_many.assert_called_once()
        mock_col.update_one.assert_called_once()

    @patch("enforcer.enforcer.SIMULATE", True)
    @patch("enforcer.enforcer.indicators")
    @patch("enforcer.enforcer.block_ip")
    def test_enforce_once_no_targets(self, mock_block, mock_col):
        mock_col.find.return_value = []
        from enforcer.enforcer import enforce_once
        count = enforce_once()
        assert count == 0
        mock_block.assert_not_called()

    @patch("enforcer.enforcer.SIMULATE", True)
    @patch("enforcer.enforcer.indicators")
    @patch("enforcer.enforcer.block_ip", return_value=True)
    def test_enforce_once_blocks_high_risk(self, mock_block, mock_col):
        mock_col.find.return_value = [
            {"indicator": "10.0.0.1", "risk_score": 80, "tags": ["malware"], "source": "OTX"},
            {"indicator": "10.0.0.2", "risk_score": 90, "tags": ["c2"],      "source": "URLhaus"},
        ]
        from enforcer.enforcer import enforce_once
        count = enforce_once()
        assert count == 2
        assert mock_block.call_count == 2


# ───────────────────────────────────────────────────────────────────────────────
# Aggregator tests (mocked network)
# ───────────────────────────────────────────────────────────────────────────────

class TestAggregator:

    @patch("osint.aggregator.requests.get")
    @patch("osint.aggregator.upsert")
    def test_emerging_threats_parse(self, mock_upsert, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = "# comment\n1.2.3.4\n5.6.7.8\n"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from osint.aggregator import fetch_emerging_threats
        fetch_emerging_threats()

        assert mock_upsert.call_count == 2
        calls = [c.args[0]["indicator"] for c in mock_upsert.call_args_list]
        assert "1.2.3.4" in calls
        assert "5.6.7.8" in calls

    @patch("osint.aggregator.requests.get")
    @patch("osint.aggregator.upsert")
    def test_skips_comments(self, mock_upsert, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = "# skip this\n\n9.9.9.9\n"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from osint.aggregator import fetch_emerging_threats
        fetch_emerging_threats()
        assert mock_upsert.call_count == 1
