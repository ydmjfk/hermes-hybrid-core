#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-013 ~ SEC-014: Logging & Evidence Ledger Hardening Test Matrix
"""

import os
import sys
import io
import logging
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hermes_core.evidence_logger import (
    log_event,
    record_evidence,
    get_recent_evidence,
    MAX_SUMMARY_BYTES,
    MAX_JSON_DEPTH
)
from hermes_core.config_loader import get_db_path


class TestLeakageHardeningSecurity(unittest.TestCase):

    def test_sec_013_logger_secret_leakage_prevention(self):
        """SEC-013: Logger must automatically redact sensitive keys and passwords"""
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("hermes.test_logger")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        raw_secret = "sk-" + "9876543210abcdef9876543210abcdef"
        msg = f"API 呼叫失敗，金鑰資訊: {raw_secret}"
        log_event("test_logger", msg, level="INFO")

        captured_output = log_capture.getvalue()
        self.assertNotIn(raw_secret, captured_output)
        self.assertIn("[REDACTED]", captured_output)

        logger.removeHandler(handler)

    def test_sec_014_evidence_ledger_secret_leakage_and_limits(self):
        """SEC-014: Evidence Ledger must sanitize secrets and enforce size bounds"""
        db_path = get_db_path("verification_evidence")
        mock_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        oversized_summary = ("A" * (MAX_SUMMARY_BYTES + 1000)) + f" Token: {mock_token}"

        record_evidence(
            task_id="sec_task_014",
            tool_name="tool_tester",
            exit_code=0,
            status="SUCCESS",
            evidence_summary=oversized_summary
        )

        records = get_recent_evidence(limit=1)
        self.assertTrue(len(records) > 0)
        rec = records[0]

        # Verify token is redacted
        self.assertNotIn(mock_token, rec["summary"])
        # Verify size limit was enforced
        self.assertTrue(len(rec["summary"].encode("utf-8")) <= MAX_SUMMARY_BYTES + 100)
        self.assertIn("[TRUNCATED]", rec["summary"])


if __name__ == "__main__":
    unittest.main()
