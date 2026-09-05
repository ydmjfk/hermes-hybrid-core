#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-008: Chat File Exfiltration Defense Test Matrix
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hermes_core.chat_client import send_chat_file


class TestChatFileExfiltration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        os.environ["HERMES_WORKSPACE_ROOT"] = str(self.workspace)
        os.environ["SYNOLOGY_CHAT_OUTGOING_TOKEN"] = "mock_outgoing_token"
        os.environ["SYNOLOGY_CHAT_INCOMING_URL"] = "https://chat.synology.mock/webhook"

        # Create allowed file inside workspace
        self.allowed_file = self.workspace / "allowed.txt"
        self.allowed_file.write_text("Hello allowed report", encoding="utf-8")

        # Create sensitive files inside workspace that must still be blocked by name/extension
        self.env_file = self.workspace / ".env"
        self.env_file.write_text("SECRET_KEY=12345", encoding="utf-8")

        # Create an outside secret file
        self.outside_secret = Path(tempfile.gettempdir()) / f"outside_leak_{os.getpid()}.txt"
        self.outside_secret.write_text("classified outside content", encoding="utf-8")

        # Create symlink pointing to outside secret
        self.symlink_file = self.workspace / "symlink-to-secret"
        if not self.symlink_file.exists():
            os.symlink(self.outside_secret, self.symlink_file)

    def tearDown(self):
        if self.outside_secret.exists():
            self.outside_secret.unlink()
        self.temp_dir.cleanup()

    def test_sec_008_chat_file_blocked_sensitive_names(self):
        """SEC-008: .env and sensitive files must be blocked from chat exfiltration"""
        res = send_chat_file(str(self.env_file))
        self.assertFalse(res, "Expected .env exfiltration to be BLOCKED")

    def test_sec_008_chat_file_blocked_ssh_key(self):
        """SEC-008: ~/.ssh/id_rsa must be blocked from chat exfiltration"""
        res = send_chat_file("~/.ssh/id_rsa")
        self.assertFalse(res, "Expected ~/.ssh/id_rsa exfiltration to be BLOCKED")

    def test_sec_008_chat_file_blocked_path_traversal(self):
        """SEC-008: ../secret.txt and encoded traversal must be blocked"""
        res1 = send_chat_file("../secret.txt")
        self.assertFalse(res1, "Expected ../secret.txt to be BLOCKED")

        res2 = send_chat_file("%2e%2e/secret.txt")
        self.assertFalse(res2, "Expected %2e%2e/secret.txt to be BLOCKED")

    def test_sec_008_chat_file_blocked_symlink_escape(self):
        """SEC-008: symlink pointing outside sandbox must be blocked"""
        res = send_chat_file(str(self.symlink_file))
        self.assertFalse(res, "Expected symlink to outside to be BLOCKED")

    def test_sec_008_chat_file_blocked_file_scheme_bypass(self):
        """SEC-008: file:// scheme prefix bypass attempt must be blocked"""
        res = send_chat_file(f"file://{self.outside_secret}")
        self.assertFalse(res, "Expected file:// outside sandbox to be BLOCKED")

    @patch("urllib.request.urlopen")
    def test_sec_008_chat_file_allowed_within_workspace(self, mock_urlopen):
        """SEC-008: Verified allowed file within workspace is permitted to send"""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"success": true}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = send_chat_file(str(self.allowed_file))
        self.assertTrue(res, "Expected safe workspace file to be allowed")


if __name__ == "__main__":
    unittest.main()
