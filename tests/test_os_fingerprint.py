import unittest
from unittest.mock import patch

from os_fingerprint import detect_os


class OSFingerprintTests(unittest.TestCase):
    def test_windows_signals_win(self):
        def fake_connect(host, port, timeout=1.2):
            if port in (135, 445, 3389):
                return True, "", 1.0
            return False, "", 1.0

        with patch("os_fingerprint._connect", side_effect=fake_connect), \
             patch("os_fingerprint._http_signals", return_value=[]):
            result = detect_os("example.test", use_nmap=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["os_family"], "windows")
        self.assertGreater(result["confidence"], 0)

    def test_linux_ssh_banner(self):
        def fake_connect(host, port, timeout=1.2):
            if port == 22:
                return True, "SSH-2.0-OpenSSH_9.6", 1.0
            return False, "", 1.0

        with patch("os_fingerprint._connect", side_effect=fake_connect), \
             patch("os_fingerprint._http_signals", return_value=[]):
            result = detect_os("example.test", use_nmap=False)
        self.assertEqual(result["os_family"], "linux")

    def test_unknown_without_signals(self):
        with patch("os_fingerprint._connect", return_value=(False, "", 1.0)), \
             patch("os_fingerprint._http_signals", return_value=[]):
            result = detect_os("example.test", use_nmap=False)
        self.assertEqual(result["os_family"], "unknown")
        self.assertEqual(result["confidence"], 0.0)


if __name__ == "__main__":
    unittest.main()
