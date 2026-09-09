import unittest
from terminal_behavior import _natural_target


class TerminalBehaviorTests(unittest.TestCase):
    def test_target_phrase(self):
        self.assertEqual(_natural_target("target example.com"), "example.com")

    def test_scan_phrase(self):
        self.assertEqual(_natural_target("scan 192.0.2.10"), "192.0.2.10")

    def test_normal_chat_stays_chat(self):
        self.assertEqual(_natural_target("how does X19 work"), "")


if __name__ == "__main__":
    unittest.main()
