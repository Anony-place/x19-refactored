import unittest

from brain.reflection_engine import reflect_on_command


class ReflectionEngineTests(unittest.TestCase):
    def test_successful_command(self):
        out = reflect_on_command("nmap -sV example.com", "21/tcp open ftp", 0)
        self.assertIn("SUCCESS", out)
        self.assertIn("open port(s)", out)

    def test_empty_command_returns_empty(self):
        self.assertEqual(reflect_on_command("", "output", 0), "")

    def test_timeout_failure(self):
        out = reflect_on_command("nmap -sV example.com", "timed out", 1)
        self.assertIn("timeout", out.lower())
        self.assertIn("PIVOT", out)

    def test_connection_refused(self):
        out = reflect_on_command("curl example.com", "connection refused", 1)
        self.assertIn("connection refused", out.lower())

    def test_output_signals_urls_and_ips(self):
        out = reflect_on_command("httpx example.com", "http://a.com [200]\n10.0.0.1", 0)
        self.assertIn("URL", out)
        self.assertIn("IP", out)

    def test_empty_output(self):
        out = reflect_on_command("cat /etc/passwd", "", 0)
        self.assertIn("empty", out.lower())


if __name__ == "__main__":
    unittest.main()
