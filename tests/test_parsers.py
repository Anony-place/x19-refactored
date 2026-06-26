import unittest

from parsers import NmapParser, HttpxParser, GobusterParser, FfufParser


class NmapParserTests(unittest.TestCase):
    def test_parses_single_open_port(self):
        parser = NmapParser()
        stdout = "21/tcp   open  ftp    vsftpd 3.0.3"
        results = parser.parse("nmap -sV 10.0.0.1", stdout)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["port"], 21)
        self.assertEqual(results[0]["service"], "ftp")
        self.assertEqual(results[0]["version"], "vsftpd 3.0.3")

    def test_parses_multiple_ports(self):
        parser = NmapParser()
        stdout = (
            "21/tcp   open  ftp    vsftpd 3.0.3\n"
            "22/tcp   open  ssh    OpenSSH 8.9\n"
            "80/tcp   open  http   nginx 1.18.0\n"
        )
        results = parser.parse("nmap -sV 10.0.0.1", stdout)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[1]["service"], "ssh")
        self.assertEqual(results[2]["service"], "http")

    def test_empty_output_returns_empty_list(self):
        parser = NmapParser()
        results = parser.parse("nmap -sV 10.0.0.1", "")
        self.assertEqual(results, [])


class HttpxParserTests(unittest.TestCase):
    def test_parses_status_codes(self):
        parser = HttpxParser()
        stdout = (
            "http://10.0.0.1 [200]\n"
            "https://10.0.0.1 [301]\n"
        )
        results = parser.parse("httpx -u http://10.0.0.1", stdout)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["status"], 200)
        self.assertEqual(results[0]["url"], "http://10.0.0.1")

    def test_returns_empty_when_no_brackets(self):
        parser = HttpxParser()
        results = parser.parse("httpx -u http://10.0.0.1", "no matches")
        self.assertEqual(results, [])


class GobusterParserTests(unittest.TestCase):
    def test_parses_directory(self):
        parser = GobusterParser()
        stdout = "/admin    (Status: 301)\n/login    (Status: 200)\n"
        command = "gobuster dir -u http://10.0.0.1 -w wordlist.txt"
        results = parser.parse(command, stdout)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["url"], "http://10.0.0.1/admin")
        self.assertEqual(results[0]["status"], 301)
        self.assertEqual(results[1]["status"], 200)

    def test_returns_empty_when_no_matches(self):
        parser = GobusterParser()
        results = parser.parse("gobuster dir -u http://10.0.0.1 -w wordlist.txt", "nothing")
        self.assertEqual(results, [])


class FfufParserTests(unittest.TestCase):
    def test_parses_fuzzing_results(self):
        parser = FfufParser()
        stdout = "/admin  [Status: 200, Size: 1234, Words: 45]\n/.env   [Status: 403, Size: 200, Words: 10]\n"
        command = "ffuf -u http://10.0.0.1/FUZZ -w wordlist.txt"
        results = parser.parse(command, stdout)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["url"], "http://10.0.0.1/admin")
        self.assertEqual(results[0]["status"], 200)
        self.assertEqual(results[1]["url"], "http://10.0.0.1/.env")

    def test_returns_empty_when_no_matches(self):
        parser = FfufParser()
        results = parser.parse("ffuf -u http://10.0.0.1/FUZZ -w wordlist.txt", "nothing")
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
