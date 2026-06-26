import unittest

from brain.decision_parser import parse_decision


class DecisionParserTests(unittest.TestCase):
    def test_valid_json_decision(self):
        d = parse_decision('{"completed": false, "next_command": "nmap -sV example.com"}')
        self.assertIsNotNone(d)
        self.assertFalse(d["completed"])
        self.assertEqual(d["next_command"], "nmap -sV example.com")

    def test_completed_decision(self):
        d = parse_decision('{"completed": true}')
        self.assertIsNotNone(d)
        self.assertTrue(d["completed"])

    def test_empty_input_returns_none(self):
        self.assertIsNone(parse_decision(""))

    def test_malformed_json_returns_none(self):
        self.assertIsNone(parse_decision("not json at all"))

    def test_trailing_comma_tolerated(self):
        d = parse_decision('{"completed": false, "next_command": "curl example.com",}')
        self.assertIsNotNone(d)
        self.assertEqual(d["next_command"], "curl example.com")

    def test_prose_fallback_extracts_nmap(self):
        # No JSON block, no EXEC:, no backticks with tool names → None
        result = parse_decision("I think we should run: nmap -sV example.com to find open ports.")
        self.assertIsNone(result)

    def test_exec_directive(self):
        d = parse_decision("EXEC: nmap -sV example.com")
        self.assertIsNotNone(d)
        self.assertEqual(d["next_command"], "nmap -sV example.com")

    def test_longcat_tool_call(self):
        raw = '<longcat_tool_call><longcat_arg_key>command</longcat_arg_key><longcat_arg_value>curl example.com</longcat_arg_value></longcat_tool_call>'
        d = parse_decision(raw)
        self.assertIsNotNone(d)
        self.assertEqual(d["next_command"], "curl example.com")


if __name__ == "__main__":
    unittest.main()
