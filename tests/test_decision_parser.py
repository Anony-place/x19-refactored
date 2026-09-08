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

    def test_nested_object_after_completed(self):
        # Regression (AUDIT_REPORT.md Bug #6): the old non-greedy regex
        # truncated at the first '}', so any nested object following
        # "completed" made the whole decision unparseable.
        import json
        raw = json.dumps({
            "thinking": "recon",
            "reasoning": "enumerate ports",
            "next_command": "__x19_builtin__ net_scan 127.0.0.1 80",
            "finding": None,
            "completed": False,
            "_mission_task": {"key": "k1", "goal": "task", "depends_on": []},
        })
        d = parse_decision(raw)
        self.assertIsNotNone(d)
        self.assertEqual(d["next_command"], "__x19_builtin__ net_scan 127.0.0.1 80")
        self.assertIn("_mission_task", d)

    def test_plan_object_after_completed(self):
        import json
        raw = json.dumps({
            "thinking": "plan",
            "reasoning": "multi step",
            "next_command": "",
            "completed": False,
            "plan": {"steps": [{"command": "curl http://example.com/"}]},
        })
        d = parse_decision(raw)
        self.assertIsNotNone(d)
        self.assertIsInstance(d.get("plan"), dict)


if __name__ == "__main__":
    unittest.main()
