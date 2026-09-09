import unittest

from brain.cognitive_runtime import CognitiveRuntime, COGNITIVE_CONTRACT, self_check


class CognitiveRuntimeTests(unittest.TestCase):
    def test_contract_is_explicit(self):
        rt = CognitiveRuntime()
        prompt = rt.prompt("base")
        self.assertIn("STATE:", prompt)
        self.assertIn("HYPOTHESIS:", prompt)
        self.assertIn("EVIDENCE:", prompt)
        self.assertIn("UPDATE:", prompt)

    def test_state_is_bounded(self):
        rt = CognitiveRuntime()
        for i in range(30):
            rt.observe(facts=[f"fact-{i}"], unknowns=[f"unknown-{i}"])
        state = rt.state.compact()
        self.assertLessEqual(len(state["known"]), 12)
        self.assertLessEqual(len(state["unknowns"]), 8)

    def test_self_check(self):
        result = self_check()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["phases"][-1], "report")


if __name__ == "__main__":
    unittest.main()
