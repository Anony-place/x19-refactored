import unittest
from unittest.mock import patch

from config import CONFIG
from runtime.model_control import switch_model


class FakePrimary:
    def __init__(self):
        self.model = "old-model"
        self.provider = "groq"


class FakeRouter:
    def __init__(self):
        self.primary_provider_id = "groq"
        self.primary_model = "old-model"
        self.primary = FakePrimary()
        self._working = ("groq", "old-model")
        self._exhausted = {("groq", "new-model")}

    def name(self):
        return f"Groq/{self._working[1]}"


class FakeSession:
    pass


class FakeAgent:
    def __init__(self):
        self.ai = FakeRouter()
        self.session = FakeSession()
        self.target = "authorized.example"


class RuntimeModelControlTests(unittest.TestCase):
    def test_switch_updates_live_backend_not_agent(self):
        agent = FakeAgent()
        original_ai = agent.ai
        original_session = agent.session

        with patch("provider_manager.discover_models", return_value=(True, ["new-model"], "ok")), \
             patch("provider_manager._verify", return_value=(True, "live API request succeeded")):
            active = switch_model(agent, "new-model")

        self.assertEqual(active, "groq/new-model")
        self.assertIs(agent.ai, original_ai)
        self.assertIs(agent.session, original_session)
        self.assertEqual(agent.ai._working, ("groq", "new-model"))
        self.assertEqual(agent.ai.primary_model, "new-model")
        self.assertEqual(agent.ai.primary.model, "new-model")
        self.assertNotIn(("groq", "new-model"), agent.ai._exhausted)

    def test_unknown_model_is_rejected_before_activation(self):
        agent = FakeAgent()
        with patch("provider_manager.discover_models", return_value=(True, ["current-model"], "ok")), \
             patch("provider_manager._verify") as verify:
            with self.assertRaises(ValueError):
                switch_model(agent, "does-not-exist")
        verify.assert_not_called()
        self.assertEqual(agent.ai._working, ("groq", "old-model"))


if __name__ == "__main__":
    unittest.main()
