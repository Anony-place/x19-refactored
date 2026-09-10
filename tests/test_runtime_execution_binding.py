import sys
import types
import unittest
from unittest.mock import patch

from execution import CommandGateway, PolicyEngine
import runtime_bootstrap


class FakeAgent:
    def __init__(self, target=""):
        self.target = target
        self.command_gateway = types.SimpleNamespace(policy_engine=None)
        self.exec = types.SimpleNamespace(gateway=self.command_gateway)


class RuntimeExecutionBindingTests(unittest.TestCase):
    def test_install_binds_policy_to_constructed_agent_target(self):
        original = FakeAgent.__init__
        fake_module = types.SimpleNamespace(X19=FakeAgent)

        with patch.dict(sys.modules, {"agent": fake_module}):
            runtime_bootstrap.install_agent_execution_policy()
            try:
                agent = FakeAgent("target.local")
                self.assertIsInstance(agent.command_gateway.policy_engine, PolicyEngine)
                self.assertEqual(agent.command_gateway.policy_engine.policy.allowed_targets, {"target.local"})
                self.assertIs(agent.exec.gateway, agent.command_gateway)
            finally:
                # The test mutates the fake class only; restore its constructor
                # so repeated test discovery in the same interpreter is stable.
                FakeAgent.__init__ = original
                if hasattr(FakeAgent, "_x19_gateway_policy_installed"):
                    delattr(FakeAgent, "_x19_gateway_policy_installed")


if __name__ == "__main__":
    unittest.main()
