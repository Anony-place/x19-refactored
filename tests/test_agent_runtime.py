import time

from agent_runtime import AgentRuntime, AgentState


class DummyAgent:
    def __init__(self):
        self.running = False
        self.stop = False
        self.calls = 0

    def autonomous_loop(self, target):
        self.running = True
        self.calls += 1
        time.sleep(0.02)
        self.running = False


def test_runtime_runs_worker_in_background():
    agent = DummyAgent()
    runtime = AgentRuntime(agent)

    assert runtime.start("fixture.local", worker=lambda: agent.autonomous_loop("fixture.local"))
    assert runtime.wait(2.0)
    assert agent.calls == 1
    assert runtime.snapshot().state == AgentState.COMPLETED
    assert any(e["state"] == "THINKING" for e in runtime.events())


def test_runtime_refuses_duplicate_start():
    agent = DummyAgent()
    runtime = AgentRuntime(agent)

    assert runtime.start("fixture.local", worker=lambda: time.sleep(0.2))
    assert not runtime.start("fixture.local", worker=lambda: None)
    runtime.stop()
    runtime.wait(2.0)
    assert runtime.snapshot().state == AgentState.STOPPED
