"""Sample x19 plugin — sends notifications on findings."""
import subprocess
import json


def on_start(agent):
    print("[Plugin] Sample plugin loaded — will notify on critical findings")


def on_finding(agent, finding):
    if finding.severity in ("critical", "high"):
        msg = f"x19: {finding.severity.upper()} — {finding.title}"
        print(f"[Plugin:Notifier] {msg}")
        # Example: send to Telegram
        # bot_token = "YOUR_BOT_TOKEN"
        # chat_id = "YOUR_CHAT_ID"
        # subprocess.run([
        #     "curl", "-s",
        #     f"https://api.telegram.org/bot{bot_token}/sendMessage",
        #     "--data-urlencode", f"chat_id={chat_id}",
        #     "--data-urlencode", f"text={msg}"
        # ], timeout=10)


def on_context_build(agent, ctx):
    """Add plugin info to AI context."""
    return "\n[Plugin: Sample notifier active — findings will be notified]\n"
