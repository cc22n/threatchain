import pytest
from datetime import datetime, timezone, timedelta
from agentgate.hitl.queue import ApprovalRequest
from agentgate.hitl.notifier import TelegramNotifier


def test_telegram_message_formatting():
    notifier = TelegramNotifier()
    req = ApprovalRequest(
        id="test-approval-12345",
        agent="recon_agent",
        tool="block_ip",
        arguments={"ip": "1.2.3.4", "duration": "24h"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    msg = notifier.format_message(req)
    assert "AGENTGATE HUMAN APPROVAL REQUIRED" in msg
    assert "recon_agent" in msg
    assert "block_ip" in msg
    assert "ip=1.2.3.4" in msg

    keyboard = notifier.get_inline_keyboard(req)
    assert len(keyboard) == 1
    assert keyboard[0][0]["text"] == "Approve"
    assert "ag_appr_" in keyboard[0][0]["callback_data"]
    assert keyboard[0][1]["text"] == "Reject"
