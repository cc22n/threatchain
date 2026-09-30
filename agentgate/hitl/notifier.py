import logging
import re
from typing import Any
import httpx
from agentgate.hitl.queue import ApprovalRequest

logger = logging.getLogger(__name__)


def _redact_bot_token(text: str) -> str:
    return re.sub(r"bot[0-9]+:[A-Za-z0-9_-]+", "bot<REDACTED>", text)


class TelegramNotifier:
    def format_message(self, request: ApprovalRequest) -> str:
        args_summary = ", ".join(f"{k}={v}" for k, v in request.arguments.items()) or "none"
        lines = [
            "AGENTGATE HUMAN APPROVAL REQUIRED",
            "",
            f"Agent: {request.agent}",
            f"Tool: {request.tool}",
            f"Arguments: {args_summary}",
            f"Approval ID: {request.id}",
            f"Expires at: {request.expires_at.strftime('%H:%M:%S UTC')}",
        ]
        return "\n".join(lines)

    def get_inline_keyboard(self, request: ApprovalRequest) -> list[list[dict[str, str]]]:
        return [
            [
                {"text": "Approve", "callback_data": f"ag_appr_{request.id}"},
                {"text": "Reject", "callback_data": f"ag_rej_{request.id}"},
            ]
        ]


async def send_approval_request(
    request: ApprovalRequest,
    token: str | None = None,
    allowlist_ids: list[int] | None = None,
) -> bool:
    """Send approval notification with inline action buttons to Telegram allowlist chats."""
    if token is None or allowlist_ids is None:
        try:
            from app.config import settings
            token = token or settings.TELEGRAM_BOT_TOKEN
            if allowlist_ids is None:
                allowlist_ids = settings.telegram_allowlist_ids
        except Exception as e:
            logger.warning("Could not read Telegram settings: %s", e)

    if not token or not allowlist_ids:
        logger.warning("Telegram notification skipped: bot token or allowlist is empty.")
        return False

    notifier = TelegramNotifier()
    message_text = notifier.format_message(request)
    keyboard = notifier.get_inline_keyboard(request)

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    sent_any = False

    async with httpx.AsyncClient(timeout=10.0) as client:
        for chat_id in allowlist_ids:
            payload = {
                "chat_id": chat_id,
                "text": message_text,
                "reply_markup": {"inline_keyboard": keyboard},
            }
            try:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    sent_any = True
                else:
                    logger.warning(
                        "Telegram sendMessage failed for chat %s with HTTP %s: %s",
                        chat_id,
                        resp.status_code,
                        _redact_bot_token(resp.text),
                    )
            except Exception as exc:
                logger.warning(
                    "Telegram notification network error for chat %s: %s",
                    chat_id,
                    _redact_bot_token(str(exc)),
                )

    return sent_any
