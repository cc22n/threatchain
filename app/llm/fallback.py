import logging
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage

logger = logging.getLogger(__name__)


class LLMWithFallback:
    def __init__(self, primary: BaseChatModel, fallback: BaseChatModel):
        self.primary = primary
        self.fallback = fallback
        self._active: BaseChatModel | None = None

    async def ainvoke(self, messages: list[BaseMessage], **kwargs):
        try:
            result = await self.primary.ainvoke(messages, **kwargs)
            self._active = self.primary
            return result
        except Exception as e:
            logger.warning("Primary LLM failed (%s), switching to fallback", e)
            result = await self.fallback.ainvoke(messages, **kwargs)
            self._active = self.fallback
            return result

    def invoke(self, messages: list[BaseMessage], **kwargs):
        try:
            result = self.primary.invoke(messages, **kwargs)
            self._active = self.primary
            return result
        except Exception as e:
            logger.warning("Primary LLM failed (%s), switching to fallback", e)
            result = self.fallback.invoke(messages, **kwargs)
            self._active = self.fallback
            return result

    @property
    def model_used(self) -> str:
        if self._active is None:
            return "none"
        return getattr(self._active, "model_name", str(self._active))

    @property
    def model_name(self) -> str:
        return self.model_used
