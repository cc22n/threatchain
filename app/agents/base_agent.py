import uuid
import logging
from abc import abstractmethod
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent_result import AgentResult

logger = logging.getLogger(__name__)


class BaseAgent:
    agent_name: str = "base"

    def __init__(self, db: AsyncSession):
        self.db = db

    @abstractmethod
    async def run(self, ioc_value: str, ioc_type: str, investigation_id: uuid.UUID) -> dict: ...

    async def _persist_result(
        self,
        investigation_id: uuid.UUID,
        findings: dict,
        raw_results: dict,
        tokens_used: int = 0,
        api_calls_made: int = 0,
        execution_time_ms: int = 0,
        llm_model_used: str = "",
        errors: dict | None = None,
        status: str = "success",
    ) -> AgentResult:
        result = AgentResult(
            investigation_id=investigation_id,
            agent_name=self.agent_name,
            status=status,
            raw_results=raw_results,
            findings=findings,
            llm_model_used=llm_model_used,
            tokens_used=tokens_used,
            api_calls_made=api_calls_made,
            execution_time_ms=execution_time_ms,
            errors=errors,
        )
        self.db.add(result)
        await self.db.commit()
        await self.db.refresh(result)
        return result
