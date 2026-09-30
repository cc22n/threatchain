import asyncio
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

    async def _run_tools_parallel(
        self,
        ioc_value: str,
        tools_to_run: list[tuple],
        context: dict | None = None,
    ) -> tuple[dict, dict, int]:
        """
        Runs tools concurrently using asyncio.gather.
        tools_to_run: list of tuples (name, tool) or (name, tool, kwargs_dict)
        Returns: (raw_results, errors, api_calls_made)
        """
        agent_identifier = f"{self.agent_name}_agent" if not self.agent_name.endswith("_agent") else self.agent_name

        async def _invoke(name, tool, kwargs):
            try:
                call_kwargs = kwargs.copy()
                call_kwargs.setdefault("agent_name", agent_identifier)
                if context is not None:
                    call_kwargs.setdefault("context", context)
                res = await tool._arun(ioc_value, **call_kwargs)
                return name, res, None
            except Exception as e:
                logger.warning("Tool %s failed: %s", name, e)
                return name, None, str(e)

        tasks = []
        for item in tools_to_run:
            name = item[0]
            tool = item[1]
            kwargs = item[2] if len(item) > 2 else {}
            tasks.append(_invoke(name, tool, kwargs))

        raw_results = {}
        errors = {}
        api_calls = 0

        completed = await asyncio.gather(*tasks, return_exceptions=True)
        for item in completed:
            if isinstance(item, Exception):
                logger.error("Unexpected error in parallel tool execution: %s", item)
                continue
            name, res, err = item
            if err is not None:
                errors[name] = err
            else:
                raw_results[name] = res
                api_calls += 1

        return raw_results, errors, api_calls

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

