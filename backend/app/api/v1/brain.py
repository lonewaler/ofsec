"""
OfSec V3 — Agentic Brain API Router
====================================
Endpoints for AI action planning and orchestration.
"""

from fastapi import APIRouter, status
from pydantic import BaseModel
import structlog

from app.api.deps import DbSession
from app.services.ai.orchestrator import AgenticBrain

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["AI Brain"])


class PlanRequest(BaseModel):
    goal: str


@router.post("/plan", status_code=status.HTTP_200_OK)
async def plan_action_endpoint(req: PlanRequest, db: DbSession):
    """
    Takes a user goal, queries Qdrant memory and the LLM, 
    and returns a CLI payload to execute.
    """
    brain = AgenticBrain()
    try:
        payload = await brain.plan_action(req.goal, db)
        return {
            "status": "success",
            "plan": payload
        }
    except Exception as e:
        logger.error("brain.plan_error", error=str(e), goal=req.goal)
        return {
            "status": "error",
            "message": str(e)
        }
