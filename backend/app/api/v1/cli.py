"""
OfSec V3 — CLI WebSocket API
==============================
WebSocket endpoints for streaming CLI outputs directly to clients.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from app.services.ops.command_runner import CLIOrchestrator
from app.services.ops.installer import AutoInstaller
from pydantic import BaseModel
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["CLI"])

class CommandPayload(BaseModel):
    tool: str
    args: list[str] = []

@router.websocket("/ws/exec")
async def websocket_exec_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint that receives a command payload, verifies authorization,
    and streams the live stdout/stderr of the tool back to the client.
    """
    await websocket.accept()
    logger.info("websocket_exec_connected", client=websocket.client)

    try:
        while True:
            # Wait for JSON payload from the client
            payload_data = await websocket.receive_json()
            
            try:
                payload = CommandPayload(**payload_data)
            except ValidationError as e:
                await websocket.send_json({"type": "error", "data": "Invalid payload format.", "details": e.errors()})
                continue
            
            tool = payload.tool
            args = payload.args

            # Security Check: Prevent arbitrary RCE by checking the tool exists in our known registry
            if tool not in AutoInstaller.TOOL_REGISTRY:
                logger.warning("websocket_exec_unauthorized_tool", tool=tool, client=websocket.client)
                await websocket.send_json({
                    "type": "error", 
                    "data": f"Unauthorized tool: '{tool}'. Only tools in TOOL_REGISTRY are permitted."
                })
                continue

            # Command composition
            cmd = [tool, *args]

            try:
                # Orchestrate execution and stream the results line-by-line
                orchestrator = CLIOrchestrator()
                async for line in orchestrator.stream_command(cmd):
                    await websocket.send_json({"type": "stdout", "data": line})
                
                await websocket.send_json({"type": "status", "data": "Command execution completed."})

            except Exception as e:
                logger.error("websocket_exec_error", error=str(e), tool=tool)
                await websocket.send_json({"type": "error", "data": str(e)})

    except WebSocketDisconnect:
        logger.info("websocket_exec_disconnected", client=websocket.client)
    except Exception as e:
        logger.exception("websocket_exec_unexpected_error", error=str(e), client=websocket.client)
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except Exception:
            pass
