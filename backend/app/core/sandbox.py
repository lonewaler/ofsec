"""
OfSec V3 — Docker Sandbox (cross-platform, graceful fallback)
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

logger = structlog.get_logger()

# Detect Docker availability at import time
_DOCKER_AVAILABLE = False
_DOCKER_ERROR = ""

try:
    import docker as _docker_sdk

    # Test connection — works on both Linux (socket) and Windows (named pipe)
    _test_client = _docker_sdk.from_env()
    _test_client.ping()
    _DOCKER_AVAILABLE = True
    logger.info("sandbox.docker_available")
except Exception as e:
    _DOCKER_ERROR = str(e)
    logger.warning(
        "sandbox.docker_unavailable",
        error=_DOCKER_ERROR,
        hint="Install Docker Desktop and ensure it is running to enable sandbox execution",
    )


class SandboxExecutor:
    def _is_available(self) -> tuple[bool, str]:
        return _DOCKER_AVAILABLE, _DOCKER_ERROR

    async def execute(
        self,
        script: str,
        language: str = "python",
        timeout: int = 60,
        memory: str = "256m",
        env_vars: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        available, err = self._is_available()

        if not available:
            return {
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
                "timed_out": False,
                "available": False,
                "error": "DOCKER_UNAVAILABLE",
                "hint": (
                    "Docker is not running on this machine. "
                    "Install Docker Desktop from https://docker.com and start it, "
                    "then restart OfSec. "
                    f"Original error: {err}"
                ),
            }

        from app.config import get_settings

        settings = get_settings()

        if not getattr(settings, "DOCKER_SANDBOX_ENABLED", False):
            return {
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
                "available": True,
                "error": "SANDBOX_DISABLED",
                "hint": "Set DOCKER_SANDBOX_ENABLED=true in backend/.env to enable script execution",
            }

        import docker

        client = docker.from_env()

        image_map = {
            "python": "python:3.12-slim",
            "bash": "bash:5-alpine",
            "node": "node:20-slim",
        }
        cmd_map = {
            "python": ["python", "-c", script],
            "bash": ["bash", "-c", script],
            "node": ["node", "-e", script],
        }
        image = image_map.get(language, "python:3.12-slim")
        command = cmd_map.get(language, ["python", "-c", script])

        loop = asyncio.get_event_loop()
        container = None

        try:
            container = await loop.run_in_executor(
                None,
                lambda: client.containers.run(
                    image=image,
                    command=command,
                    environment=env_vars or {},
                    mem_limit=memory,
                    network_mode="none",
                    read_only=True,
                    remove=False,
                    detach=True,
                    stdout=True,
                    stderr=True,
                    security_opt=["no-new-privileges"],
                    cap_drop=["ALL"],
                ),
            )

            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, container.wait),
                    timeout=float(timeout),
                )
                stdout = container.logs(stdout=True, stderr=False).decode(errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode(errors="replace")
                exit_code = result.get("StatusCode", -1)
                timed_out = False
            except TimeoutError:
                with __import__("contextlib").suppress(Exception):
                    container.kill()
                stdout, stderr = "", f"Timed out after {timeout}s"
                exit_code, timed_out = -1, True

            logger.info("sandbox.complete", language=language, exit_code=exit_code, timed_out=timed_out)

            return {
                "stdout": stdout[:50_000],
                "stderr": stderr[:10_000],
                "exit_code": exit_code,
                "timed_out": timed_out,
                "available": True,
                "error": None,
            }

        except Exception as e:
            logger.error("sandbox.error", error=str(e), exc_info=True)
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "timed_out": False,
                "available": True,
                "error": str(e),
            }
        finally:
            if container:
                with __import__("contextlib").suppress(Exception):
                    container.remove(force=True)


sandbox = SandboxExecutor()
