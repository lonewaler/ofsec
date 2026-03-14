"""
OfSec V3 — CLI Command Runner
===============================
Execution engine for local Pentesting orchestration.
Streams live output from CLI tools.
"""

import asyncio
from typing import AsyncGenerator

import structlog

logger = structlog.get_logger(__name__)


class CLIOrchestrator:
    """Asynchronous runner for CLI tools."""

    @staticmethod
    async def stream_command(cmd: list[str]) -> AsyncGenerator[str, None]:
        """
        Executes a command asynchronously and yields its combined stdout and stderr line by line.
        """
        logger.info("streaming_command_start", command=" ".join(cmd))
        process = None
        try:
            # Map stderr to stdout to get one continuous stream
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            # process.stdout will not be None since we PIPEd it
            if process.stdout is not None:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    # Decode, strip trailing newline, and yield
                    yield line.decode("utf-8", errors="replace").rstrip("\n")

            await process.wait()
            logger.info("streaming_command_complete", command=" ".join(cmd), returncode=process.returncode)

        except Exception as e:
            logger.exception("streaming_command_error", command=" ".join(cmd), error=str(e))
            yield f"[Error] Failed to execute command: {str(e)}"
        finally:
            if process is not None and process.returncode is None:
                logger.warning("streaming_command_terminated", command=" ".join(cmd))
                try:
                    process.terminate()
                    await process.wait()
                except ProcessLookupError:
                    pass
