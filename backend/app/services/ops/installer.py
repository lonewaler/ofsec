"""
OfSec V3 — OS Auto-Discovery & Installer Engine
=================================================
Engine for discovering the OS and safely installing missing required tools.
"""

from __future__ import annotations

import asyncio
import platform
import shutil

import structlog

logger = structlog.get_logger(__name__)


class AutoInstaller:
    """Handles automatic tool discovery and installation."""

    # OS-specific installation commands for essential tools
    TOOL_REGISTRY = {
        "nmap": {
            "linux": ["apt-get", "install", "-y", "nmap"],
            "darwin": ["brew", "install", "nmap"],
            "windows": ["choco", "install", "nmap", "-y"],
        },
        "amass": {
            "linux": ["apt-get", "install", "-y", "amass"],
            "darwin": ["brew", "install", "amass"],
            "windows": ["choco", "install", "amass", "-y"],
        },
        "sqlmap": {
            "linux": ["apt-get", "install", "-y", "sqlmap"],
            "darwin": ["brew", "install", "sqlmap"],
            "windows": ["choco", "install", "sqlmap", "-y"],
        },
        "theharvester": {
            "linux": ["apt-get", "install", "-y", "theharvester"],
            "darwin": ["brew", "install", "theharvester"],
            "windows": ["choco", "install", "theharvester", "-y"],
        },
    }

    @staticmethod
    def get_os() -> str:
        """Return the current operating system normalized to 'linux', 'darwin', or 'windows'."""
        system = platform.system().lower()
        if system == "linux":
            return "linux"
        elif system == "darwin":
            return "darwin"
        elif system == "windows":
            return "windows"
        return system

    @staticmethod
    def is_tool_installed(tool_name: str) -> bool:
        """Check if a tool's binary is available in the system PATH."""
        return shutil.which(tool_name) is not None

    @classmethod
    async def install_tool(cls, tool_name: str) -> bool:
        """
        Asynchronously install a tool based on the current OS.
        Returns True if successful or already installed, False otherwise.
        """
        if cls.is_tool_installed(tool_name):
            logger.info("tool_already_installed", tool=tool_name)
            return True

        os_name = cls.get_os()
        
        if tool_name not in cls.TOOL_REGISTRY:
            raise ValueError(f"Tool '{tool_name}' not found in TOOL_REGISTRY.")
        
        if os_name not in cls.TOOL_REGISTRY[tool_name]:
            raise ValueError(f"OS '{os_name}' not supported for installing '{tool_name}'.")

        cmd = cls.TOOL_REGISTRY[tool_name][os_name]
        logger.info("installing_tool", tool=tool_name, os=os_name, command=" ".join(cmd))

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("tool_installation_success", tool=tool_name)
                return True
            else:
                logger.error(
                    "tool_installation_failed",
                    tool=tool_name,
                    return_code=process.returncode,
                    stderr=stderr.decode("utf-8", errors="replace").strip()
                )
                return False

        except Exception as e:
            logger.exception("tool_installation_error", tool=tool_name, error=str(e))
            return False
