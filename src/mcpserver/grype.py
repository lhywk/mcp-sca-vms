"""
Grype MCP Server for SBOM Scanning.
"""

import asyncio
import os
import sys
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .core import mcp

# 1. Server Initialization and Data Structure Definition

@dataclass
class ScanResult:
    """A structured result for the SBOM scan, returning the report file path."""
    ok: bool
    message: str = ""
    report_file_path: Optional[str] = None

@dataclass
class CommandResult:
    """A structured class to hold the result of a command execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""

# 2. Core Logic & Helper Functions
async def run_grype_command(args: List[str], timeout: int) -> CommandResult:
    """Runs a shell command and returns a CommandResult object."""
    try:
        process = await asyncio.create_subprocess_shell(
            ' '.join(args),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return CommandResult(success=False, stderr=f"Operation timed out after {timeout}s.")

        return CommandResult(
            success=process.returncode == 0,
            stdout=stdout_b.decode("utf-8"),
            stderr=stderr_b.decode("utf-8")
        )
    except FileNotFoundError:
        return CommandResult(success=False, stderr="Grype is not installed or not in PATH.")
    except Exception as e:
        return CommandResult(success=False, stderr=f"An unexpected error occurred: {e}")

def format_response(result: CommandResult, success_msg: str, error_msg: str) -> str:
    """Formats the final string response based on the command result."""
    if result.success:
        return success_msg
    return f"{error_msg}\n{result.stderr}"

# 3. MCP Tool Definitions
@mcp.tool()
async def check_grype_status() -> str:
    """Checks if Grype is installed correctly and returns its version."""
    result = await run_grype_command(args=["grype", "--version"], timeout=10)
    return format_response(result, success_msg=f"Grype is installed and working correctly:\n{result.stdout.strip()}", error_msg="Grype health check failed:")

@mcp.tool()
async def update_database() -> str:
    """Updates Grype's vulnerability database to the latest version."""
    result = await run_grype_command(args=["grype", "db", "update"], timeout=300)
    return format_response(result, success_msg=f"Grype database updated successfully.\n{result.stdout.strip()}", error_msg="Database update failed:")

@mcp.tool()
async def check_database_status() -> str:
    """Checks the status of Grype's vulnerability database."""
    result = await run_grype_command(args=["grype", "db", "status"], timeout=30)
    return format_response(result, success_msg=f"Grype database status:\n{result.stdout.strip()}", error_msg="Database status check failed:")

# 4. SBOM Scan
@mcp.tool()
async def scan_sbom(
    sbom_path: str,
    output_file: str, 
    timeout: int = 300
) -> ScanResult:
    """
    Scans an SBOM, saves the full JSON report, and returns the path to the report.

    Args:
        sbom_path: Path to the SBOM file to scan.
        output_file: Path to save the full JSON scan results.
        timeout: Command timeout in seconds (default: 300s).

    Returns:
        A ScanResult object with the path to the generated JSON report.
    """
    if not Path(sbom_path).is_file():
        return ScanResult(ok=False, message=f"Error: SBOM file '{sbom_path}' not found.")

    args = ["grype", f"sbom:{sbom_path}", "-o", "json", "--file", output_file]

    try:
        await asyncio.to_thread(
            subprocess.run,
            args,
            text=True,
            check=True,
            timeout=timeout
        )
        
        return ScanResult(
            ok=True, 
            message=f"Scan successful. Report saved to {output_file}",
            report_file_path=str(Path(output_file).resolve())
        )

    except subprocess.TimeoutExpired:
        return ScanResult(ok=False, message=f"error: Scan timed out after {timeout} seconds")
    except subprocess.CalledProcessError as cpe:
        return ScanResult(ok=False, message=f"error: {cpe.stderr or str(cpe)}")
    except Exception as e:
        return ScanResult(ok=False, message=f"error: {e}")
