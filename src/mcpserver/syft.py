"""
Syft MCP Server for Code Repositories
"""

import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .core import mcp

# 1. Server Initialization and Data Structure Definition
@dataclass
class CommandResult:
    """A structured class to hold the result of a command execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""

# 2. Core Logic: Execution, Validation, and Response Formatting
async def run_syft_command(args: List[str], timeout: int) -> CommandResult:
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
        return CommandResult(success=False, stderr="Syft is not installed or not in PATH.")
    except Exception as e:
        return CommandResult(success=False, stderr=f"An unexpected error occurred: {e}")

def write_output_file(path_str: str, content: str) -> bool:
    """Safely writes content to a file."""
    try:
        path = Path(path_str)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return True
    except IOError as e:
        print(f"Error writing to file {path_str}: {e}", file=sys.stderr)
        return False

def format_response(result: CommandResult, success_msg: str, error_msg: str) -> str:
    """Formats the final string response based on the command result."""
    if result.success:
        return success_msg
    return f"{error_msg}\n{result.stderr}"

# 3. MCP Tool Definition
@mcp.tool()
async def check_status() -> str:
    """Checks if Syft is installed correctly and returns its version."""
    result = await run_syft_command(args=["syft", "--version"], timeout=10)
    return format_response(
        result,
        success_msg=f"Syft is installed and working correctly:\n{result.stdout.strip()}",
        error_msg="Syft health check failed:"
    )

@mcp.tool()
async def generate_sbom_from_repository(
    repository_path: str, output_file: str, format: str = "cyclonedx-json", exclude: str = None
) -> str:
    """
    Generates a full SBOM from a local code repository (directory).

    Args:
        repository_path: The local filesystem path to the code repository.
        output_file: The path where the generated SBOM file will be saved.
        format: The desired SBOM format (e.g., cyclonedx-json, spdx-json).
        exclude: Comma-separated glob patterns to exclude from the scan (e.g., "**/node_modules,**/*.log").
    """
    if not Path(repository_path).is_dir():
        return f"Error: The path '{repository_path}' is not a valid directory."

    args = ["syft", "scan", f"dir:{repository_path}", "-o", format, "-q"]
    if exclude:
        for pattern in exclude.split(","):
            args.extend(["--exclude", pattern.strip()])
    
    result = await run_syft_command(args, timeout=600)

    if result.success:
        write_output_file(output_file, result.stdout)

    return format_response(
        result,
        success_msg=f"SBOM generated successfully. Saved to: {output_file}",
        error_msg=f"SBOM generation failed for '{repository_path}':"
    )

@mcp.tool()
async def convert_sbom(input_file: str, output_file: str, output_format: str) -> str:
    """
    Converts an existing SBOM file from one format to another.

    Args:
        input_file: Path to the source SBOM file to convert.
        output_file: Path where the converted SBOM will be saved.
        output_format: The target format to convert to (e.g., spdx-json, cyclonedx-xml).
    """
    if not Path(input_file).is_file():
        return f"Error: The input file '{input_file}' is not a valid file."

    args = ["syft", "convert", input_file, "-o", output_format, "-q"]
    result = await run_syft_command(args, timeout=60)
    
    if result.success:
        write_output_file(output_file, result.stdout)

    return format_response(
        result,
        success_msg=f"SBOM converted successfully. Saved to: {output_file}",
        error_msg="SBOM conversion failed:"
    )