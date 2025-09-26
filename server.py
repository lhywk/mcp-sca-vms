"""
Grype MCP Server for SBOM Scanning with Vulnerability Prioritization
"""

import asyncio
import os
import sys
import subprocess
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from mcp.server import FastMCP

# 1. Server Initialization and Data Structure Definition
mcp = FastMCP("grype-sbom-scanner-mcp-server")

@dataclass
class CommandResult:
    """A structured class to hold the result of a command execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""

@dataclass
class ScanSbomOut:
    """Result object for SBOM scans used by MCP tools."""
    ok: bool
    output: Optional[str] = None
    notes: List[str] = field(default_factory=list)

# 2. Core Logic: Execution, Validation, and Response Formatting
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

def summarize_vulnerabilities(json_string: str) -> List[str]:
    """
    Parses Grype's JSON output. Creates a summary count of ALL vulnerabilities,
    but provides a detailed list of ONLY Critical and High vulnerabilities,
    grouped by package.
    """
    try:
        data = json.loads(json_string)
        matches = data.get("matches", [])
        
        if not matches:
            return ["No vulnerabilities found."]
            
        # 1. First, get the counts for ALL severities for the summary line.
        severities = [match['vulnerability']['severity'] for match in matches]
        counts = Counter(severities)
        
        all_severities_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
        summary_parts = [f"{sev}: {counts[sev]}" for sev in all_severities_order if sev in counts]
        
        # This summary line is now complete and correct.
        summary_lines = [f"Vulnerability Summary: {', '.join(summary_parts)}"]

        # 2. Now, create the detailed list for ONLY Critical and High vulnerabilities.
        vulns_by_package = {}
        
        for match in matches:
            sev = match['vulnerability']['severity']
            
            # Filter for only Critical and High for the detailed list
            if sev not in ["Critical", "High"]:
                continue

            pkg_name = match['artifact']['name']
            vid = match['vulnerability']['id']
            description = match['vulnerability'].get('description', 'No description available.')
            vuln_detail = f"  - {vid} ({sev}): {description}"

            if pkg_name not in vulns_by_package:
                vulns_by_package[pkg_name] = []
            vulns_by_package[pkg_name].append(vuln_detail)

        # 3. Build the final detailed list section.
        if vulns_by_package:
            summary_lines.append("") # Add a blank line for spacing
            summary_lines.append("Key Vulnerabilities by Package (Critical & High):")
            
            package_index = 1
            for pkg_name, vulns in vulns_by_package.items():
                summary_lines.append(f"{package_index}. {pkg_name} - {len(vulns)}vulnerabilities found")
                summary_lines.extend(vulns)
                package_index += 1
            
        return summary_lines

    except (json.JSONDecodeError, KeyError) as e:
        return [f"Could not parse or summarize vulnerability data: {e}"]

# 3. MCP Tool Definition
@mcp.tool()
async def check_status() -> str:
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
    output_file: Optional[str] = None, 
    timeout: int = 300                 
) -> ScanSbomOut:
    """
    Scans an SBOM, creates a prioritized summary, and optionally saves the full JSON report.

    Args:
        sbom_path: Path to the SBOM file to scan.
        output_file: (Optional) Path to save the full JSON scan results.
        timeout: Command timeout in seconds (default: 300s).

    Returns:
        ScanSbomOut where 'notes' contains a summary of ALL vulnerability counts 
        but a detailed list of ONLY Critical and High vulnerabilities. 
        The full JSON is in 'output'.
    """
    if not Path(sbom_path).exists():
        return ScanSbomOut(ok=False, notes=[f"SBOM file not found: {sbom_path}"])

    args = ["grype", f"sbom:{sbom_path}", "-o", "json"]

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            args,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        
        notes = []
        summary = summarize_vulnerabilities(result.stdout)
        notes.extend(summary)

        if output_file:
            if write_output_file(output_file, result.stdout):
                notes.append(f"Full JSON report saved to {output_file}")
            else:
                notes.append(f"Warning: Scan succeeded but failed to write to {output_file}")
        
        return ScanSbomOut(ok=True, output=result.stdout, notes=notes)

    except subprocess.TimeoutExpired:
        return ScanSbomOut(ok=False, notes=[f"error: Scan timed out after {timeout} seconds"])
    except subprocess.CalledProcessError as cpe:
        stderr_msg = cpe.stderr or str(cpe)
        return ScanSbomOut(ok=False, output=cpe.stdout or None, notes=[f"error: {stderr_msg}"])
    except Exception as e:
        return ScanSbomOut(ok=False, notes=[f"error: {e}"])

# 5. Server Execution Entry Point
def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()