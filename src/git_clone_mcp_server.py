import sys
import subprocess
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from mcp.server import FastMCP

mcp = FastMCP("git-clone-mcp-server")
SCRIPT_DIR = Path(__file__).resolve().parent

@dataclass
class CloneStatus:
    status: str
    message: str
    path: Optional[str] = None

# Tool 1: Start the clone process
@mcp.tool()
async def start_clone(repository_url: str, target_path: str) -> CloneStatus:
    """
    Starts a git clone process in the background and immediately returns its PID.
    
    Args:
        repository_url: The URL of the repository to clone.
        target_path: The absolute path where the repository should be cloned.
    """
    try:
        p = Path(target_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and any(p.iterdir()):
            return CloneStatus(status="failed", message=f"Target directory '{target_path}' is not empty.")
    except Exception as e:
        return CloneStatus(status="failed", message=f"Error preparing target path: {e}")

    args = ["git", "clone", "--depth", "1", repository_url, target_path]
    
    try:
        with open(os.devnull, 'w') as f_null:
            proc = subprocess.Popen(args, stdout=f_null, stderr=f_null)
        
        pid_file = SCRIPT_DIR / f"clone_{proc.pid}.pid"
        pid_file.write_text(target_path)

        return CloneStatus(
            status="running",
            message=f"Clone process started with PID {proc.pid}. Use 'check_clone_status' to check progress.",
            path=str(proc.pid)
        )
    except FileNotFoundError:
        return CloneStatus(status="failed", message="Error: 'git' command not found.")
    except Exception as e:
        return CloneStatus(status="failed", message=f"Failed to start clone process: {e}")

# Tool 2: Check the clone process status
@mcp.tool()
async def check_clone_status(pid: str) -> CloneStatus:
    """
    Checks if a process with a given PID is still running.

    Args:
        pid: The Process ID (PID) of the background clone process, as returned by the 'start_clone' tool.
    """
    try:
        pid_int = int(pid)
        pid_file = SCRIPT_DIR / f"clone_{pid_int}.pid"

        if not pid_file.exists():
            return CloneStatus(status="failed", message=f"No active clone process found for PID {pid_int}. It may have failed or already completed.")

        is_running = False
        if sys.platform == "win32":
            cmd = f'tasklist /NH /FI "PID eq {pid_int}"'
            output = subprocess.check_output(cmd, shell=True, text=True)
            if str(pid_int) in output:
                is_running = True
        else:
            try:
                os.kill(pid_int, 0)
                is_running = True
            except OSError:
                is_running = False

        if is_running:
            return CloneStatus(status="running", message=f"Clone process {pid_int} is still running.")
        else:
            target_path_str = pid_file.read_text()
            target_path = Path(target_path_str)
            pid_file.unlink()

            if (target_path / ".git").exists():
                return CloneStatus(status="completed", message="Clone completed successfully.", path=target_path_str)
            else:
                return CloneStatus(status="failed", message=f"Clone process {pid_int} finished unexpectedly. The repository may be incomplete.")
    
    except Exception as e:
        return CloneStatus(status="failed", message=f"Error checking status: {e}")

def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()