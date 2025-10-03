import sys
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from mcp.server import FastMCP

# 1. Path and Server Configuration
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_FILE = SCRIPT_DIR / "latest_scan_result.json"
DASHBOARD_URL = "http://localhost:8501"

mcp = FastMCP("dashboard-generator-mcp-server")

# 2. Data Structures and Helper Functions
@dataclass
class DashboardResult:
    ok: bool
    message: str
    dashboard_url: str = DASHBOARD_URL

def as_float(v) -> Optional[float]:
    try:
        return float(v)
    except Exception:
        return None

def load_epss_map(path: Optional[Path]) -> Dict[str, Tuple[Optional[float], Optional[float], Optional[str]]]:
    """
    Parse EPSS MCP output (fixed list shape) into:
        { "CVE-...": (epss, percentile, date) }

    Expected shape:
    [
      {"match_index": 0, "severity": "high|critical", "cve": "CVE-2024-1234",
       "epss": 0.43666, "percentile": 0.97446, "date": "2025-09-25"},
      ...
    ]
    """
    mapping: Dict[str, Tuple[Optional[float], Optional[float], Optional[str]]] = {}
    if not path or not path.exists():
        return mapping

    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        return mapping

    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = row.get("cve")
        if not (isinstance(cve, str) and cve.startswith("CVE-")):
            continue

        e = as_float(row.get("epss"))
        p = as_float(row.get("percentile"))
        d = row.get("date") if isinstance(row.get("date"), str) else None

        # If duplicate CVEs exist, pick the one with the higher EPSS
        if cve in mapping:
            prev_e, _, _ = mapping[cve]
            if e is not None and (prev_e is None or e > prev_e):
                mapping[cve] = (e, p, d)
        else:
            mapping[cve] = (e, p, d)

    return mapping

def preprocess_grype_json(
    input_path: Path,
    epss_map: Dict[str, Tuple[Optional[float], Optional[float], Optional[str]]] | None = None
) -> List[dict]:
    """Reads the Grype JSON and extracts only the fields needed for the dashboard."""
    processed_data = []
    data = json.loads(input_path.read_text(encoding='utf-8'))
    matches = data.get("matches", [])
    epss_map = epss_map or {}

    for match in matches:
        vulnerability = match.get('vulnerability', {})

        primary_id = vulnerability.get('id', 'N/A')
        cve_id = "N/A"
        if isinstance(primary_id, str) and primary_id.startswith("CVE-"):
            cve_id = primary_id
        else:
            related_vulns = match.get('relatedVulnerabilities', [])
            for rel_vuln in related_vulns:
                rid = rel_vuln.get('id', '')
                if isinstance(rid, str) and rid.startswith("CVE-"):
                    cve_id = rid
                    break

        cvss_score = "N/A"
        cvss_list = vulnerability.get('cvss', [])
        if cvss_list:
            metrics = cvss_list[0].get('metrics', {})
            if metrics and metrics.get('baseScore') is not None:
                cvss_score = round(metrics.get('baseScore', 0.0), 1)
        if cvss_score == "N/A":
            related_vulns = match.get('relatedVulnerabilities', [])
            for rel_vuln in related_vulns:
                rel_cvss_list = rel_vuln.get('cvss', [])
                if rel_cvss_list:
                    metrics = rel_cvss_list[0].get('metrics', {})
                    if metrics and metrics.get('baseScore') is not None:
                        cvss_score = round(metrics.get('baseScore', 0.0), 1)
                        break

        fixed_version = "N/A"
        fix_info = vulnerability.get('fix', {})
        if fix_info and fix_info.get('versions'):
            fixed_version = fix_info['versions'][0] if fix_info['versions'] else "N/A"

        epss_val: str | float = "N/A"
        percentile_val: str | float = "N/A"
        epss_date: str = "N/A"
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            tup = epss_map.get(cve_id)
            if tup:
                e, p, d = tup
                if e is not None:
                    epss_val = round(e, 5)
                if p is not None:
                    percentile_val = round(p, 5)
                if isinstance(d, str) and d:
                    epss_date = d

        processed_data.append({
            "Severity": vulnerability.get('severity', 'Unknown'),
            "CVSS Score": cvss_score,
            "CVE ID": cve_id,
            "Package": match.get('artifact', {}).get('name', 'N/A'),
            "Version": match.get('artifact', {}).get('version', 'N/A'),
            "Fixed Version": fixed_version,
            "DataSource": vulnerability.get('dataSource', 'N/A'),
            "EPSS": epss_val,
            "EPSS Percentile": percentile_val,
            "EPSS Date": epss_date,
        })
    return processed_data

# 3. MCP Tool Definition
@mcp.tool()
async def generate_dashboard(vulnerability_json_path: str, epss_json_path: str = "") -> DashboardResult:
    """
    Receives a JSON file path, preprocesses the data, and updates the file for the dashboard.

    Args:
        vulnerability_json_path: The file path to the raw Grype JSON report that needs to be processed.
        epss_json_path: (Optional) Path to EPSS MCP JSON output to enrich rows (epss/percentile/date).
    """
    try:
        epss_map = load_epss_map(Path(epss_json_path)) if epss_json_path else {}
        processed_data = preprocess_grype_json(Path(vulnerability_json_path), epss_map=epss_map)
        DATA_FILE.write_text(json.dumps(processed_data, indent=2), encoding='utf-8')
        return DashboardResult(
            ok=True,
            message="Dashboard data has been updated. Please check the running dashboard."
        )
    except Exception as e:
        return DashboardResult(ok=False, message=f"Failed to process data: {e}")

# 4. Server Execution Entry Point
def main():
    mcp.run(transport="stdio")

if __name__ == '__main__':
    main()