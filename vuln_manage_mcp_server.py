import asyncio
import json
import random
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import httpx
import aiohttp

from mcp.server import FastMCP

mcp = FastMCP("vuln-manage-mcp-server")

# --- Configuration ---
EPSS_API = "https://api.first.org/data/v1/epss"
HTTP_TIMEOUT_SECS = 60
MAX_RETRIES = 3
ALLOWED_SEVERITIES = {"high", "critical", "medium", "low", "negligible", "unknown"}

# --- Data Structures ---
@dataclass
class VulnerabilitySummary:
    """A data class to hold detailed information for a single CVE."""
    cve_id: str
    package_name: str = "N/A"
    description: str = "No description available."
    cvss_v3_score: Optional[float] = None
    severity: Optional[str] = None
    vector_string: Optional[str] = None
    references: List[str] = field(default_factory=list)

# --- Helper Functions ---
def is_cve(s: Optional[str]) -> bool:
    """Checks if a string is in CVE format."""
    return isinstance(s, str) and s.startswith("CVE-")

def num(v) -> Optional[float]:
    """Converts a value to float, returns None on failure."""
    try:
        return float(v)
    except (ValueError, TypeError):
        return None

def is_valid_cve_id(cve_id: str) -> bool:
    """Checks if the given string is a valid CVE ID format."""
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    return cve_pattern.match(cve_id) is not None

def parse_grype_match(match: dict, match_index: int) -> Optional[Dict]:
    """Parses a single 'match' object to extract key information."""
    vulnerability = match.get("vulnerability") or {}
    severity = str(vulnerability.get("severity") or "unknown").strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        return None

    risk = num(vulnerability.get("risk", 0.0))
    
    cve_id = None
    for rv in match.get("relatedVulnerabilities") or []:
        rid = rv.get("id")
        if is_cve(rid): cve_id = rid; break
    if not cve_id:
        vid = vulnerability.get("id")
        if is_cve(vid): cve_id = vid

    epss = pct = None
    for e in vulnerability.get("epss") or []:
        if e.get("cve") == cve_id:
            ee, pp = num(e.get("epss")), num(e.get("percentile"))
            if ee is not None and pp is not None:
                epss, pct = ee, pp
                break
    return {
        "match_index": match_index,
        "severity": severity,
        "cve": cve_id,
        "epss": epss,
        "percentile": pct,
        "risk": risk,
    }

async def fetch_nvd_data(cve_id: str) -> Optional[dict]:
    """Fetches CVE data from the NVD API."""
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(nvd_api_url, timeout=15.0)
            response.raise_for_status()
            data = response.json()
            if data.get("totalResults", 0) > 0:
                return data['vulnerabilities'][0]['cve']
    except Exception as e:
        print(f"API/Network Error for {cve_id}: {e}", file=sys.stderr)
    return None

def parse_nvd_response(cve_data: dict, package_name: str) -> VulnerabilitySummary:
    """Parses the NVD API response into a VulnerabilitySummary object."""
    cve_id = cve_data.get('id', 'Unknown')
    description = next((d['value'] for d in cve_data.get('descriptions', []) if d.get('lang') == 'en'), "No description.")
    metrics = cve_data.get('metrics', {})
    cvss_score, severity, vector = None, None, None
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        metric_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        cvss_score = metric_data.get('baseScore')
        severity = metric_data.get('baseSeverity')
        vector = metric_data.get('vectorString')
    references = [ref.get('url') for ref in cve_data.get('references', []) if ref.get('url')]
    return VulnerabilitySummary(cve_id=cve_id, package_name=package_name, description=description, cvss_v3_score=cvss_score, severity=severity, vector_string=vector, references=references[:3])

def format_summary_response(summary: VulnerabilitySummary) -> str:
    """Formats a VulnerabilitySummary object into a markdown string."""
    refs = "\n".join([f"  - {ref}" for ref in summary.references])
    return (f"### {summary.cve_id} (패키지: {summary.package_name})\n"
            f"**- Severity:** {summary.severity} ({summary.cvss_v3_score})\n"
            f"**- Description:** {summary.description}\n"
            f"**- References:**\n{refs}")

async def fetch_epss_batch(session: aiohttp.ClientSession, cves: List[str]) -> Dict:
    """
    Fetches EPSS scores for a list of CVEs from the FIRST.org API.
    Retries up to MAX_RETRIES on network errors.
    """
    if not cves: return {}
    params = {"cve": ",".join(cves)}
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(EPSS_API, params=params, timeout=HTTP_TIMEOUT_SECS) as resp:
                if resp.status == 200:
                    payload = await resp.json()
                    return {item['cve']: item for item in payload.get("data", [])}
                return {}
        except Exception:
            if attempt == MAX_RETRIES - 1: return {}
            await asyncio.sleep(1 + attempt)
    return {}

async def fill_missing_epss_via_api(parsed_vulns: List[Dict]):
    """
Iterates through the list of parsed vulnerabilities to find CVEs with no EPSS score,
and calls the fetch_epss_batch function to fill in the missing data.
"""
    cves_to_fetch = list(set(item['cve'] for item in parsed_vulns if item.get('cve') and item.get('epss') is None))
    if not cves_to_fetch: return
    async with aiohttp.ClientSession() as session:
        epss_data = await fetch_epss_batch(session, cves_to_fetch)
    for item in parsed_vulns:
        if item['cve'] in epss_data:
            data = epss_data[item['cve']]
            item['epss'] = num(data.get('epss'))
            item['percentile'] = num(data.get('percentile'))

# --- MCP Tools ---
@mcp.tool()
async def get_vulnerability_details(vulnerability_id: str) -> str:
    """
    Fetches and summarizes details for a single vulnerability ID from the NVD.

    Args:
        vulnerability_id: The CVE identifier to look up (e.g., "CVE-2021-44906").
    """
    if not is_valid_cve_id(vulnerability_id):
        return f"Error: '{vulnerability_id}' is not a valid CVE ID format."

    cve_data = await fetch_nvd_data(vulnerability_id)
    if not cve_data:
        return f"Error: Could not retrieve details for {vulnerability_id}."

    summary = parse_nvd_response(cve_data, package_name="Unknown")
    return format_summary_response(summary)

@mcp.tool()
async def get_patch_priority_list(
    vulnerabilities_json_path: str, 
    output_json_path: str, 
    fetch_missing_epss: bool = True
) -> str:
    """
    Parses a Grype JSON report,
    sorts all vulnerabilities by risk score, saves the full sorted list 
    to a new JSON file, and returns a confirmation message.

    Args:
        vulnerabilities_json_path: The path to the raw Grype JSON scan result file.
        output_json_path: The path where the prioritized and sorted JSON list will be saved.
        fetch_missing_epss: If True, fetches missing EPSS scores from an external API for any CVEs that lack them.
    
    Returns:
        A string message indicating the success or failure of the operation.
    """
    p = Path(vulnerabilities_json_path)
    if not p.exists(): return f"Error: Input file not found: {p.as_posix()}"
    try:
        matches = json.loads(p.read_text(encoding="utf-8")).get("matches", [])
        if not matches:
            Path(output_json_path).write_text("[]", encoding="utf-8")
            return f"No vulnerabilities found. Empty list saved to: {output_json_path}"
        
        parsed_vulns = [row for i, m in enumerate(matches) if (row := parse_grype_match(m, i))]
        
        if fetch_missing_epss:
            await fill_missing_epss_via_api(parsed_vulns)
        
        parsed_vulns.sort(key=lambda x: x.get("risk", 0.0), reverse=True)
        
        output_path = Path(output_json_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(parsed_vulns, indent=2), encoding="utf-8")

        return f"Successfully generated full patch priority list. Saved to: {output_json_path}"
    except Exception as e:
        return f"Error: Could not process vulnerability data: {e}"

# --- Server Execution ---
def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()