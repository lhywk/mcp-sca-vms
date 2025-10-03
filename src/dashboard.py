import streamlit as st
import pandas as pd
import json
from pathlib import Path
import re
import requests
from dataclasses import dataclass, field
from typing import List, Optional

DATA_FILE = Path("latest_scan_result.json")
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

st.set_page_config(
    page_title="Vulnerability Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Align headers and cells to the left */
    div[data-testid="stDataFrameColumnHeader"], div[data-testid="stDataFrameTableCell"] {
        text-align: left !important;
    }
</style>
""", unsafe_allow_html=True)

@dataclass
class VulnerabilitySummary:
    """A structured class to hold summarized vulnerability details."""
    cve_id: str
    package_name: str = "N/A"
    description: str = "No description available."
    cvss_v3_score: Optional[float] = None
    severity: Optional[str] = None
    vector_string: Optional[str] = None
    references: List[str] = field(default_factory=list)

def _is_valid_cve_id(cve_id: str) -> bool:
    """Validates if the string follows the common CVE format."""
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    return cve_pattern.match(cve_id) is not None

def _parse_nvd_response(cve_data: dict, package_name: str) -> VulnerabilitySummary:
    """Parses the NVD API response into a simple summary object."""
    cve_id = cve_data.get('id', 'Unknown')
    description = next((d['value'] for d in cve_data.get('descriptions', []) if d.get('lang') == 'en'), "No description.")
    
    metrics = cve_data.get('metrics', {})
    cvss_score, severity, vector = None, None, None
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        metric_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        cvss_score = metric_data.get('baseScore')
        severity = metric_data.get('baseSeverity')
        vector = metric_data.get('vectorString')
    
    all_references = [ref.get('url') for ref in cve_data.get('references', []) if ref.get('url')]
    unique_references = list(dict.fromkeys(all_references))

    return VulnerabilitySummary(
        cve_id=cve_id, package_name=package_name, description=description,
        cvss_v3_score=cvss_score, severity=severity, vector_string=vector,
        references=unique_references[:3]
    )

@st.cache_data(ttl=3600)
def fetch_nvd_data_sync(cve_id: str) -> Optional[dict]:
    """Fetches vulnerability data from the NVD API 2.0 (Synchronous)."""
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(nvd_api_url, timeout=15.0)
        response.raise_for_status()
        data = response.json()
        if data.get("totalResults", 0) > 0:
            return data['vulnerabilities'][0]['cve']
    except (requests.HTTPError, requests.RequestException) as e:
        st.error(f"API/Network Error for {cve_id}: {e}")
    return None

@st.dialog("CVE Details", width="large")
def show_cve_dialog(summary: VulnerabilitySummary):
    """
    Displays CVE details in a large, responsive dialog popup.
    """
    st.header(f"{summary.cve_id}")
    if summary.severity:
        style = severity_styler(summary.severity)
        st.markdown(f'Severity : <span style="{style}">{summary.severity.upper()}</span>', unsafe_allow_html=True)
        st.markdown("<hr style='margin-top: 0.5rem; margin-bottom: 0.5rem;'>", unsafe_allow_html=True)
    if summary.cvss_v3_score:
        st.metric("CVSS v3.1 Score", f"{summary.cvss_v3_score}")
        st.markdown("<hr style='margin-top: 0.5rem; margin-bottom: 0.5rem;'>", unsafe_allow_html=True)
    with st.container(border=True):
        st.subheader("Description")
        st.write(summary.description)
    with st.container(border=True):
        st.subheader("References")
        if summary.references:
            for ref in summary.references:
                st.markdown(
                    f'<div style="display: flex; align-items: flex-start; margin-bottom: 0.5rem;">'
                    f'<span style="margin-right: 0.5em;">•</span>'
                    f'<div style="word-break: break-all;"><a href="{ref}" target="_blank">{ref}</a></div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.caption("No references provided.")

def to_float(series, default=0.0):
    return pd.to_numeric(series, errors="coerce").fillna(default)

def severity_styler(val: str):
    val_capitalized = str(val).capitalize()
    cmap = {
        "Critical": "color: red; font-weight: bold;",
        "High": "color: orange; font-weight: bold;",
        "Medium": "color: #FFD700; text-shadow: -1px 0 black, 0 1px black, 1px 0 black, 0 -1px black; font-weight: bold;",
        "Low": "color: green; font-weight: bold;",
    }
    return cmap.get(val_capitalized, "color: white;")

def get_ordinal_suffix(n: int) -> str:
    if pd.isna(n): return ''
    n = int(n)
    if 10 <= n % 100 <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
    return f"{n}{suffix}"

def linkify(url):
    u = str(url or "")
    return u if u.startswith("http") else None

def build_priority_columns(df: pd.DataFrame) -> pd.DataFrame:
    for c in ["EPSS", "EPSS Percentile", "CVSS Score", "risk"]:
        if c not in df.columns:
            df[c] = None
    return df

def severity_kpis(frame: pd.DataFrame):
    if "Severity" in frame.columns:
        counts = frame["Severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Critical", int(counts.get("Critical", 0)))
        c2.metric("High", int(counts.get("High", 0)))
        c3.metric("Medium", int(counts.get("Medium", 0)))
        c4.metric("Low", int(counts.get("Low", 0)))

# Load
st.title("Vulnerability Scan Dashboard")
if not DATA_FILE.exists():
    st.warning("Waiting for scan data… Run the MCP generator first.")
    st.stop()
raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
if not raw:
    st.success("No vulnerabilities found.")
    st.stop()
df = pd.DataFrame(raw)

df = build_priority_columns(df)

rename_map = {
    'severity': 'Severity', 'cve': 'CVE ID', 'package_name': 'Package',
    'installed_version': 'Version', 'fix_version': 'Fixed Version',
    'cvss_score': 'CVSS Score', 'epss': 'EPSS', 'percentile': 'EPSS Percentile',
    'data_source': 'DataSource'
}
df.rename(columns=rename_map, inplace=True)

# Sidebar Filters
with st.sidebar:
    st.header("Filters")
    pkg_search = st.text_input("Package contains", "", help="Case-insensitive substring match.")
    cve_search = st.text_input("CVE contains", "", help="e.g. : CVE-2023- or a keyword.")
    only_fix = st.checkbox("Only show items with a fixed version", value=False)
    st.sidebar.divider()
    with st.sidebar.form("cve_lookup_form"):
        st.subheader("Find CVE Details")
        cve_id_lookup = st.text_input("Enter a CVE ID to lookup", help="e.g. : CVE-2021-44228")
        submitted = st.form_submit_button("Search")

if submitted and cve_id_lookup:
    if not _is_valid_cve_id(cve_id_lookup):
        st.sidebar.error(f"'{cve_id_lookup}' is not a valid CVE ID format.")
    else:
        with st.spinner(f"Fetching details for {cve_id_lookup}..."):
            cve_data = fetch_nvd_data_sync(cve_id_lookup)
        
        if cve_data:
            original_vuln_data = df[df['CVE ID'] == cve_id_lookup].iloc[0] if not df[df['CVE ID'] == cve_id_lookup].empty else None
            
            summary = _parse_nvd_response(cve_data, package_name=original_vuln_data['Package'] if original_vuln_data is not None else "N/A")
            
            if original_vuln_data is not None:
                summary.severity = original_vuln_data['Severity']

            show_cve_dialog(summary)
        else:
            st.sidebar.error(f"{cve_id_lookup} not found in NVD.")

# Apply filters
flt = df.copy()
if "Package" in flt.columns and pkg_search:
    flt = flt[flt["Package"].astype(str).str.contains(pkg_search, case=False, na=False)]
if "CVE ID" in flt.columns and cve_search:
    flt = flt[flt["CVE ID"].astype(str).str.contains(cve_search, case=False, na=False)]
if "Fixed Version" in flt.columns and only_fix:
    flt = flt[flt["Fixed Version"].astype(str).str.lower().ne("n/a")]

st.caption(f"Showing {len(flt)} / {len(df)} after filters")
for c in ["CVSS Score", "EPSS", "EPSS Percentile", "risk"]:
    if c in flt.columns:
        flt[c] = pd.to_numeric(flt[c], errors="coerce")

# Tabs
tab_overview, tab_priority, tab_table = st.tabs(["Overview", "Priority", "Full Table"])

with tab_overview:
    severity_kpis(flt)
    st.subheader("Vulnerability Overview by Severity")
    if "Severity" in flt.columns:
        counts = flt["Severity"].value_counts()
        ordered = [s for s in SEVERITY_ORDER if s in counts.index]
        if not counts.empty:
            chart_data = counts.reindex(ordered, fill_value=0).reset_index()
            chart_data.columns = ["Severity", "Count"]
            chart_data["Severity"] = pd.Categorical(chart_data["Severity"], categories=SEVERITY_ORDER, ordered=True)
            chart_data = chart_data.sort_values("Severity")
            st.bar_chart(chart_data, x="Severity", y="Count", use_container_width=True)

with tab_priority:
    st.subheader("Patch Priority Top 10")
    topN = flt.sort_values("risk", ascending=False).head(10).copy()
    topN['Rank'] = range(1, len(topN) + 1)
    
    topN['EPSS (Percentile)'] = topN.apply(
        lambda row: f"{row['EPSS']:.1%} ({get_ordinal_suffix(row['EPSS Percentile'] * 100)})"
                    if pd.notna(row.get('EPSS')) and pd.notna(row.get('EPSS Percentile')) else 'N/A',
        axis=1
    )
    
    column_config = {
        "DataSource": st.column_config.LinkColumn("DataSource", display_text="Open", help="Source"),
        "CVSS Score": st.column_config.NumberColumn("CVSS", format="%.1f")
    }
    if "DataSource" in topN.columns:
        topN["DataSource"] = topN["DataSource"].apply(linkify)

    show_cols = [
        "Rank", "Severity", "CVE ID",
        "Package", "Version", "Fixed Version", "CVSS Score",
        "EPSS (Percentile)", "DataSource",
    ]
    show_cols = [c for c in show_cols if c in topN.columns]
    
    styler_priority = topN[show_cols].style.map(severity_styler, subset=['Severity']).format({"CVSS Score": "{:.1f}"})
    
    st.dataframe(
        styler_priority,
        use_container_width=True,
        hide_index=True,
        column_config=column_config,
    )

with tab_table:
    st.markdown("#### Severity Summary")
    severity_kpis(flt)
    st.subheader("All Detected Vulnerabilities")
    table = flt.copy()

    if "DataSource" in table.columns:
        table["DataSource"] = table["DataSource"].apply(linkify)

    if "Severity" in table.columns:
        table["Severity"] = table["Severity"].fillna("Unknown")
        table["Severity"] = pd.Categorical(table["Severity"], categories=SEVERITY_ORDER, ordered=True)
        table = table.sort_values(["Severity"], ascending=[True])

    table['Rank'] = range(1, len(table) + 1)
    
    table['EPSS (Percentile)'] = table.apply(
        lambda row: f"{row['EPSS']:.1%} ({get_ordinal_suffix(row['EPSS Percentile'] * 100)})"
                    if pd.notna(row.get('EPSS')) and pd.notna(row.get('EPSS Percentile')) else 'N/A',
        axis=1
    )

    show_cols = [
        "Rank", "Severity", "CVE ID",
        "Package", "Version", "Fixed Version", "CVSS Score",
        "EPSS (Percentile)", "DataSource",
    ]
    show_cols = [c for c in show_cols if c in table.columns]
    final_table = table[show_cols]

    column_config_table = {
        "DataSource": st.column_config.LinkColumn("DataSource", display_text="Open", help="Open the data source link"),
        "CVSS Score": st.column_config.NumberColumn("CVSS", format="%.1f")
    }

    styler = (
        final_table.style
        .map(severity_styler, subset=['Severity'])
        .format({"CVSS Score": "{:.1f}"})
    )

    st.dataframe(
        styler,
        use_container_width=True,
        hide_index=True,
        column_config=column_config_table
    )

    csv = final_table.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV", csv, "vulnerabilities_filtered.csv", "text/csv")