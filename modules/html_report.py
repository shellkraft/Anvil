import os
import json
import html
import base64
from datetime import datetime
from typing import List, Dict

from .utils import CVSS_RANGES, cvss_range

SEVERITY_COLOURS = {
    "P1": ("#ff2d55", "#fff0f3"),
    "P2": ("#ff6b35", "#fff5f0"),
    "P3": ("#f7b731", "#fffbf0"),
    "P4": ("#2196f3", "#f0f6ff"),
    "P5": ("#6c757d", "#f8f9fa"),
}

SEVERITY_ORDER = ["P1", "P2", "P3", "P4", "P5"]

# P-Level definitions for the Severity Model tab
P_LEVEL_DEFINITIONS = [
    {
        "level": "P1",
        "meaning": "Critical – Immediate threat",
        "detail": (
            "Reliably exploitable for privilege escalation or high-impact code execution. "
            "No user interaction required. Low attack complexity. Immediate remediation required."
        ),
        "cvss": "8.0 – 8.8",
    },
    {
        "level": "P2",
        "meaning": "High – Significant risk",
        "detail": (
            "May require user interaction, timing, or specific conditions to exploit. "
            "Often leads to privilege escalation or sensitive data exposure. Should be prioritized."
        ),
        "cvss": "7.0 – 7.9",
    },
    {
        "level": "P3",
        "meaning": "Medium – Security weakness",
        "detail": (
            "Misconfiguration or weak control that could be chained with other vulnerabilities. "
            "Limited impact on its own, but contributes to overall risk."
        ),
        "cvss": "4.0 – 6.9",
    },
    {
        "level": "P4",
        "meaning": "Low – Minor issue",
        "detail": (
            "Limited exploitability, non-default execution path, or theoretical risk. "
            "Best-practice recommendations with low immediate impact."
        ),
        "cvss": "0.1 – 3.9",
    },
    {
        "level": "P5",
        "meaning": "Informational – Hardening note",
        "detail": (
            "Contextual observations with no direct security impact. "
            "Hardening advice or informational notes for defense-in-depth."
        ),
        "cvss": "N/A",
    },
]


def _e(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def _severity_badge(severity: str) -> str:
    colour, _ = SEVERITY_COLOURS.get(severity, ("#6c757d", "#f8f9fa"))
    return (
        f'<span class="badge" style="background:{colour}">'
        f'{_e(severity)}</span>'
    )


def _cvss_badge(severity: str) -> str:
    cvss = cvss_range(severity)
    colour, _ = SEVERITY_COLOURS.get(severity, ("#6c757d", "#f8f9fa"))
    style = (
        f"color:{colour};border:1px solid {colour};"
        if severity != "P5"
        else "color:#6c757d;border:1px solid #6c757d;"
    )
    return f'<span class="cvss-badge" style="{style}">{_e(cvss)}</span>'


def _finding_card(f: dict, index: int) -> str:
    severity  = f.get("severity", "P5")
    _, bg     = SEVERITY_COLOURS.get(severity, ("#6c757d", "#f8f9fa"))
    colour, _ = SEVERITY_COLOURS.get(severity, ("#6c757d", "#f8f9fa"))
    message   = _e(f.get("message", ""))
    module    = _e(f.get("module", ""))
    timestamp = _e(f.get("timestamp", ""))
    detail    = _e(f.get("detail", "")).replace("\n", "<br>")

    return f"""
    <div class="finding-card" data-severity="{_e(severity)}" data-module="{_e(f.get('module',''))}"
         style="border-left: 4px solid {colour}; background: {bg}">
      <div class="card-header" onclick="toggleDetail('detail-{index}')">
        <div class="card-left">
          {_severity_badge(severity)}
          {_cvss_badge(severity)}
          <span class="card-module">{module}</span>
          <span class="card-message">{message}</span>
        </div>
        <div class="card-right">
          <span class="card-time">{timestamp}</span>
          <span class="toggle-icon" id="icon-{index}">&#9654;</span>
        </div>
      </div>
      <div class="card-detail" id="detail-{index}" style="display:none">
        <pre>{detail}</pre>
      </div>
    </div>"""


def _build_counts(findings: List[dict]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "P5")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _donut_chart(counts: Dict[str, int]) -> str:
    """Generate an SVG donut chart for severity distribution."""
    total        = sum(counts.values()) or 1
    radius       = 60
    cx, cy       = 80, 80
    stroke_width = 28
    circumference = 2 * 3.14159 * radius

    segments = []
    offset   = 0.0
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        colour, _ = SEVERITY_COLOURS[sev]
        fraction  = count / total
        dash      = fraction * circumference
        gap       = circumference - dash
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
            f'stroke="{colour}" stroke-width="{stroke_width}" '
            f'stroke-dasharray="{dash:.2f} {gap:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})">'
            f'<title>{sev}: {count}</title></circle>'
        )
        offset += dash

    legend = ""
    for sev in SEVERITY_ORDER:
        count     = counts.get(sev, 0)
        colour, _ = SEVERITY_COLOURS[sev]
        legend += (
            f'<div class="legend-item">'
            f'<span class="legend-dot" style="background:{colour}"></span>'
            f'{sev}: <strong>{count}</strong></div>'
        )

    return f"""
    <div class="chart-wrap">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="{cx}" cy="{cy}" r="{radius}" fill="none"
                stroke="#e9ecef" stroke-width="{stroke_width}"/>
        {"".join(segments)}
        <text x="{cx}" y="{cy+6}" text-anchor="middle"
              font-size="18" font-weight="bold" fill="#212529">{total}</text>
        <text x="{cx}" y="{cy+22}" text-anchor="middle"
              font-size="10" fill="#6c757d">findings</text>
      </svg>
      <div class="legend">{legend}</div>
    </div>"""


def _summary_cards(counts: Dict[str, int]) -> str:
    cards = ""
    for sev in SEVERITY_ORDER:
        count      = counts.get(sev, 0)
        colour, bg = SEVERITY_COLOURS[sev]
        cards += f"""
        <div class="summary-card" style="border-top: 4px solid {colour}; background:{bg}">
          <div class="summary-count" style="color:{colour}">{count}</div>
          <div class="summary-label">{sev}</div>
        </div>"""
    return f'<div class="summary-cards">{cards}</div>'


def _modules_table(findings: List[dict]) -> str:
    module_counts: Dict[str, Dict[str, int]] = {}
    for f in findings:
        mod = f.get("module", "Unknown")
        sev = f.get("severity", "P5")
        if mod not in module_counts:
            module_counts[mod] = {s: 0 for s in SEVERITY_ORDER}
        module_counts[mod][sev] += 1

    rows = ""
    for mod, sev_counts in sorted(module_counts.items()):
        total = sum(sev_counts.values())
        cells = "".join(
            f'<td class="mt-sev">'
            f'{"<strong>" + str(sev_counts[s]) + "</strong>" if sev_counts[s] else "&ndash;"}'
            f'</td>'
            for s in SEVERITY_ORDER
        )
        rows += f'<tr><td class="mt-mod">{_e(mod)}</td>{cells}<td class="mt-total"><strong>{total}</strong></td></tr>'

    headers = "".join(
        f'<th class="mt-hdr-sev" style="color:{SEVERITY_COLOURS[s][0]}">{s}</th>'
        for s in SEVERITY_ORDER
    )
    return f"""
    <table class="modules-table findings-module-table">
      <thead>
        <tr><th class="mt-hdr-mod">Module</th>{headers}<th class="mt-hdr-total">Total</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>"""


def _pe_security_table(pe_results: list) -> str:
    """
    Build the PE security mitigation grid as an HTML table.
    Each row = one binary; columns = ASLR, HighEntropyVA, DEP, SafeSEH, CFG,
    Authenticode, StrongNaming, DotNET, Arch.
    """
    if not pe_results:
        return ""

    def pill(val: str) -> str:
        v = val.upper() if val else "?"
        if v == "PASS":          return '<span class="pe-pill pe-pass">PASS</span>'
        if v == "FAIL":          return '<span class="pe-pill pe-fail">FAIL</span>'
        if v == "WARN":          return '<span class="pe-pill pe-warn">WARN</span>'
        if v in ("N/A", "NA"):   return '<span class="pe-pill pe-na">N/A</span>'
        if v == "YES":           return '<span class="pe-pill pe-yes">YES</span>'
        if v == "NO":            return '<span class="pe-pill pe-no">NO</span>'
        return f'<span class="pe-pill pe-na">{_e(val)}</span>'

    rows = ""
    for r in pe_results:
        arch_badge = f'<span class="pe-arch">{_e(r.get("arch", "?"))}</span>'
        rows += f"""
        <tr>
          <td class="binary-name" title="{_e(r.get("path", ""))}">{_e(r.get("name", ""))}</td>
          <td>{arch_badge}</td>
          <td>{pill(r.get("dotnet", "NO"))}</td>
          <td>{pill(r.get("aslr", "?"))}</td>
          <td>{pill(r.get("high_entropy", "?"))}</td>
          <td>{pill(r.get("dep", "?"))}</td>
          <td>{pill(r.get("safeseh", "?"))}</td>
          <td>{pill(r.get("cfg", "?"))}</td>
          <td>{pill(r.get("authenticode", "?"))}</td>
          <td>{pill(r.get("strongname", "?"))}</td>
        </tr>"""

    return f"""
    <div class="pe-table-wrap">
      <table class="pe-table">
        <thead>
          <tr>
            <th class="left">Binary</th>
            <th>Arch</th>
            <th>.NET</th>
            <th>ASLR</th>
            <th>HighEntropyVA</th>
            <th>DEP / NX</th>
            <th>SafeSEH</th>
            <th>CFG</th>
            <th>Authenticode</th>
            <th>StrongName</th>
          </tr>
        </thead>
        <tbody>{rows}
        </tbody>
      </table>
    </div>"""


def _severity_model_content() -> str:
    """Build the Severity Model tab explaining P1–P5."""
    rows = ""
    for p in P_LEVEL_DEFINITIONS:
        colour, _ = SEVERITY_COLOURS[p["level"]]
        rows += f"""
        <tr>
          <td style="text-align:center">
            <span class="badge" style="background:{colour}">{_e(p["level"])}</span>
          </td>
          <td>
            <strong>{_e(p["meaning"])}</strong><br>
            <span style="color:#6c757d;font-size:12px">{_e(p["detail"])}</span>
          </td>
          <td style="text-align:center;font-family:'Consolas',monospace;white-space:nowrap">
            {_e(p["cvss"])}
          </td>
        </tr>"""

    return f"""
    <div class="section-title">P-Level Severity Classification</div>
    <p style="color:#6c757d;margin-bottom:24px;font-size:13px">
      The P‑level reflects Anvil’s internal risk assessment based on exploitability,
      integrity impact, and required conditions. The CVSS ranges are estimates
      for local privilege escalation scenarios only; other finding types may
      have different CVSS scores. P1 findings are the most immediately actionable.
    </p>
    <div style="background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,0.08);
                overflow:hidden;margin-bottom:32px">
      <table class="modules-table" style="margin-bottom:0">
        <thead>
          <tr>
            <th style="width:70px;text-align:center">P Level</th>
            <th>Meaning &amp; Context</th>
            <th style="width:130px;text-align:center">Typical CVSS</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <div style="background:#f8f9fa;border-radius:10px;padding:16px 20px;
                font-size:12px;color:#6c757d;border-left:4px solid #00bcd4">
      <strong style="color:#212529">Note on CVSS estimates:</strong>
      Ranges reflect local privilege escalation vectors only. Remote code execution
      scenarios (CVSS 9.0+) are outside the scope of Anvil&rsquo;s detection model.
      P1 findings are the most immediately actionable &mdash; they require no chaining
      and no user interaction to escalate privileges.
    </div>"""


def _load_logo_tag(report_script_dir: str) -> str:
    """
    Attempt to load logo.png and return a base64-embedded <img> tag so the
    report stays fully self-contained.  Returns an empty string if the file
    is missing or unreadable.

    Search order:
      1. PyInstaller extraction dir (sys._MEIPASS) — used when running as
         a compiled exe; PyInstaller extracts --add-data files here.
      2. Directory of this script — used when running from source.
      3. Directory of the running executable — fallback for cases where
         logo.png is placed alongside anvil.exe.
    """
    import sys

    candidates = []

    # 1. PyInstaller bundle extraction directory
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "logo.png"))

    # 2. Script source directory (normal Python execution)
    candidates.append(os.path.join(report_script_dir, "logo.png"))

    # 3. Alongside the running exe
    exe_dir = os.path.dirname(sys.executable)
    if exe_dir:
        candidates.append(os.path.join(exe_dir, "logo.png"))

    logo_path = next((p for p in candidates if os.path.isfile(p)), None)
    if not logo_path:
        return ""

    try:
        with open(logo_path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        return (
            f'<div class="report-header-logo">'
            f'<img src="data:image/png;base64,{b64}" alt="Anvil Logo" class="report-logo">'
            f'</div>'
        )
    except Exception:
        return ""


def generate_html_report(
    findings: List[dict],
    ctx: dict,
    output_path: str,
    scan_start: str,
    scan_end: str,
) -> None:
    counts         = _build_counts(findings)
    donut          = _donut_chart(counts)
    summary_cards  = _summary_cards(counts)
    modules_table  = _modules_table(findings)
    pe_results     = ctx.get("pe_security_results", [])
    pe_sec_table   = _pe_security_table(pe_results)
    pe_sec_section = (
        '\n  <!-- PE Security Mitigations -->\n'
        '  <div class="section-title">PE Binary Security Mitigations</div>\n'
        + pe_sec_table
    ) if pe_results else ""

    # Sort findings by severity
    sev_rank        = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings, key=lambda f: sev_rank.get(f.get("severity", "P5"), 99)
    )

    # Build filter buttons
    all_modules = sorted({f.get("module", "Unknown") for f in findings})
    sev_buttons = "".join(
        f'<button class="filter-btn active" onclick="filterSeverity(\'{s}\')" '
        f'data-filter="{s}" '
        f'style="border-color:{SEVERITY_COLOURS[s][0]};color:{SEVERITY_COLOURS[s][0]}">'
        f'{s} ({counts.get(s, 0)})</button>'
        for s in SEVERITY_ORDER
    )
    mod_buttons = "".join(
        f'<button class="filter-btn mod-btn active" onclick="filterModule(\'{_e(m)}\')" '
        f'data-filter="{_e(m)}">{_e(m)}</button>'
        for m in all_modules
    )

    finding_cards = "\n".join(_finding_card(f, i) for i, f in enumerate(sorted_findings))

    # Target info
    target_exe = _e(ctx.get("exe_path") or "N/A")
    target_svc = _e(ctx.get("service_name") or "N/A")
    target_pid = _e(str(ctx.get("pid") or "N/A"))
    target_dir = _e(ctx.get("install_dir") or "N/A")
    total      = sum(counts.values())

    # Header: logo.png if it exists next to this script, otherwise "Anv1L" text
    _script_dir    = os.path.dirname(os.path.abspath(__file__))
    logo_html      = _load_logo_tag(_script_dir)
    header_content = logo_html if logo_html else '<h1>AnviL</h1>'

    severity_model = _severity_model_content()

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anvil \u2013 Security Assessment Report</title>
<style>
  /* \u2500\u2500 Reset & Base \u2500\u2500 */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    color: #212529;
    font-size: 14px;
    line-height: 1.6;
  }}

  /* \u2500\u2500 Header \u2500\u2500 */
  .report-header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1c2128 100%);
    color: #fff;
    padding: 40px 48px 32px;
    border-bottom: 3px solid #00bcd4;
  }}
  .report-header h1 {{
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 4px;
    color: #00bcd4;
  }}
  .report-header-logo {{ margin-bottom: 16px; }}
  .report-logo {{ max-height: 100px; display: block; }}
  .report-subtitle {{ color: #8b949e; font-size: 13px; margin-bottom: 24px; }}
  .report-meta {{
    display: flex; gap: 32px; flex-wrap: wrap;
    font-size: 12px; color: #8b949e;
  }}
  .report-meta strong {{ color: #e6edf3; }}

  /* \u2500\u2500 Main Layout \u2500\u2500 */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}

  /* \u2500\u2500 Tabs \u2500\u2500 */
  .tab-nav {{
    display: flex; margin-bottom: 28px;
    border-bottom: 2px solid #e9ecef;
  }}
  .tab-btn {{
    padding: 10px 22px;
    background: none; border: none;
    font-size: 13px; font-weight: 600;
    color: #6c757d; cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: color 0.15s, border-color 0.15s;
  }}
  .tab-btn:hover {{ color: #212529; }}
  .tab-btn.active {{ color: #00bcd4; border-bottom-color: #00bcd4; }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}

  /* \u2500\u2500 Section Titles \u2500\u2500 */
  .section-title {{
    font-size: 16px; font-weight: 700;
    color: #0d1117; margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 2px solid #e9ecef;
    display: flex; align-items: center; gap: 8px;
  }}
  .section-title::before {{
    content: ""; display: block;
    width: 4px; height: 20px; border-radius: 2px;
    background: #00bcd4;
  }}

  /* \u2500\u2500 Dashboard Row \u2500\u2500 */
  .dashboard {{ display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }}
  .dashboard-left {{ flex: 1; min-width: 260px; }}
  .dashboard-right {{ flex: 2; min-width: 300px; }}

  /* \u2500\u2500 Summary Cards \u2500\u2500 */
  .summary-cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .summary-card {{
    flex: 1; min-width: 80px;
    background: #fff; border-radius: 10px;
    padding: 16px 12px; text-align: center;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  }}
  .summary-count {{
    font-size: 28px; font-weight: 800; line-height: 1; margin-bottom: 4px;
  }}
  .summary-label {{
    font-size: 10px; font-weight: 600;
    text-transform: uppercase; color: #6c757d; letter-spacing: 0.5px;
  }}

  /* \u2500\u2500 Donut Chart \u2500\u2500 */
  .chart-wrap {{
    display: flex; align-items: center; gap: 24px;
    background: #fff; border-radius: 12px;
    padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    margin-bottom: 16px;
  }}
  .legend {{ display: flex; flex-direction: column; gap: 8px; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 12px; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}

  /* \u2500\u2500 Target Info \u2500\u2500 */
  .target-info {{
    background: #fff; border-radius: 12px;
    padding: 20px 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    margin-bottom: 24px;
  }}
  .target-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 12px 24px; margin-top: 12px;
  }}
  .target-row {{ display: flex; flex-direction: column; gap: 2px; }}
  .target-label {{ font-size: 11px; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }}
  .target-value {{
    font-family: "Consolas", "Menlo", monospace;
    font-size: 12px; color: #0d1117; word-break: break-all;
  }}

  /* \u2500\u2500 Modules Table \u2500\u2500 */
  .modules-table {{
    width: 100%; border-collapse: collapse;
    background: #fff; border-radius: 12px;
    overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    margin-bottom: 32px;
  }}
  .modules-table th {{
    background: #f8f9fa; padding: 10px 12px;
    text-align: left; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px;
    color: #6c757d; border-bottom: 1px solid #e9ecef;
  }}
  .modules-table td {{
    padding: 10px 12px; border-bottom: 1px solid #f0f2f5; font-size: 13px;
  }}
  .modules-table tr:last-child td {{ border-bottom: none; }}
  .modules-table tr:hover td {{ background: #f8f9fa; }}

  /* ── Findings-by-module table (fixed layout + column borders) ── */
  .findings-module-table {{
    table-layout: fixed;
  }}
  .findings-module-table th, .findings-module-table td {{
    border-right: 1px solid #e9ecef;
  }}
  .findings-module-table th:last-child, .findings-module-table td:last-child {{
    border-right: none;
  }}
  .mt-hdr-mod {{
    text-align: left !important;
    color: #6c757d !important;
    width: auto;
  }}
  .mt-hdr-sev {{
    text-align: center !important;
    font-weight: 700 !important;
    width: 56px;
  }}
  .mt-hdr-total {{
    text-align: center !important;
    color: #6c757d !important;
    width: 64px;
  }}
  .mt-mod  {{ text-align: left; }}
  .mt-sev  {{ text-align: center; }}
  .mt-total {{ text-align: center; }}

  /* \u2500\u2500 Filters \u2500\u2500 */
  .filters {{
    background: #fff; border-radius: 12px;
    padding: 16px 20px; margin-bottom: 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  }}
  .filter-group {{ margin-bottom: 10px; }}
  .filter-group:last-child {{ margin-bottom: 0; }}
  .filter-label {{
    font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px; color: #6c757d; margin-bottom: 8px;
  }}
  .filter-buttons {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .filter-btn {{
    padding: 4px 12px; border-radius: 20px;
    border: 1.5px solid; background: transparent;
    font-size: 11px; font-weight: 600;
    cursor: pointer; transition: all 0.15s; opacity: 0.4;
  }}
  .filter-btn.active {{ opacity: 1; }}
  .filter-btn:hover {{ opacity: 0.8; }}

  /* \u2500\u2500 Finding Cards \u2500\u2500 */
  .findings-list {{ display: flex; flex-direction: column; gap: 8px; }}
  .finding-card {{
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.07);
    overflow: hidden; transition: box-shadow 0.15s;
  }}
  .finding-card:hover {{ box-shadow: 0 3px 10px rgba(0,0,0,0.12); }}
  .finding-card.hidden {{ display: none; }}
  .card-header {{
    display: flex; align-items: center;
    justify-content: space-between;
    padding: 14px 16px; cursor: pointer; user-select: none; gap: 12px;
  }}
  .card-left {{ display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; }}
  .card-right {{ display: flex; align-items: center; gap: 12px; flex-shrink: 0; }}
  .badge {{
    padding: 2px 10px; border-radius: 12px;
    font-size: 10px; font-weight: 800;
    text-transform: uppercase; letter-spacing: 0.5px;
    color: #fff; flex-shrink: 0;
  }}
  .cvss-badge {{
    padding: 2px 8px; border-radius: 4px;
    font-size: 10px; font-weight: 600;
    font-family: "Consolas", monospace;
    background: transparent; flex-shrink: 0; white-space: nowrap;
  }}
  .card-module {{
    font-size: 11px; font-weight: 600; color: #6c757d; flex-shrink: 0;
    background: #f0f2f5; padding: 2px 8px; border-radius: 4px;
  }}
  .card-message {{
    font-size: 13px; font-weight: 500; color: #212529;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }}
  .card-time {{ font-size: 11px; color: #6c757d; white-space: nowrap; }}
  .toggle-icon {{
    font-size: 10px; color: #6c757d;
    transition: transform 0.2s; width: 16px; text-align: center;
  }}
  .card-detail {{ padding: 0 16px 16px; border-top: 1px solid rgba(0,0,0,0.06); }}
  .card-detail pre {{
    font-family: "Consolas", "Menlo", "Courier New", monospace;
    font-size: 12px; line-height: 1.7; color: #1a1a2e;
    background: rgba(255,255,255,0.5);
    padding: 12px 16px; border-radius: 6px;
    overflow-x: auto; white-space: pre-wrap; word-break: break-word;
    margin-top: 12px;
  }}

  /* \u2500\u2500 No findings state \u2500\u2500 */
  .no-findings {{
    text-align: center; padding: 48px; color: #6c757d;
    font-size: 15px; background: #fff; border-radius: 12px;
  }}

  /* \u2500\u2500 Footer \u2500\u2500 */
  .report-footer {{
    text-align: center; padding: 24px;
    color: #6c757d; font-size: 12px;
    border-top: 1px solid #e9ecef; margin-top: 40px;
  }}

  /* \u2500\u2500 PE Security Table \u2500\u2500 */
  .pe-table-wrap {{
    background: #fff; border-radius: 12px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    overflow-x: auto; margin-bottom: 32px;
  }}
  .pe-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .pe-table th {{
    background: #0d1117; color: #e6edf3;
    padding: 10px 12px; text-align: center;
    font-weight: 600; white-space: nowrap;
    position: sticky; top: 0; z-index: 1;
  }}
  .pe-table th.left {{ text-align: left; }}
  .pe-table td {{
    padding: 8px 12px; border-bottom: 1px solid #f0f2f5;
    text-align: center; white-space: nowrap;
  }}
  .pe-table td.binary-name {{
    text-align: left; font-family: "Consolas","Courier New",monospace;
    font-size: 11px; color: #212529; max-width: 220px;
    overflow: hidden; text-overflow: ellipsis;
  }}
  .pe-table tr:last-child td {{ border-bottom: none; }}
  .pe-table tr:hover td {{ background: #f8f9fa; }}
  .pe-pill {{
    display: inline-block; padding: 2px 9px; border-radius: 10px;
    font-size: 10px; font-weight: 700; letter-spacing: 0.3px; min-width: 38px;
  }}
  .pe-pass {{ background: #d1fae5; color: #065f46; }}
  .pe-fail {{ background: #fee2e2; color: #991b1b; }}
  .pe-warn {{ background: #fef3c7; color: #92400e; }}
  .pe-na   {{ background: #f0f2f5; color: #6c757d; }}
  .pe-yes  {{ background: #dbeafe; color: #1e40af; }}
  .pe-no   {{ background: #f0f2f5; color: #6c757d; }}
  .pe-arch {{
    display: inline-block; padding: 1px 7px; border-radius: 4px;
    font-size: 10px; font-weight: 600; background: #ede9fe; color: #5b21b6;
  }}

  /* \u2500\u2500 Print \u2500\u2500 */
  @media print {{
    body {{ background: #fff; }}
    .filters, .filter-btn, .tab-nav {{ display: none; }}
    .tab-panel {{ display: block !important; }}
    .finding-card {{ break-inside: avoid; box-shadow: none; border: 1px solid #e9ecef; }}
    .card-detail {{ display: block !important; }}
    .report-header {{ background: #0d1117 !important; -webkit-print-color-adjust: exact; }}
  }}
</style>
</head>
<body>

<!-- Header -->
<div class="report-header">
  {header_content}
  <div class="report-subtitle">Windows Thick Client Security Assessment Report</div>
  <div class="report-meta">
    <div><strong>Scan Start:</strong> {_e(scan_start)}</div>
    <div><strong>Scan End:</strong> {_e(scan_end)}</div>
    <div><strong>Total Findings:</strong> {total}</div>
    <div><strong>Generated:</strong> {_e(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
  </div>
</div>

<div class="container">

  <!-- Tab Navigation -->
  <div class="tab-nav">
    <button class="tab-btn active" id="btn-findings" onclick="switchTab('findings', this)">Findings</button>
    <button class="tab-btn" id="btn-severity-model" onclick="switchTab('severity-model', this)">Severity Model</button>
  </div>

  <!-- ── Findings Tab ── -->
  <div class="tab-panel active" id="tab-findings">

    <!-- Dashboard -->
    <div class="section-title">Executive Summary</div>
    <div class="dashboard">
      <div class="dashboard-left">
        {donut}
      </div>
      <div class="dashboard-right">
        {summary_cards}
        <div class="target-info">
          <div class="section-title" style="margin-bottom:12px;font-size:14px">Target Information</div>
          <div class="target-grid">
            <div class="target-row">
              <span class="target-label">Executable</span>
              <span class="target-value">{target_exe}</span>
            </div>
            <div class="target-row">
              <span class="target-label">Service</span>
              <span class="target-value">{target_svc}</span>
            </div>
            <div class="target-row">
              <span class="target-label">Process ID</span>
              <span class="target-value">{target_pid}</span>
            </div>
            <div class="target-row">
              <span class="target-label">Install Directory</span>
              <span class="target-value">{target_dir}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    {pe_sec_section}

    <!-- Module Breakdown -->
    <div class="section-title">Findings by Module</div>
    {modules_table}

    <!-- All Findings -->
    <div class="section-title">All Findings
      <span style="font-size:12px;font-weight:400;color:#6c757d;margin-left:8px">
        Click any finding to expand details
      </span>
    </div>

    <!-- Filters -->
    <div class="filters">
      <div class="filter-group">
        <div class="filter-label">Filter by Severity</div>
        <div class="filter-buttons">{sev_buttons}
          <button class="filter-btn active" onclick="resetSeverity()"
            style="border-color:#6c757d;color:#6c757d">All</button>
        </div>
      </div>
      <div class="filter-group">
        <div class="filter-label">Filter by Module</div>
        <div class="filter-buttons">{mod_buttons}
          <button class="filter-btn mod-btn active" onclick="resetModule()"
            style="border-color:#6c757d;color:#6c757d">All</button>
        </div>
      </div>
    </div>

    <!-- Finding Cards -->
    <div class="findings-list" id="findingsList">
      {finding_cards if finding_cards else '<div class="no-findings">No findings recorded.</div>'}
    </div>

  </div><!-- /tab-findings -->

  <!-- ── Severity Model Tab ── -->
  <div class="tab-panel" id="tab-severity-model">
    {severity_model}
  </div><!-- /tab-severity-model -->

</div>

<!-- Footer -->
<div class="report-footer">
  Generated by <strong>Anvil</strong> \u2014 Windows Thick Client Security Assessment Tool
</div>

<script>
  // \u2500\u2500 Tab switching \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  function switchTab(name, btn) {{
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    btn.classList.add('active');
  }}

  // \u2500\u2500 Toggle finding detail \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  function toggleDetail(id) {{
    const el   = document.getElementById(id);
    const idx  = id.split('-')[1];
    const icon = document.getElementById('icon-' + idx);
    if (el.style.display === 'none') {{
      el.style.display = 'block';
      icon.innerHTML = '&#9660;';
    }} else {{
      el.style.display = 'none';
      icon.innerHTML = '&#9654;';
    }}
  }}

  // \u2500\u2500 Severity filter \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  let activeSeverities = new Set({json.dumps(SEVERITY_ORDER)});
  let activeModules    = null;

  function filterSeverity(sev) {{
    if (activeSeverities.has(sev)) {{
      activeSeverities.delete(sev);
    }} else {{
      activeSeverities.add(sev);
    }}
    document.querySelectorAll('.filter-btn:not(.mod-btn)').forEach(btn => {{
      if (btn.dataset.filter) {{
        btn.classList.toggle('active', activeSeverities.has(btn.dataset.filter));
      }}
    }});
    applyFilters();
  }}

  function resetSeverity() {{
    activeSeverities = new Set({json.dumps(SEVERITY_ORDER)});
    document.querySelectorAll('.filter-btn:not(.mod-btn)').forEach(b => b.classList.add('active'));
    applyFilters();
  }}

  // \u2500\u2500 Module filter \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  function filterModule(mod) {{
    activeModules = (activeModules === mod) ? null : mod;
    document.querySelectorAll('.mod-btn').forEach(btn => {{
      btn.classList.toggle('active',
        !btn.dataset.filter || btn.dataset.filter === activeModules || activeModules === null
      );
    }});
    applyFilters();
  }}

  function resetModule() {{
    activeModules = null;
    document.querySelectorAll('.mod-btn').forEach(b => b.classList.add('active'));
    applyFilters();
  }}

  // \u2500\u2500 Apply both filters \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  function applyFilters() {{
    document.querySelectorAll('.finding-card').forEach(card => {{
      const sevOk = activeSeverities.has(card.dataset.severity);
      const modOk = activeModules === null || card.dataset.module === activeModules;
      card.classList.toggle('hidden', !(sevOk && modOk));
    }});
  }}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_out)
