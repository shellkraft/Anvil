import json
import re
from datetime import datetime
from typing import Optional


_KV_RE = re.compile(r"^(\s{0,4})([A-Za-z][A-Za-z0-9 _\-/]{0,19}?)\s+:\s+(.*)")


def _parse_detail(detail: str) -> dict:
    result: dict   = {}
    analysis: list = []
    last_key: Optional[str] = None

    for raw in detail.splitlines():
        line = raw.rstrip()
        if not line:
            last_key = None
            continue

        m = _KV_RE.match(line)
        if m:
            key   = m.group(2).strip().lower().replace(" ", "_")
            value = m.group(3).strip()
            result[key] = value
            last_key    = key
        elif last_key and line.startswith(" "):
            result[last_key] = result[last_key] + " " + line.strip()
        else:
            analysis.append(line.strip())
            last_key = None

    if analysis:
        result["analysis"] = analysis

    return result


def _serialise_finding(f: dict) -> dict:
    return {
        "severity":  f.get("severity", "P5"),
        "module":    f.get("module", ""),
        "message":   f.get("message", ""),
        "timestamp": f.get("timestamp", ""),
        "detail":    _parse_detail(f.get("detail", "")),
    }


def write_json_report(findings: list, ctx: dict, output_file: str) -> None:
    report = {
        "tool":      "Anvil",
        "generated": datetime.now().isoformat(),
        "target": {
            "exe":         ctx.get("exe_path"),
            "service":     ctx.get("service_name"),
            "pid":         ctx.get("pid"),
            "install_dir": ctx.get("install_dir"),
        },
        "total_findings": len(findings),
        "findings":       [_serialise_finding(f) for f in findings],
    }
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4, ensure_ascii=False)
