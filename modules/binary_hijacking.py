import os
from typing import List, Optional, Set, Tuple

from .utils import (
    finding, print_info, print_warning,
    path_writable_by_non_admin, is_windows,
    _SECURITY_MANDATORY_HIGH_RID,
    _SECURITY_MANDATORY_MEDIUM_RID,
    _SECURITY_MANDATORY_SYSTEM_RID,
    _is_protected_system_path,
    _esc_label,
    _severity_phantom,
    _severity_replace,
    _rid_from_label,
    _is_auto_triggered,
)
from . import procmon_session

MODULE_NAME = "Binary Hijacking"


def _is_system_path(path: str) -> bool:
    """Delegate to the centralised protected-path guard in utils."""
    return _is_protected_system_path(path, from_procmon=False)

# ---------------------------------------------------------------------------
# Environmental check — writable PATH entries before System32
# ---------------------------------------------------------------------------
def _check_path_for_writable_entries() -> List[dict]:
    """
    Walk %PATH% in order.  A writable entry appearing before System32 means
    an attacker can plant a same-named EXE that gets picked up before the real one.
    This is application-independent and always runs.
    """
    results   = []
    system32  = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    env_path  = os.environ.get("PATH", "")
    found_s32 = False

    for p in env_path.split(";"):
        p = p.strip().strip('"')
        if not p:
            continue
        if os.path.normcase(p) == os.path.normcase(system32):
            found_s32 = True
        if not found_s32 and os.path.isdir(p) and path_writable_by_non_admin(p):
            results.append(finding(
                severity = "P2",
                message  = f"Writable PATH entry before System32: {p}",
                detail   = (
                    f"Directory    : {p}\n"
                    f"Position     : Appears in %%PATH%% before System32\n"
                    f"Writable     : Yes (AccessCheck confirmed for standard users)\n"
                    f"Attack       : Plant a malicious .exe here with the same name as any\n"
                    f"               system binary.  It will be resolved before System32."
                ),
                module = MODULE_NAME,
            ))

    return results


# ---------------------------------------------------------------------------
# CSV analysis (Procmon path)
# ---------------------------------------------------------------------------
def _analyze_csv(
    csv_path: str,
    target_exe_name: str,
    target_pid: Optional[int],
    auto_trigger: bool = False,
    auto_trigger_desc: str = "",
) -> List[dict]:
    findings: List[dict] = []
    seen: Set[str] = set()
    target_lower = target_exe_name.lower()

    for row in procmon_session.parse_procmon_csv(csv_path):

        # ── Process / PID filter ──────────────────────────────────────────────
        if row.get("Process Name", "").lower() != target_lower:
            continue

        try:
            row_pid = int(row.get("PID", 0))
        except (ValueError, TypeError):
            row_pid = 0
        if target_pid and row_pid and row_pid != target_pid:
            continue

        if row.get("Operation", "").strip() != "CreateFile":
            continue

        path = row.get("Path", "").strip()
        if not path.lower().endswith(".exe"):
            continue

        result = row.get("Result", "").strip()

        # Deduplicate (path, result) pairs
        key = os.path.normcase(path) + "|" + result
        if key in seen:
            continue
        seen.add(key)

        # ── Gate 1: Skip system paths ─────────────────────────────────────────
        if _is_system_path(path):
            continue

        # ── Gate 2: Integrity must be High or System ──────────────────────────
        csv_integrity = row.get("Integrity", "").strip()
        rid = _rid_from_label(csv_integrity)
        if rid is None or rid < _SECURITY_MANDATORY_HIGH_RID:
            continue

        esc_lbl = _esc_label(rid)

        # ── Gate 3: Directory must be writable by non-admin ───────────────────
        exe_dir = os.path.dirname(path)
        if not exe_dir:
            continue

        # For NAME NOT FOUND: use exact directory (or nearest existing parent)
        # For SUCCESS: use the directory of the resolved EXE
        check_dir = exe_dir
        if "NAME NOT FOUND" in result and not os.path.isdir(exe_dir):
            check_dir = os.path.dirname(exe_dir)
        if not check_dir or _is_system_path(check_dir):
            continue
        if not path_writable_by_non_admin(check_dir):
            continue

        exe_name = os.path.basename(path)

        # ── Classify ──────────────────────────────────────────────────────────
        if "NAME NOT FOUND" in result:
            sev = _severity_phantom(rid, auto_trigger)
            trigger_note = (
                f"\n    Trigger      : {auto_trigger_desc}"
                if auto_trigger_desc else
                "\n    Trigger      : User-launched (manual execution required → P2)"
            )
            findings.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] Phantom EXE: {exe_name}",
                detail   = (
                    f"EXE name     : {exe_name}\n"
                    f"Attempted at : {path}\n"
                    f"Result       : NAME NOT FOUND — file does not exist at this path\n"
                    f"Process IL   : {csv_integrity}  (PID {row_pid})\n"
                    f"Plant dir    : {check_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Attack       : Drop malicious '{exe_name}' into '{check_dir}'.\n"
                    f"               It will be loaded on next process execution."
                ),
                module = MODULE_NAME,
            ))

        elif result == "SUCCESS":
            if not path_writable_by_non_admin(exe_dir):
                continue   # EXE exists but dir isn't writable — not replaceable
            sev = _severity_replace(rid, auto_trigger)
            trigger_note = (
                f"\n    Trigger      : {auto_trigger_desc}"
                if auto_trigger_desc else
                "\n    Trigger      : User-launched (manual execution required)"
            )
            findings.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] EXE loaded from writable directory: {exe_name}",
                detail   = (
                    f"EXE name     : {exe_name}\n"
                    f"Loaded from  : {path}\n"
                    f"Result       : SUCCESS — EXE was found and loaded\n"
                    f"Process IL   : {csv_integrity}  (PID {row_pid})\n"
                    f"Writable dir : {exe_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Attack       : Replace '{path}' with a malicious binary before launch."
                ),
                module = MODULE_NAME,
            ))

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def run(ctx: dict) -> List[dict]:
    findings: List[dict] = []

    # ── Environmental check (always) ──────────────────────────────────────────
    print_info("Checking PATH entries for writable pre-System32 directories…")
    findings.extend(_check_path_for_writable_entries())

    # ── Procmon CSV path ──────────────────────────────────────────────────────
    exe_path    = ctx.get("exe_path")
    procmon_exe = procmon_session.get_procmon_exe(ctx)

    if not procmon_exe or not procmon_session.capture_exists():
        if not procmon_exe:
            print_warning("Procmon not available — EXE runtime analysis skipped.")
        else:
            print_warning("No capture.pml — EXE runtime analysis skipped.")
        if not findings:
            print_info("No binary hijacking vectors found.")
        return findings

    csv_path = procmon_session.export_filtered_csv(procmon_exe, "binary")
    if not csv_path:
        # export_filtered_csv already printed the specific reason (missing .pmc,
        # Procmon crash, etc.) — no additional message needed here.
        if not findings:
            print_info("No binary hijacking vectors found.")
        return findings

    target_name = os.path.basename(exe_path) if exe_path else ""
    given_pid   = ctx.get("launched_pid") or ctx.get("pid")

    # ── P1 gate ───────────────────────────────────────────────────────────────
    auto_trigger, auto_trigger_desc = _is_auto_triggered(exe_path)
    if auto_trigger:
        print_info(f"Auto-trigger confirmed: {auto_trigger_desc}")
    else:
        print_info("No auto-trigger detected — findings capped at P2.")

    csv_findings = _analyze_csv(
        csv_path          = csv_path,
        target_exe_name   = target_name,
        target_pid        = given_pid,
        auto_trigger      = auto_trigger,
        auto_trigger_desc = auto_trigger_desc,
    )
    findings.extend(csv_findings)
    print_info(f"Procmon EXE analysis: {len(csv_findings)} finding(s).")

    if not findings:
        print_info("No binary hijacking vectors found.")

    return findings
