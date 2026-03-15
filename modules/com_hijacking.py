import os
import re
from typing import Dict, List, Optional, Set, Tuple

from .utils import (
    finding, print_info, print_warning,
    path_writable_by_non_admin, is_windows,
    get_process_integrity, integrity_label,
    _SECURITY_MANDATORY_HIGH_RID,
    _SECURITY_MANDATORY_MEDIUM_RID,
    _SECURITY_MANDATORY_SYSTEM_RID,
    _is_protected_system_path,
    _esc_label,
    _rid_from_label,
    _severity_phantom,
    _severity_replace,
    _is_auto_triggered,
)
from . import procmon_session

MODULE_NAME = "COM Hijacking"

CLSID_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
)


_SYSTEM_ROOT = os.path.normcase(os.environ.get("SystemRoot", "C:\\Windows"))
_PROTECTED_PREFIXES = tuple(
    os.path.normcase(p) for p in [
        os.path.join(_SYSTEM_ROOT, "System32"),
        os.path.join(_SYSTEM_ROOT, "SysWOW64"),
        os.path.join(_SYSTEM_ROOT, "System"),
        _SYSTEM_ROOT,
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    ]
)


def _is_protected(path: str) -> bool:
    """Separator-aware protected-path guard (does NOT call os.path.abspath)."""
    return _is_protected_system_path(path, from_procmon=True)


def _is_protected_static(path: str) -> bool:
    """Static (non-Procmon) guard — calls abspath for registry values."""
    norm = os.path.normcase(os.path.abspath(path))
    return any(norm.startswith(p + os.sep) or norm == p for p in _PROTECTED_PREFIXES)


# ---------------------------------------------------------------------------
# Integrity helpers
# ---------------------------------------------------------------------------
def _get_process_il(ctx: dict) -> Tuple[int, str]:
    """Return (rid, label) for the target process."""
    pid = ctx.get("launched_pid") or ctx.get("pid")
    rid = get_process_integrity(pid) if pid else None
    if rid is None:
        rid = _SECURITY_MANDATORY_MEDIUM_RID
    return rid, integrity_label(rid)


def _severity_for_il(rid: Optional[int]) -> str:
    """Map integrity RID → severity for genuine hijack surfaces."""
    if rid is None:                              return "P3"
    if rid >= _SECURITY_MANDATORY_SYSTEM_RID:    return "P1"
    if rid >= _SECURITY_MANDATORY_HIGH_RID:      return "P2"
    if rid >= _SECURITY_MANDATORY_MEDIUM_RID:    return "P3"
    return "P4"


def _esc_label_local(rid: Optional[int]) -> str:
    if rid is None:                              return "Code Execution"
    if rid >= _SECURITY_MANDATORY_HIGH_RID:      return "Privilege Escalation"
    if rid >= _SECURITY_MANDATORY_MEDIUM_RID:    return "User-Level Code Execution"
    return "Code Execution (Low IL)"


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _open_reg_key(hive, path):
    try:
        import winreg
        return winreg.OpenKey(hive, path)
    except Exception:
        return None


def _reg_query_value(key, name="") -> Optional[str]:
    try:
        import winreg
        value, _ = winreg.QueryValueEx(key, name)
        return str(value)
    except Exception:
        return None


def _enum_subkeys(key):
    try:
        import winreg
        index = 0
        while True:
            try:
                yield winreg.EnumKey(key, index)
                index += 1
            except OSError:
                break
    except Exception:
        return


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
def _resolve_server_path(raw_path: str) -> str:
    """
    Extract the executable path from a COM server registry value.

    The value may be:
      "C:\\path with spaces\\server.dll"
      "C:\\path with spaces\\server.exe" /args
      C:\\nospaces\\server.dll
      %SystemRoot%\\server.dll
    """
    if not raw_path:
        return ""
    expanded = os.path.expandvars(raw_path).strip()
    if expanded.startswith('"'):
        expanded = expanded[1:].split('"')[0]
    else:
        expanded = expanded.split(" ")[0]
    expanded = expanded.strip()
    if not expanded:
        return ""
    try:
        expanded = os.path.normpath(expanded)
    except Exception:
        pass
    return expanded


def _dir_writable(directory: str) -> bool:
    if not directory:
        return False
    if _is_protected_static(directory):
        return False
    return path_writable_by_non_admin(directory)


# ---------------------------------------------------------------------------
# CLSID extraction (static)
# ---------------------------------------------------------------------------
def _extract_clsids_from_binary(exe_path: str) -> Set[str]:
    clsids: Set[str] = set()
    if not exe_path or not os.path.isfile(exe_path):
        return clsids
    MAX_READ = 16 * 1024 * 1024
    try:
        with open(exe_path, "rb") as f:
            data = f.read(MAX_READ)
        for m in CLSID_RE.finditer(data.decode("ascii", errors="ignore")):
            clsids.add(m.group(0).upper())
        try:
            for m in CLSID_RE.finditer(data.decode("utf-16-le", errors="ignore")):
                clsids.add(m.group(0).upper())
        except Exception:
            pass
    except Exception:
        pass
    return clsids


# ---------------------------------------------------------------------------
# CLSID checks against HKLM (static, scoped to binary)
# ---------------------------------------------------------------------------
def _check_clsids_against_hklm(clsids: Set[str], il_rid: int, il_label: str) -> List[dict]:
    """
    For each CLSID found in the binary:
      - Not in HKLM AND not in HKCU → phantom (user-level persistence only)
      - HKLM exists AND HKCU also exists → HKCU shadow (real hijack)
      - HKLM exists, server path is missing → phantom server path (real hijack surface)
    """
    results = []
    if not clsids or not is_windows():
        return results

    esc_lbl = _esc_label_local(il_rid)
    sev     = _severity_for_il(il_rid)

    try:
        import winreg
        for clsid in sorted(clsids):
            hklm_path = rf"SOFTWARE\Classes\CLSID\{clsid}"
            hkcu_path = rf"Software\Classes\CLSID\{clsid}"

            hklm_key = _open_reg_key(winreg.HKEY_LOCAL_MACHINE, hklm_path)
            hkcu_key = _open_reg_key(winreg.HKEY_CURRENT_USER,  hkcu_path)

            # ── Case 1: Completely unregistered → user-level persistence only ──
            if hklm_key is None and hkcu_key is None:
                phantom_sev = "P3" if il_rid >= _SECURITY_MANDATORY_HIGH_RID else "P4"
                results.append(finding(
                    severity = phantom_sev,
                    message  = f"[User-Level COM Activation Surface] Phantom CLSID: {clsid}",
                    detail   = (
                        f"CLSID        : {clsid}\n"
                        f"Status       : No HKLM or HKCU registration found\n"
                        f"Process IL   : {il_label}\n"
                        f"Impact       : A user can register this CLSID under HKCU without admin rights.\n"
                        f"               This enables user-level code execution / persistence — it is\n"
                        f"               NOT privilege escalation unless the process genuinely runs\n"
                        f"               elevated in normal (non-tool-launched) conditions.\n"
                        f"Register at  : HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32\n"
                        f"               Default value → full path to malicious DLL"
                    ),
                    module = MODULE_NAME,
                ))
                continue

            # ── Case 2: HKCU shadow overrides HKLM → real hijack ──────────────
            if hkcu_key is not None and hklm_key is not None:
                results.append(finding(
                    severity = sev,
                    message  = f"[{esc_lbl}] HKCU COM shadow overrides HKLM: {clsid}",
                    detail   = (
                        f"CLSID        : {clsid}\n"
                        f"HKLM entry   : Exists  (legitimate registration)\n"
                        f"HKCU entry   : EXISTS  ← takes precedence over HKLM\n"
                        f"Process IL   : {il_label}\n"
                        f"Impact       : Any COM activation of {clsid} by this process will use\n"
                        f"               the HKCU registration instead of the system one.\n"
                        f"               If the HKCU server path points to a writable or missing\n"
                        f"               file, this is an active hijack surface."
                    ),
                    module = MODULE_NAME,
                ))
                continue

            # ── Case 3: HKLM exists — check server path ────────────────────────
            if hklm_key is not None:
                for server_type in ("InprocServer32", "LocalServer32"):
                    server_key = _open_reg_key(
                        winreg.HKEY_LOCAL_MACHINE,
                        rf"{hklm_path}\{server_type}"
                    )
                    if not server_key:
                        continue
                    raw      = _reg_query_value(server_key)
                    srv_path = _resolve_server_path(raw or "")

                    if srv_path and not os.path.isfile(srv_path):
                        parent = os.path.dirname(srv_path)
                        if parent and os.path.isdir(parent) and _dir_writable(parent):
                            results.append(finding(
                                severity = sev,
                                message  = f"[{esc_lbl}] COM server missing & directory writable: {clsid}",
                                detail   = (
                                    f"CLSID        : {clsid}\n"
                                    f"Server type  : {server_type}\n"
                                    f"Missing path : {srv_path}\n"
                                    f"Plant dir    : {parent}  ← writable by standard users\n"
                                    f"Process IL   : {il_label}\n"
                                    f"Attack       : Drop a malicious binary at '{srv_path}'.\n"
                                    f"               COM activation will load the planted binary."
                                ),
                                module = MODULE_NAME,
                            ))
                        else:
                            results.append(finding(
                                severity = "P4",
                                message  = f"COM server missing (dir not writable): {clsid} → {server_type}",
                                detail   = (
                                    f"CLSID        : {clsid}\n"
                                    f"Missing path : {srv_path}\n"
                                    f"Dir writable : No — standard users cannot plant here."
                                ),
                                module = MODULE_NAME,
                            ))

                    elif srv_path and os.path.isfile(srv_path):
                        srv_dir = os.path.dirname(srv_path)
                        if _dir_writable(srv_dir):
                            results.append(finding(
                                severity = sev,
                                message  = f"[{esc_lbl}] COM server in writable directory: {clsid}",
                                detail   = (
                                    f"CLSID        : {clsid}\n"
                                    f"Server type  : {server_type}\n"
                                    f"Binary       : {srv_path}\n"
                                    f"Writable dir : {srv_dir}  ← writable by standard users\n"
                                    f"Process IL   : {il_label}\n"
                                    f"Attack       : Replace the COM server binary with a malicious copy."
                                ),
                                module = MODULE_NAME,
                            ))

    except Exception:
        pass

    return results


# ---------------------------------------------------------------------------
# HKCU shadow scan (profile-wide — not binary scoped)
# ---------------------------------------------------------------------------
def _scan_hkcu_shadows(
    il_rid: int,
    il_label: str,
    clsid_filter: Optional[set] = None,
) -> List[dict]:
    """
    Enumerate HKCU\\Software\\Classes\\CLSID and report entries that shadow HKLM.

    clsid_filter — set of lowercase CLSID strings extracted from the binary.
                   Must never be None or empty — always scope to the target.
    """
    results = []
    if not is_windows():
        return results
    # Safety net: never enumerate all HKCU COM entries without a scope filter.
    if not clsid_filter:
        return results

    sev     = _severity_for_il(il_rid)
    esc_lbl = _esc_label_local(il_rid)

    try:
        import winreg
        hkcu_base = r"Software\Classes\CLSID"
        hkcu_key  = _open_reg_key(winreg.HKEY_CURRENT_USER, hkcu_base)
        if not hkcu_key:
            return results

        for clsid in _enum_subkeys(hkcu_key):
            if clsid_filter and clsid.lower() not in clsid_filter:
                continue

            hklm_exists = _open_reg_key(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SOFTWARE\Classes\CLSID\{clsid}"
            ) is not None

            for server_type in ("InprocServer32", "LocalServer32"):
                sk_path    = rf"{hkcu_base}\{clsid}\{server_type}"
                server_key = _open_reg_key(winreg.HKEY_CURRENT_USER, sk_path)
                if not server_key:
                    continue
                raw      = _reg_query_value(server_key)
                srv_path = _resolve_server_path(raw or "")

                if hklm_exists:
                    results.append(finding(
                        severity = sev,
                        message  = f"[{esc_lbl}] HKCU COM shadow exists: {clsid} overrides HKLM",
                        detail   = (
                            f"CLSID        : {clsid}\n"
                            f"HKCU key     : HKCU\\{sk_path}\n"
                            f"Server path  : {srv_path or '(empty)'}\n"
                            f"Process IL   : {il_label}\n"
                            f"Status       : HKCU takes precedence over HKLM — this entry is\n"
                            f"               actively hijacking COM activation for this CLSID.\n"
                            f"Verify       : Confirm this registration is intentional."
                        ),
                        module = MODULE_NAME,
                    ))
                elif srv_path and not os.path.isfile(srv_path):
                    results.append(finding(
                        severity = "P4",
                        message  = f"HKCU COM entry points to missing file: {clsid}",
                        detail   = (
                            f"CLSID        : {clsid}\n"
                            f"Server path  : {srv_path}  (file does not exist)\n"
                            f"HKLM entry   : None (HKCU only — no active shadow)\n"
                            f"Note         : Dangling HKCU registration. Low risk unless\n"
                            f"               an HKLM entry is later added for this CLSID."
                        ),
                        module = MODULE_NAME,
                    ))

    except Exception:
        pass

    return results


# ---------------------------------------------------------------------------
# NEW: Procmon runtime COM server load analysis
# ---------------------------------------------------------------------------
def _parse_data_path(detail: str) -> str:
    """
    Extract the binary path from a Procmon RegQueryValue Detail string.

    Detail format:  Type: REG_SZ, Length: 86, Data: C:\\ProgramData\\Vendor\\app.exe,0
    The trailing ",0" is an icon index suffix (from DisplayIcon values) and must
    be stripped.  Environment variables are expanded.  Bare filenames (no directory
    component, e.g. "wow64cpu.dll") are discarded — they resolve via the system
    loader search order, not from a fixed user-writable path.
    """
    m = re.search(r"Data:\s*(.+)", detail)
    if not m:
        return ""
    raw = m.group(1).strip().strip('"')
    
    raw = re.sub(r",\s*\d+\s*$", "", raw).strip()
    # Strip leading @ used in MUI resource references (e.g. @%SystemRoot%\...)
    raw = raw.lstrip("@")
    expanded = os.path.expandvars(raw)
    # Discard bare filenames with no path separator — not a fixed writable path
    if not os.path.dirname(expanded):
        return ""
    return expanded


def _analyze_com_server_loads(
    csv_path: str,
    target_exe_name: str,
    target_pid: Optional[int],
    auto_trigger: bool = False,
    auto_trigger_desc: str = "",
) -> List[dict]:
    """
    Detect the CVE-2025-24076 class of priv-esc from a Procmon CSV:

      A High/SYSTEM process resolves a binary path from an HKLM registry key,
      then accesses that binary via CreateFile from a directory writable by
      standard users.

    Two-pass approach:

      Pass A — RegQueryValue rows:
        Collect every registry key whose Data value resolves to a .dll or .exe
        path outside protected system roots.  This covers InprocServer32,
        LocalServer32, DisplayIcon, AppPaths, and any other HKLM mechanism a
        SYSTEM process uses to locate a binary — intentionally broader than
        CLSID-only, because the vulnerability class is about writable binary
        paths, not just COM specifically.

        Stored as: normcase(path) → (registry_key, integrity, pid)

      Pass B — CreateFile rows:
        Collect all .dll / .exe CreateFile accesses by the same process.
        Stored as: normcase(path) → (result, integrity, pid)

      Correlation:
        For each path found in Pass A, look it up in Pass B.
        - Found in Pass B with NAME NOT FOUND → phantom (plantable)
        - Found in Pass B with SUCCESS + writable dir → replaceable
        - Found only in Pass A (no CreateFile seen) → registry reference only;
          emitted as a lower-confidence advisory if dir is writable, because
          the activation may not have been triggered during the capture window.

    Writable directory check uses path_writable_by_non_admin() (AccessCheck
    via ctypes), not a naive write test.  Protected system paths are excluded
    before the AccessCheck call.
    """
    results: List[dict] = []

    target_lower = target_exe_name.lower() if target_exe_name else ""
    BINARY_EXTS  = {".dll", ".exe", ".ocx", ".ax"}

    # ── Pass A: registry-sourced binary paths ─────────────────────────────────
    # Maps normcase(resolved_path) → (registry_key_path, integrity_label, pid)
    reg_paths: Dict[str, Tuple[str, str, int]] = {}

    for row in procmon_session.parse_procmon_csv(csv_path):
        if target_lower and row.get("Process Name", "").lower() != target_lower:
            continue
        try:
            row_pid = int(row.get("PID", 0))
        except (ValueError, TypeError):
            row_pid = 0
        if target_pid and row_pid and row_pid != target_pid:
            continue
        if row.get("Operation", "").strip() != "RegQueryValue":
            continue
        if row.get("Result", "").strip() != "SUCCESS":
            continue

        csv_integrity = row.get("Integrity", "").strip()
        rid = _rid_from_label(csv_integrity)
        if rid is None or rid < _SECURITY_MANDATORY_HIGH_RID:
            continue

        bin_path = _parse_data_path(row.get("Detail", ""))
        if not bin_path:
            continue
        if os.path.splitext(bin_path)[1].lower() not in BINARY_EXTS:
            continue
        if _is_protected(bin_path):
            continue

        key = os.path.normcase(bin_path)
        if key not in reg_paths:
            reg_paths[key] = (row.get("Path", "").strip(), csv_integrity, row_pid)

    if not reg_paths:
        return results

    # ── Pass B: CreateFile accesses by the same process ───────────────────────
    # Maps normcase(path) → (result, integrity_label, pid, original_case_path)
    file_events: Dict[str, Tuple[str, str, int, str]] = {}

    for row in procmon_session.parse_procmon_csv(csv_path):
        if target_lower and row.get("Process Name", "").lower() != target_lower:
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
        if os.path.splitext(path)[1].lower() not in BINARY_EXTS:
            continue

        result        = row.get("Result", "").strip()
        csv_integrity = row.get("Integrity", "").strip()

        key = os.path.normcase(path)
        if key not in file_events:
            file_events[key] = (result, csv_integrity, row_pid, path)

    # ── Correlation and finding emission ──────────────────────────────────────
    seen: Set[str] = set()

    trigger_note = (
        f"\n    Trigger      : {auto_trigger_desc}"
        if auto_trigger_desc else
        "\n    Trigger      : User-launched (manual interaction required)"
    )

    for norm_path, (reg_key, reg_integrity, reg_pid) in reg_paths.items():
        file_event = file_events.get(norm_path)

        if file_event:
            result, file_integrity, file_pid, display_path = file_event
            # Prefer CreateFile integrity (actual load-time IL)
            csv_integrity = file_integrity or reg_integrity
            pid_display   = file_pid or reg_pid
        else:
            # Registry named this path but we never saw a CreateFile for it.
            # Either the activation wasn't triggered during capture, or the
            # process uses the path for metadata only (version check, icon).
            result        = "REGISTRY REFERENCE ONLY (no CreateFile observed in capture)"
            csv_integrity = reg_integrity
            pid_display   = reg_pid
            display_path  = norm_path

        rid = _rid_from_label(csv_integrity)
        if rid is None or rid < _SECURITY_MANDATORY_HIGH_RID:
            continue

        esc_lbl  = _esc_label(rid)
        bin_name = os.path.basename(display_path)
        bin_dir  = os.path.dirname(display_path)

        if not bin_dir:
            continue

        # Writable check — use nearest existing directory for NAME NOT FOUND
        check_dir = bin_dir
        if "NAME NOT FOUND" in result and not os.path.isdir(bin_dir):
            check_dir = os.path.dirname(bin_dir)
        if not check_dir or _is_protected(check_dir):
            continue
        if not path_writable_by_non_admin(check_dir):
            continue

        dedup_key = norm_path + "|" + result[:30]
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        if "NAME NOT FOUND" in result:
            sev = _severity_phantom(rid, auto_trigger)
            results.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] Binary path is phantom & directory writable: {bin_name}",
                detail   = (
                    f"Binary       : {display_path}\n"
                    f"Registry key : {reg_key}\n"
                    f"Result       : NAME NOT FOUND — file does not exist at this path\n"
                    f"Process IL   : {csv_integrity}  (PID {pid_display})\n"
                    f"Plant dir    : {check_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Attack       : Drop a malicious '{bin_name}' into '{check_dir}'.\n"
                    f"               The {csv_integrity} process will load it on next activation.\n"
                    f"               No existing file to displace — easiest exploit variant.\n"
                    f"               See CVE-2025-24076 for a worked example of this pattern."
                ),
                module = MODULE_NAME,
            ))

        elif result == "SUCCESS":
            if not path_writable_by_non_admin(bin_dir):
                continue
            sev = _severity_replace(rid, auto_trigger)
            results.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] Binary loaded by {csv_integrity} process from writable directory: {bin_name}",
                detail   = (
                    f"Binary       : {display_path}\n"
                    f"Registry key : {reg_key}\n"
                    f"Result       : SUCCESS — file was found and accessed\n"
                    f"Process IL   : {csv_integrity}  (PID {pid_display})\n"
                    f"Writable dir : {bin_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Attack       : Replace '{bin_name}' with a malicious proxy binary.\n"
                    f"               Export original functions to avoid crashes on load.\n"
                ),
                module = MODULE_NAME,
            ))

        elif "REGISTRY REFERENCE ONLY" in result:
            # Lower-confidence: path came from the registry but no file I/O seen.
            # Still worth reporting — the dir is writable and path is HKLM-registered.
            sev = _severity_phantom(rid, auto_trigger)
            # Downgrade by one level — not confirmed loaded in this capture
            downgrade = {"P1": "P2", "P2": "P2", "P3": "P3"}
            sev = downgrade.get(sev, sev)
            results.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] HKLM key references binary in writable directory (not confirmed loaded): {bin_name}",
                detail   = (
                    f"Binary       : {display_path}\n"
                    f"Registry key : {reg_key}\n"
                    f"Result       : No CreateFile observed — activation may not have been\n"
                    f"               triggered during the Procmon capture window.\n"
                    f"Process IL   : {csv_integrity}  (PID {pid_display})\n"
                    f"Writable dir : {check_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Next step    : Trigger the relevant application action and re-run the\n"
                    f"               capture to confirm the binary is actually loaded."
                ),
                module = MODULE_NAME,
            ))

    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run(ctx: dict) -> List[dict]:
    findings = []

    if not is_windows():
        print_warning("COM hijacking checks require Windows.")
        return findings

    try:
        import winreg  # noqa: F401
    except ImportError:
        print_warning("winreg module unavailable — COM hijacking check skipped.")
        return findings

    il_rid   = ctx.get("il_rid")
    il_label = ctx.get("il_label") or "Unknown"
    if il_rid is None:
        il_rid, il_label = _get_process_il(ctx)

    exe_path = ctx.get("exe_path")

    # ── Guard: exe_path is required for all COM analysis ─────────────────────
    # Without it we have no CLSIDs to scope to, so we would be forced to scan
    # all HKCU entries system-wide — which produces false positives unrelated
    # to the target application. Refuse to run rather than produce noise.
    if not exe_path or not os.path.isfile(exe_path):
        print_warning(
            "COM Hijacking: no valid executable path — module skipped.\n"
            "    Use --exe or --service to scope CLSID analysis to the target binary."
        )
        return findings

    # ── 1. Static registry-based checks (scoped to binary CLSIDs) ────────────
    clsids: Set[str] = set()
    print_info(f"Extracted CLSID references from binary: {exe_path}")
    clsids = _extract_clsids_from_binary(exe_path)

    if not clsids:
        pass  # Nothing to report — HKCU shadow scan will be skipped below
    else:
        print_info(f"Found {len(clsids)} CLSID reference(s) — checking HKLM registrations…")
        findings.extend(_check_clsids_against_hklm(clsids, il_rid, il_label))

    # clsid_filter_set is ALWAYS derived from the binary — never None/empty,
    # so _scan_hkcu_shadows will only check CLSIDs relevant to this target.
    # If the binary had no CLSIDs, skip HKCU scanning entirely.
    clsid_filter_set: Optional[set] = {c.lower() for c in clsids} if clsids else None

    if clsid_filter_set:
        print_info("Scanning HKCU for existing COM shadow registrations…")
        print_info(f"  Scoped to {len(clsid_filter_set)} CLSID(s) extracted from target binary.")
        findings.extend(_scan_hkcu_shadows(il_rid, il_label, clsid_filter=clsid_filter_set))

    # ── 2. Procmon runtime COM server load analysis (NEW) ─────────────────────
    procmon_exe = procmon_session.get_procmon_exe(ctx)

    if not procmon_exe or not procmon_session.capture_exists():
        if not procmon_exe:
            print_warning("Procmon not available — runtime COM server load analysis skipped.")
        else:
            print_warning("No capture.pml — runtime COM server load analysis skipped.")
    else:
        csv_path = procmon_session.export_filtered_csv(procmon_exe, "com")
        if not csv_path:
            pass  # Filter missing or no events — runtime COM analysis skipped silently
        else:
            target_name = os.path.basename(exe_path) if exe_path else ""
            given_pid   = ctx.get("launched_pid") or ctx.get("pid")

            auto_trigger, auto_trigger_desc = _is_auto_triggered(exe_path)
            if auto_trigger:
                print_info(f"Auto-trigger confirmed: {auto_trigger_desc}")
            else:
                print_info("No auto-trigger detected — Procmon COM findings capped at P2.")

            procmon_findings = _analyze_com_server_loads(
                csv_path          = csv_path,
                target_exe_name   = target_name,
                target_pid        = given_pid,
                auto_trigger      = auto_trigger,
                auto_trigger_desc = auto_trigger_desc,
            )
            findings.extend(procmon_findings)

            if procmon_findings:
                print_info(f"Procmon COM analysis: {len(procmon_findings)} finding(s).")
            else:
                print_info("Procmon COM analysis: no COM server loads from writable paths found.")

    if not findings:
        print_info("No COM hijacking vectors identified.")

    return findings
