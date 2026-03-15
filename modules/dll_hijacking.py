import os
import re
from typing import List, Optional, Set, Tuple

from .utils import (
    finding,
    print_info,
    print_warning,
    path_writable_by_non_admin,
    get_process_integrity,
    integrity_label,
    _SECURITY_MANDATORY_HIGH_RID,
    _SECURITY_MANDATORY_MEDIUM_RID,
    _SECURITY_MANDATORY_SYSTEM_RID,
    is_admin,
    _PROTECTED_PATH_PREFIXES,
    _is_protected_system_path,
    _esc_label,
    _severity_phantom as _severity_for_phantom,
    _severity_replace as _severity_for_loaded_writable,
    _rid_from_label as _rid_from_csv_label_base,
    _is_auto_triggered,
)
from . import procmon_session

MODULE_NAME = "DLL Hijacking"


# ---------------------------------------------------------------------------
# Protected system path guard
# ---------------------------------------------------------------------------
# Paths that Windows will NEVER redirect via user-writable directories.
# These are absolute, fully-qualified system locations.
_SYSROOT = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))

_PROTECTED_DLL_DIRS: Tuple[str, ...] = tuple(
    os.path.normcase(p) for p in [
        os.path.join(_SYSROOT, "System32"),
        os.path.join(_SYSROOT, "SysWOW64"),
        os.path.join(_SYSROOT, "System"),
        os.path.join(_SYSROOT, "WinSxS"),
        _SYSROOT,
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ]
)


# ---------------------------------------------------------------------------
# API Set Schema virtual DLL filter
# ---------------------------------------------------------------------------
# api-ms-* and ext-ms-* are Windows API Set Schema forwarding stubs. They are
# resolved by the Windows loader through the ApiSetSchema kernel data structure
# (a PE section in ntdll.dll), completely bypassing the normal DLL search order.
# No file named api-ms-win-core-*.dll etc. is ever loaded from disk — the loader
# silently redirects the reference to the real implementation DLL. Reporting
# these as hijackable is always a false positive.
def _is_api_set_dll(dll_name: str) -> bool:
    """Return True if the DLL name is an API Set Schema virtual DLL."""
    name = dll_name.lower()
    return name.startswith("api-ms-") or name.startswith("ext-ms-")


def _is_system_path(path: str) -> bool:
    """
    Return True if the path is inside a Windows system directory.
    DLLs attempted from these locations cannot be hijacked by planting
    files in a user-writable directory — Windows loads them directly.

    IMPORTANT: do NOT call os.path.abspath() on these paths.  Procmon CSV
    paths are already fully-qualified Windows absolute paths.  Calling
    abspath() on a non-Windows host prepends the Linux CWD and produces
    paths like '/C:\\Windows\\...' that never match any prefix, causing
    every system path to pass this guard and appear vulnerable.

    Uses a backslash-terminated prefix match so that C:\\WindowsApps\\
    is not mistaken for being inside C:\\Windows\\.
    """
    norm = os.path.normcase(path) if path else ""
    return any(
        norm.startswith(p + "\\") or norm.startswith(p + "/") or norm == p
        for p in _PROTECTED_DLL_DIRS
    )


def _dir_is_system_path(directory: str) -> bool:
    """Same guard for directory strings.  No abspath() — normcase only."""
    norm = os.path.normcase(directory) if directory else ""
    return any(
        norm.startswith(p + "\\") or norm.startswith(p + "/") or norm == p
        for p in _PROTECTED_DLL_DIRS
    )


# ---------------------------------------------------------------------------
# KnownDLLs — Windows-protected DLLs that bypass the search order
# ---------------------------------------------------------------------------
def _get_known_dlls() -> Set[str]:
    """
    Return the set of DLL names protected by the Windows KnownDLLs mechanism.

    KnownDLLs are pre-mapped by the Session Manager as named kernel sections
    at boot time. When a process loads a DLL whose name appears in this set,
    the loader satisfies the request directly from the existing kernel section —
    the filesystem search order is never consulted. Planting a file with the
    same name in a writable directory has no effect on KnownDLL resolution.

    Primary source: the live registry key. The hard-coded fallback covers the
    canonical Windows 10/11 KnownDLLs in case the key is inaccessible (e.g.
    running without registry read access or on a non-Windows host for testing).

    Deliberately excluded from the fallback (NOT actual KnownDLLs — can be
    hijacked if Procmon shows them searched in a user-writable directory):
      version.dll, ws2_32.dll, crypt32.dll, ucrtbase.dll, gdi32full.dll,
      msvcp_win.dll, win32u.dll, combase.dll, shcore.dll, uxtheme.dll,
      msimg32.dll, mpr.dll, winhttp.dll, wldp.dll, netapi32.dll,
      netutils.dll, windowscodecs.dll
    """
    known: Set[str] = set()
    registry_loaded = False

    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        ) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                    i += 1
                    # Only value entries that point at .dll files are DLL names;
                    # the "DllDirectory" value (a path) is intentionally skipped.
                    if isinstance(value, str) and value.lower().endswith(".dll"):
                        known.add(value.lower())
                except OSError:
                    break
        registry_loaded = bool(known)
    except Exception:
        pass

    if not registry_loaded:
        # Hard-coded fallback — confirmed KnownDLLs on Windows 10/11 (all builds).
        known |= {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
            "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "user32.dll",
            "msvcrt.dll", "sechost.dll", "shell32.dll", "gdi32.dll", "shlwapi.dll",
            "imm32.dll", "comctl32.dll", "comdlg32.dll", "msctf.dll",
            "normaliz.dll", "setupapi.dll",
        }

    return known


KNOWN_DLLS: Set[str] = set()


# ---------------------------------------------------------------------------
# Integrity helpers
# ---------------------------------------------------------------------------
def _rid_from_csv_label(label: str) -> Optional[int]:
    """Map a Procmon CSV integrity label to a RID integer."""
    return _rid_from_csv_label_base(label)


def _get_integrity_safe(pid: Optional[int]) -> Tuple[Optional[int], str]:
    rid = get_process_integrity(pid) if pid else None
    if rid is None and is_admin():
        rid = _SECURITY_MANDATORY_HIGH_RID
    return rid, integrity_label(rid)


# ---------------------------------------------------------------------------
# Downloads path detection
# ---------------------------------------------------------------------------
# Downloads path detection
# ---------------------------------------------------------------------------
def _downloads_dir() -> Optional[str]:
    """Return the current user's Downloads directory path."""
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        d = os.path.join(userprofile, "Downloads")
        if os.path.isdir(d):
            return d
    return None


_USERS_DOWNLOADS_RE = re.compile(
    r"(?i)C:\\Users\\[^\\]+\\Downloads\\"
)


def _is_downloads_path(path: str) -> bool:
    return bool(_USERS_DOWNLOADS_RE.match(path))


# ---------------------------------------------------------------------------
# Writable directory check (no walk-up for phantom DLLs)
# ---------------------------------------------------------------------------
def _exact_dir_writable(dll_path: str) -> Optional[str]:
    """
    For phantom DLL (NAME NOT FOUND): check only the EXACT directory that
    was searched.  Do NOT walk up — we need the attacker to be able to
    write a file at precisely that path, not some parent directory.
    """
    dll_dir = os.path.dirname(dll_path)
    if not dll_dir:
        return None
    if _dir_is_system_path(dll_dir):
        return None
    # Directory may not exist yet (phantom) — check the nearest existing parent
    check = dll_dir
    if not os.path.isdir(check):
        # If the directory itself doesn't exist, the parent must be writable
        # AND the attacker must be able to create the subdirectory
        parent = os.path.dirname(check)
        if os.path.isdir(parent) and path_writable_by_non_admin(parent) and not _dir_is_system_path(parent):
            return parent
        return None
    if path_writable_by_non_admin(check):
        return check
    return None


def _writable_dir_with_walkup(dll_path: str) -> Optional[str]:
    """
    For loaded DLL (SUCCESS): find nearest writable directory at or above
    the DLL's location — this identifies intercept / replacement opportunities.
    """
    dll_dir = os.path.dirname(dll_path)
    cur = dll_dir
    while cur:
        if _dir_is_system_path(cur):
            return None  # Never report system dirs as intercept points
        if os.path.isdir(cur) and path_writable_by_non_admin(cur):
            return cur
        par = os.path.dirname(cur)
        if par == cur:
            break
        cur = par
    return None


# ---------------------------------------------------------------------------
# CSV analysis (Procmon path)
# ---------------------------------------------------------------------------
def _analyze_csv(
    csv_path: str,
    target_exe_name: str,
    target_pid: Optional[int],
    exe_path: Optional[str],
    known_dlls: Set[str],
    integrity_rid: Optional[int],
    integrity_lbl: str,
    auto_trigger: bool = False,
    auto_trigger_desc: str = "",
) -> List[dict]:
    """
    Parse dll_capture.csv. Apply gate logic per row. Return structured findings.

    Gates applied per row (in order):
      1. Process / PID filter
      2. Operation must be CreateFile, path must end with .dll
      3. Skip API Set Schema virtual DLLs (api-ms-*, ext-ms-*)
      4. Skip Windows KnownDLLs (resolved from kernel sections, not disk)
      5. Skip protected system paths
      6. Writable directory check (AccessCheck)
      7. Integrity-aware severity assignment

    Columns used: Process Name, PID, Operation, Path, Result, Integrity
    """
    findings: List[dict] = []
    seen: Set[Tuple[str, str]] = set()
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
        if not path.lower().endswith(".dll"):
            continue

        dll_name = os.path.basename(path).lower()

        # ── Gate: API Set Schema virtual DLLs ────────────────────────────────
        # These are resolved by the loader via the ApiSetSchema kernel data
        # structure — never through the filesystem search order. Cannot be
        # hijacked by planting a file on disk regardless of directory ACLs.
        if _is_api_set_dll(dll_name):
            continue

        # ── Gate: KnownDLLs ──────────────────────────────────────────────────
        # Pre-mapped as named kernel sections at boot. The filesystem search
        # order is bypassed entirely for these DLLs.
        if dll_name in known_dlls:
            continue

        result  = row.get("Result", "").strip()
        key     = (os.path.normcase(path), result)
        if key in seen:
            continue
        seen.add(key)

        # ── Gate 1: Protected path guard ─────────────────────────────────────
        # The attempted load path must not be inside a system directory.
        if _is_system_path(path):
            continue

        # ── Integrity resolution (prefer CSV column, fall back to token read) ─
        csv_integrity = row.get("Integrity", "").strip()
        eff_rid   = integrity_rid
        eff_label = integrity_lbl
        if csv_integrity:
            csv_rid = _rid_from_csv_label(csv_integrity)
            if csv_rid is not None:
                eff_rid   = csv_rid
                eff_label = csv_integrity

        esc_lbl   = _esc_label(eff_rid)

        # ── Downloads drive-by detection ─────────────────────────────────────
        if "NAME NOT FOUND" in result and _is_downloads_path(path):
            # Downloads is always writable by the current user — no AccessCheck needed.
            exe_in_downloads = bool(exe_path and _is_downloads_path(exe_path))
            if exe_in_downloads:
                sev      = "P1" if (eff_rid or 0) >= _SECURITY_MANDATORY_HIGH_RID else "P2"
                vtype    = "Drive-By Download DLL Hijack (RCE)"
                scenario = (
                    f"The target executable itself is in Downloads. An attacker delivers\n"
                    f"    a malicious {dll_name} via a browser download to the same directory.\n"
                    f"    When the victim runs the application, the attacker's DLL is loaded."
                )
            else:
                sev   = "P2"
                vtype = "DLL Search Order Includes Downloads Directory"
                scenario = (
                    f"A process outside Downloads is searching for {dll_name} inside the\n"
                    f"    Downloads directory. Unusual — indicates abnormal search path exposure.\n"
                    f"    An attacker can place a malicious DLL in Downloads without admin rights."
                )

            findings.append(finding(
                severity = sev,
                message  = f"[{vtype}] {dll_name}",
                detail   = (
                    f"DLL          : {dll_name}\n"
                    f"Attempted at : {path}\n"
                    f"Result       : NAME NOT FOUND (file does not exist — plantable)\n"
                    f"Process IL   : {eff_label}  (PID {row_pid})\n"
                    f"Attack vector: Drive-by download — attacker delivers DLL via browser\n"
                    f"    {scenario}\n"
                    f"Attack step  : Place malicious {dll_name} at: {path}"
                ),
                module = MODULE_NAME,
            ))
            continue  # Handled as downloads finding, do not double-report below

        # ── Gate 2: NAME NOT FOUND — phantom DLL ─────────────────────────────
        if "NAME NOT FOUND" in result:
            writable_dir = _exact_dir_writable(path)
            if not writable_dir:
                continue

            sev = _severity_for_phantom(eff_rid, auto_trigger)
            trigger_note = (
                f"\n    Trigger      : {auto_trigger_desc}"
                if auto_trigger_desc else
                "\n    Trigger      : User-launched (manual execution required → P2)"
            )
            findings.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] Phantom DLL: {dll_name}",
                detail   = (
                    f"DLL          : {dll_name}\n"
                    f"Attempted at : {path}\n"
                    f"Result       : NAME NOT FOUND — file does not exist at this path\n"
                    f"Process IL   : {eff_label}  (PID {row_pid})\n"
                    f"Plant dir    : {writable_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Attack       : Drop malicious {dll_name} into '{writable_dir}'.\n"
                    f"               It will be loaded on the next application execution."
                ),
                module = MODULE_NAME,
            ))

        # ── Gate 3: SUCCESS — DLL loaded from potentially writable location ───
        elif result == "SUCCESS":
            writable_dir = _writable_dir_with_walkup(path)
            if not writable_dir:
                continue

            sev = _severity_for_loaded_writable(eff_rid, auto_trigger)
            trigger_note = (
                f"\n    Trigger      : {auto_trigger_desc}"
                if auto_trigger_desc else
                "\n    Trigger      : User-launched (manual execution required)"
            )
            findings.append(finding(
                severity = sev,
                message  = f"[{esc_lbl}] DLL loaded from writable directory: {dll_name}",
                detail   = (
                    f"DLL          : {dll_name}\n"
                    f"Loaded from  : {path}\n"
                    f"Result       : SUCCESS — DLL was loaded\n"
                    f"Process IL   : {eff_label}  (PID {row_pid})\n"
                    f"Writable dir : {writable_dir}  ← writable by standard users (AccessCheck)"
                    f"{trigger_note}\n"
                    f"Attack       : Replace '{path}' with a malicious version before the\n"
                    f"               application loads it."
                ),
                module = MODULE_NAME,
            ))

    return findings


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def analyze(ctx: dict, procmon_exe: Optional[str], known_dlls: Set[str]) -> List[dict]:
    findings:  List[dict] = []
    exe_path   = ctx.get("exe_path")
    given_pid  = ctx.get("launched_pid") or ctx.get("pid")

    if not exe_path and not given_pid:
        print_warning("No executable or PID — DLL hijacking check skipped.")
        return findings

    integrity_rid = ctx.get("il_rid")
    label         = ctx.get("il_label") or "Unknown"
    if integrity_rid is None:
        # Fall back to live query if ctx wasn't populated (e.g. module run standalone)
        integrity_rid, label = _get_integrity_safe(given_pid)

    # ── P1 gate: determine whether this process is auto-triggered ─────────────
    auto_trigger, auto_trigger_desc = _is_auto_triggered(exe_path)
    if auto_trigger:
        print_info(f"Auto-trigger confirmed: {auto_trigger_desc} — P1 classification eligible.")
    else:
        print_info("No auto-trigger detected (user-launched) — findings capped at P2.")

    if not procmon_exe or not procmon_session.capture_exists():
        if not procmon_exe:
            print_warning("Procmon not available — DLL hijacking runtime analysis skipped.")
        else:
            print_warning("No capture.pml — DLL hijacking runtime analysis skipped.")
        print_info("No DLL hijacking vectors found.")
        return findings

    csv_path = procmon_session.export_filtered_csv(procmon_exe, "dll")
    if not csv_path:
        print_info("No DLL hijacking vectors found.")
        return findings

    target_name = os.path.basename(exe_path) if exe_path else ""
    procmon_findings = _analyze_csv(
        csv_path          = csv_path,
        target_exe_name   = target_name,
        target_pid        = given_pid,
        exe_path          = exe_path,
        known_dlls        = known_dlls,
        integrity_rid     = integrity_rid,
        integrity_lbl     = label,
        auto_trigger      = auto_trigger,
        auto_trigger_desc = auto_trigger_desc,
    )
    findings.extend(procmon_findings)
    print_info(f"Procmon DLL analysis: {len(procmon_findings)} finding(s).")

    if not findings:
        print_info("No DLL hijacking vectors found.")

    return findings


def run(ctx: dict) -> List[dict]:
    """Module dispatch entry point."""
    global KNOWN_DLLS
    if not KNOWN_DLLS:
        KNOWN_DLLS = _get_known_dlls()
    procmon_exe = procmon_session.get_procmon_exe(ctx)
    return analyze(ctx, procmon_exe, KNOWN_DLLS)
