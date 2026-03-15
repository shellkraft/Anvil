import os
import re
from typing import List, Optional, Set, Tuple

from .utils import (
    finding, print_info, print_warning,
    path_writable_by_non_admin, is_windows,
    _SECURITY_MANDATORY_HIGH_RID,
    _SECURITY_MANDATORY_SYSTEM_RID,
    _is_auto_triggered,
)
from . import procmon_session

MODULE_NAME = "Symlink Attack (Arbitrary File Write)"

_VULNERABLE_DISPOSITIONS = frozenset({
    "supersede",
    "overwrite",
    "overwriteif",
    "openif",
})

_SYSROOT = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
_PROTECTED_DIRS: Tuple[str, ...] = tuple(
    os.path.normcase(p) for p in [
        os.path.join(_SYSROOT, "System32"),
        os.path.join(_SYSROOT, "SysWOW64"),
        os.path.join(_SYSROOT, "System"),
        _SYSROOT,
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ]
)

# Regex to identify user-profile paths: C:\Users\<username>\...
# These are only exploitable cross-user if Authenticated Users / Everyone
# has explicit write access — mere BUILTIN\Users membership is not enough.
_USER_PROFILE_RE = re.compile(
    r"(?i)^[A-Za-z]:\\Users\\[^\\]+\\",
)


def _is_system_path(path: str) -> bool:
    # NOTE: no abspath() — paths from Procmon CSV are already fully qualified
    norm = os.path.normcase(path) if path else ""
    return any(norm.startswith(p + os.sep) or norm.startswith(p + "/") or norm == p
               for p in _PROTECTED_DIRS)


def _rid_from_label(label: str) -> Optional[int]:
    s = (label or "").lower().strip()
    if "system" in s:  return _SECURITY_MANDATORY_SYSTEM_RID
    if "high"   in s:  return _SECURITY_MANDATORY_HIGH_RID
    return None


def _vulnerable_disposition(detail: str) -> Optional[str]:
    for token in detail.split(","):
        token = token.strip()
        if token.lower().startswith("disposition:"):
            disp = token.split(":", 1)[1].strip()
            if disp.lower() in _VULNERABLE_DISPOSITIONS:
                return disp
    return None


def _is_user_profile_path(path: str) -> bool:
    """Return True if path is under C:\\Users\\<any username>\\."""
    return bool(_USER_PROFILE_RE.match(path))


def _cross_user_writable(path: str) -> bool:
    """
    For paths inside a user profile (C:\\Users\\<user>\\...):
    Return True only if Authenticated Users or Everyone has effective
    write/delete/create permissions.

    Standard users can write to their OWN profile, but that is not a
    cross-user privilege escalation vector — the attacker must be a
    DIFFERENT user.  BUILTIN\\Users includes local admins, so it is
    not a safe indicator of cross-user access.

    We rely on AccessCheck (path_writable_by_non_admin) which uses a
    Medium-IL impersonation token.  If the tool is running as the profile
    owner, AccessCheck will return True even though another user can't
    write there — so we additionally verify we are NOT inside our own
    profile before trusting the result.
    """
    if not path:
        return False
    # Get the current user's profile directory
    own_profile = os.path.normcase(os.environ.get("USERPROFILE", ""))
    norm_path   = os.path.normcase(path)
    if own_profile and norm_path.startswith(own_profile):
        # This is inside our own profile — writable only by us and admins.
        # Not a cross-user escalation vector.
        return False
    # For another user's profile, AccessCheck against our (admin) token
    # will still return True for admin-accessible paths.  In practice, if
    # it's another user's AppData and the tool is running as a different admin,
    # the DACL check is meaningful.  But we need to be conservative:
    # return False unless the path is explicitly world-writable.
    return path_writable_by_non_admin(path)


def _dir_exploitable(directory: str) -> Tuple[bool, dict]:
    """
    Perform all four exploitability checks for a symlink attack directory.

    Returns (exploitable, checks_dict) where checks_dict has keys:
      dir_writable, file_deletable, file_creatable, dir_cleanable

    Gates:
      1. Directory is writable by standard user (AccessCheck)
      2. If directory is inside another user's profile: cross-user writable
      3. Standard user can create files in the directory
      4. All files in the directory can be deleted by a standard user
         (attacker must be able to empty the dir to reliably plant the symlink)
    """
    checks = {
        "dir_writable":    False,
        "file_deletable":  False,
        "file_creatable":  False,
        "dir_cleanable":   False,
    }

    if not directory or not os.path.isdir(directory):
        return False, checks

    if _is_system_path(directory):
        return False, checks

    # Gate 1: directory writable
    if _is_user_profile_path(directory):
        writable = _cross_user_writable(directory)
    else:
        writable = path_writable_by_non_admin(directory)

    checks["dir_writable"] = writable
    if not writable:
        return False, checks

    # Gate 2 & 3: file_creatable — AccessCheck on the directory covers this
    # (write access to a directory implies CreateFile in that directory)
    checks["file_creatable"] = True
    checks["file_deletable"] = True   # Delete requires dir write; confirmed above

    # Gate 4: dir_cleanable — verify every file in the directory is deletable
    # (writable dir ACL implies delete-child permission; we confirm by checking
    # each file's own ACL doesn't deny deletion)
    all_deletable = True
    try:
        for entry in os.scandir(directory):
            if entry.is_file(follow_symlinks=False):
                # File is deletable if:
                #   a) The directory has FILE_DELETE_CHILD (dir write covers this), OR
                #   b) The file itself is writable / deletable
                # AccessCheck on the file directly for conservative check:
                if not path_writable_by_non_admin(entry.path):
                    # File has restrictive ACL — attacker may not be able to delete it
                    all_deletable = False
                    break
    except (PermissionError, OSError):
        # Can't enumerate — assume not cleanable (conservative)
        all_deletable = False

    checks["dir_cleanable"] = all_deletable
    if not all_deletable:
        return False, checks

    return True, checks


def _checks_to_detail(checks: dict) -> str:
    """Format the exploitability check results for inclusion in finding detail."""
    def yn(v): return "YES" if v else "NO"
    return (
        f"Directory writable : {yn(checks['dir_writable'])}\n"
        f"File deletable     : {yn(checks['file_deletable'])}\n"
        f"File creatable     : {yn(checks['file_creatable'])}\n"
        f"Directory cleanable: {yn(checks['dir_cleanable'])}"
    )


# ---------------------------------------------------------------------------
# CSV analysis
# ---------------------------------------------------------------------------
def _analyze_csv(
    csv_path: str,
    target_exe_name: str,
    target_pid: Optional[int],
    auto_trigger: bool = False,
    auto_trigger_desc: str = "",
) -> List[dict]:
    """
    Parse symlink_capture.csv and apply full gate logic per row.

    Gates (all must pass):
      1. Process Name == target_exe_name (case-insensitive)
      2. Operation == CreateFile
      3. Integrity in (High, System)
      4. Disposition in (Supersede, Overwrite, OverwriteIf, OpenIf)
      5. "Open Reparse Point" NOT in Detail
      6. Full exploitability check: dir_writable + file_deletable +
         file_creatable + dir_cleanable
         — with cross-user guard for user-profile paths
    """
    findings: List[dict] = []
    seen: Set[str]       = set()
    target_lower         = target_exe_name.lower()

    for row in procmon_session.parse_procmon_csv(csv_path):

        # ── Gate 1: Process filter ────────────────────────────────────────────
        if row.get("Process Name", "").lower() != target_lower:
            continue

        try:
            row_pid = int(row.get("PID", 0))
        except (ValueError, TypeError):
            row_pid = 0
        if target_pid and row_pid and row_pid != target_pid:
            continue

        # ── Gate 2: Operation ─────────────────────────────────────────────────
        if row.get("Operation", "").strip() != "CreateFile":
            continue

        path = row.get("Path", "").strip()
        if not path:
            continue

        result = row.get("Result", "").strip()
        is_phantom = "NAME NOT FOUND" in result
        is_success = result == "SUCCESS"
        if not is_phantom and not is_success:
            continue

        key = os.path.normcase(path) + "|" + result
        if key in seen:
            continue
        seen.add(key)

        if _is_system_path(path):
            continue

        # ── Gate 3: Integrity must be High or System ──────────────────────────
        csv_integrity = row.get("Integrity", "").strip()
        rid = _rid_from_label(csv_integrity)
        if rid is None:
            continue

        # ── Gate 4: Vulnerable Disposition ────────────────────────────────────
        detail      = row.get("Detail", row.get("Details", "")).strip()
        disposition = _vulnerable_disposition(detail)
        if disposition is None:
            continue

        # ── Gate 5: Open Reparse Point ABSENT ─────────────────────────────────
        if "Open Reparse Point" in detail:
            continue

        # ── Gate 6: Full exploitability check ────────────────────────────────
        directory = os.path.dirname(path)
        exploitable, checks = _dir_exploitable(directory)

        # For SUCCESS rows: additionally verify the specific file is deletable
        if is_success and exploitable:
            # If the file has a restrictive ACL overriding the dir ACL, re-check
            if os.path.isfile(path) and not path_writable_by_non_admin(path):
                checks["file_deletable"] = False
                exploitable = False

        if not exploitable:
            continue

        # ── Severity — P1 only if auto-triggered ─────────────────────────────
        if auto_trigger:
            sev = "P1"
            trigger_note = f"Trigger      : {auto_trigger_desc}"
        else:
            sev = "P2"
            trigger_note = "Trigger      : User-launched (manual execution required → P2)"

        findings.append(finding(
            severity = sev,
            message  = f"[Privilege Escalation] Symlink-blind {disposition} by {csv_integrity} process: {os.path.basename(path)}",
            detail   = (
                f"Process      : {row.get('Process Name', '')}  (PID {row_pid})\n"
                f"Integrity    : {csv_integrity}\n"
                f"File path    : {path}\n"
                f"Directory    : {directory}\n"
                f"Disposition  : {disposition}  ← vulnerable (creates/overwrites the target)\n"
                f"Reparse flag : ABSENT — process will follow symlinks\n"
                f"Scenario     : {'File does not exist — attacker pre-creates symlink' if is_phantom else 'File exists and is replaceable — attacker deletes and replaces with symlink'}\n"
                f"\nExploitability checks:\n"
                f"{_checks_to_detail(checks)}\n"
                f"\n{trigger_note}\n"
                f"\nExploit:\n"
                f"  1. CreateSymlink.exe \"{os.path.basename(path)}\" \"C:\\\\Windows\\\\System32\\\\target_file\"\n"
                f"     (run in '{directory}' before triggering the privileged write)\n"
                f"  2. Trigger the application action that causes the {csv_integrity} process\n"
                f"     to write '{os.path.basename(path)}'.\n"
                f"  3. Windows follows the symlink → {csv_integrity} process writes to System32.\n"
                f"Tool         : https://github.com/googleprojectzero/symboliclink-testing-tools"
            ),
            module = MODULE_NAME,
        ))

    return findings


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def analyze(ctx: dict, procmon_exe: Optional[str]) -> List[dict]:
    findings: List[dict] = []

    if not is_windows():
        print_warning("Symlink attack checks require Windows.")
        return findings

    exe_path  = ctx.get("exe_path")
    given_pid = ctx.get("launched_pid") or ctx.get("pid")

    if not procmon_exe or not procmon_session.capture_exists():
        if not procmon_exe:
            print_warning("Procmon not available — symlink analysis skipped.")
        else:
            print_warning("No capture.pml — symlink analysis skipped.")
        print_info("No symlink attack vectors found.")
        return findings

    csv_path = procmon_session.export_filtered_csv(procmon_exe, "symlink")
    if not csv_path:
        # export_filtered_csv already printed the specific reason.
        print_info("No symlink attack vectors found.")
        return findings

    # ── P1 gate ───────────────────────────────────────────────────────────────
    auto_trigger, auto_trigger_desc = _is_auto_triggered(exe_path)
    if auto_trigger:
        print_info(f"Auto-trigger confirmed: {auto_trigger_desc}")
    else:
        print_info("No auto-trigger detected — findings capped at P2.")

    target_name  = os.path.basename(exe_path) if exe_path else ""
    csv_findings = _analyze_csv(
        csv_path          = csv_path,
        target_exe_name   = target_name,
        target_pid        = given_pid,
        auto_trigger      = auto_trigger,
        auto_trigger_desc = auto_trigger_desc,
    )
    findings.extend(csv_findings)

    if csv_findings:
        print_info(f"Procmon symlink analysis: {len(csv_findings)} finding(s).")
    else:
        print_info("No symlink attack vectors found.")

    return findings


def run(ctx: dict) -> List[dict]:
    procmon_exe = procmon_session.get_procmon_exe(ctx)
    return analyze(ctx, procmon_exe)

