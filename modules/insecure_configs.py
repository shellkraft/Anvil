import os
from typing import List, Optional, Set, Tuple

from .utils import (
    finding, print_info, print_warning,
    path_writable_by_non_admin,
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

MODULE_NAME = "Insecure Configuration Files"

CONFIG_EXTENSIONS: Set[str] = {
    ".ini", ".conf", ".cfg", ".config", ".xml", ".json",
    ".yaml", ".yml", ".toml", ".properties", ".env",
    ".bat", ".cmd", ".reg",
}

# ---------------------------------------------------------------------------
# High-risk config watchlist
# ---------------------------------------------------------------------------
# These filenames are known to support dynamic module/engine/plugin/driver
# loading.  A writable or plantable instance is substantially more dangerous
# than a generic config because an attacker can use it to force DLL execution
# without replacing any binary.
HIGH_RISK_CONFIG_NAMES: Set[str] = {
    "openssl.cnf",       # OpenSSL: engine/provider loading via ENGINE_load_*
    "openssl.cfg",       # Alternative OpenSSL config extension
    "wrapper.conf",      # Java Service Wrapper: wrapper.java.additional, lib paths
    "log4j2.xml",        # Log4j2: JNDILookup, custom appenders, plugin classpath
    "log4j.properties",  # Log4j 1.x: custom appender class loading
    "java.security",     # JVM security policy: security.provider.N class loading
    "php.ini",           # PHP: extension=, zend_extension= — direct .so/.dll load
    "my.cnf",            # MySQL/MariaDB: plugin-load, plugin_dir
    "my.ini",            # MySQL/MariaDB on Windows (same semantics as my.cnf)
    "httpd.conf",        # Apache HTTPD: LoadModule directive
    "nginx.conf",        # nginx: load_module directive
    "sshd_config",       # OpenSSH: AuthorizedKeysCommand, ForceCommand
}

# Human-readable description of why each family is dangerous.
# Used in the finding detail line. Falls back to a generic note if not listed.
_HIGH_RISK_REASON: dict = {
    "openssl.cnf":      "supports ENGINE/provider loading — can force arbitrary DLL execution",
    "openssl.cfg":      "supports ENGINE/provider loading — can force arbitrary DLL execution",
    "wrapper.conf":     "Java Service Wrapper — controls JVM lib path and native library loading",
    "log4j2.xml":       "Log4j2 — custom plugin classpath and JNDI lookup (CVE-2021-44228 family)",
    "log4j.properties": "Log4j 1.x — custom appender class loading via ClassLoader",
    "java.security":    "JVM security provider list — controls cryptographic module class loading",
    "php.ini":          "PHP — extension= and zend_extension= load shared libraries directly",
    "my.cnf":           "MySQL/MariaDB — plugin-load and plugin_dir control native plugin loading",
    "my.ini":           "MySQL/MariaDB — plugin-load and plugin_dir control native plugin loading",
    "httpd.conf":       "Apache HTTPD — LoadModule loads arbitrary shared objects",
    "nginx.conf":       "nginx — load_module directive loads arbitrary shared objects",
    "sshd_config":      "OpenSSH — AuthorizedKeysCommand / ForceCommand / subsystem execution",
}

# ---------------------------------------------------------------------------
# Dangerous content keywords
# ---------------------------------------------------------------------------
# These keywords inside a config file indicate dynamic module loading
# directives.  Their presence means that a malicious replacement or plant
# could cause immediate DLL/shared-object execution by the High/System process.
DANGEROUS_CONFIG_KEYS: Set[str] = {
    "engine",
    "provider",
    "plugin",
    "module",
    "dynamic_path",
    "load_module",
    "driver",
    "library",
    "extension",
    "zend_extension",   # PHP-specific — loads a Zend engine extension (.so/.dll)
    "loadmodule",       # Apache httpd — case-insensitive alias
    "plugin-load",      # MySQL/MariaDB
    "plugin_load",      # MySQL/MariaDB (underscore variant)
    "jndi",             # Log4j JNDI lookup
    "classpath",        # Java classpath manipulation
    "authorizedkeyscommand",  # sshd — arbitrary command execution
    "forcecommand",           # sshd — arbitrary command execution
}


# ---------------------------------------------------------------------------
# Severity model for config findings
# ---------------------------------------------------------------------------
# Generic configs start at P4 — a writable config is weak hygiene, but
# without evidence the process parses it for executable directives it is NOT
# a privilege escalation vector.  The [Privilege escalation] label is reserved
# for genuinely dangerous configs (HIGH_RISK_CONFIG_NAMES or confirmed dynamic
# loading keywords in the file content).
#
# Escalation signals:
#   Signal A — filename is in HIGH_RISK_CONFIG_NAMES
#   Signal B — file content contains DANGEROUS_CONFIG_KEYS keywords (SUCCESS only)
#
#   0 signals → P4  (weak hygiene — interesting but not exploitable as-is)
#   1 signal  → P3  (probable avenue for tampering; exploitability uncertain)
#   2 signals → P2  (confirmed code-execution pathway; user ceiling without auto-trigger)
#   auto-trigger + 2 signals → P1  (persistent, no-interaction-required priv esc)

def _base_severity(rid: Optional[int], auto_trigger: bool) -> str:
    """
    Return the base severity for a generic (non-escalated) config finding.
    P4 is the floor — a writable/plantable config is not a priv-esc vector
    by itself.  Only HIGH_RISK_CONFIG_NAMES or dangerous content keywords
    justify a higher starting point.
    """
    return "P4"


def _apply_escalation(sev: str, signals: int, auto_trigger: bool) -> str:
    """
    Escalate `sev` by `signals` steps, respecting the auto-trigger ceiling.

    Each confirmed signal (high-risk filename, dangerous content keywords)
    adds one severity step.  The maximum reachable severity is P1 only when
    auto_trigger is True; otherwise P2 is the ceiling (user must interact).

      signals=0: no change         (P4 stays P4)
      signals=1: P4→P3             (possible avenue for tampering)
      signals=2: P4→P2 (user) / P4→P1 (auto-trigger)
    """
    _ORDER = ["P5", "P4", "P3", "P2", "P1"]
    ceiling = "P1" if auto_trigger else "P2"

    try:
        idx = _ORDER.index(sev.upper())
    except ValueError:
        return sev

    escalated_idx = min(idx + signals, _ORDER.index(ceiling))
    return _ORDER[escalated_idx]


# ---------------------------------------------------------------------------
# Content inspection (best-effort, read-only)
# ---------------------------------------------------------------------------
def _scan_config_content(path: str) -> List[str]:
    """
    Read the config file at `path` and return a sorted list of any
    DANGEROUS_CONFIG_KEYS keywords found in it (case-insensitive).

    Returns an empty list if the file cannot be read for any reason —
    this is purely opportunistic enrichment and must never cause the
    finding to be skipped or the module to raise.

    Only called when Procmon reported SUCCESS (file exists and was opened).
    Reads at most 512 KB to avoid large performance penalties on unexpectedly
    large files (e.g. a binary misidentified by extension).
    """
    MAX_READ_BYTES = 512 * 1024
    found: List[str] = []
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_READ_BYTES)
        # Decode permissively — config files may be UTF-8, Latin-1, or ASCII.
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")
        text_lower = text.lower()
        for kw in DANGEROUS_CONFIG_KEYS:
            if kw in text_lower:
                found.append(kw)
    except Exception:
        pass   # Permission denied, file locked, encoding error — all silently ignored
    return sorted(found)


def _is_system_path(path: str) -> bool:
    """Delegate to the centralised protected-path guard (Procmon path — no abspath)."""
    return _is_protected_system_path(path, from_procmon=True)


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
    findings: List[dict] = []
    seen: Set[str]       = set()
    target_lower         = target_exe_name.lower()

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
        if not path:
            continue

        # ── Config extension filter ───────────────────────────────────────────
        ext = os.path.splitext(path)[1].lower()
        if ext not in CONFIG_EXTENSIONS:
            continue

        result = row.get("Result", "").strip()

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

        # ── Gate 3: Directory writable by non-admin ───────────────────────────
        cfg_dir = os.path.dirname(path)
        if not cfg_dir or _is_system_path(cfg_dir):
            continue

        # For NAME NOT FOUND: check exact dir or nearest existing parent
        check_dir = cfg_dir
        if "NAME NOT FOUND" in result and not os.path.isdir(cfg_dir):
            check_dir = os.path.dirname(cfg_dir)
        if not check_dir or not path_writable_by_non_admin(check_dir):
            continue

        cfg_name       = os.path.basename(path)
        cfg_name_lower = cfg_name.lower()

        # ── High-risk config detection ────────────────────────────────────────
        is_high_risk   = cfg_name_lower in HIGH_RISK_CONFIG_NAMES
        high_risk_note = ""
        if is_high_risk:
            reason         = _HIGH_RISK_REASON.get(cfg_name_lower, "supports dynamic module loading")
            high_risk_note = f"High-risk config : {cfg_name} ({reason})\n    "

        # ── Content inspection (SUCCESS + file exists and is accessible) ──────
        # Only attempted when Procmon confirmed the file was successfully opened.
        # Never attempted for phantom configs — the file does not exist yet.
        dynamic_note = ""
        if result == "SUCCESS" and os.path.isfile(path):
            matched_keys = _scan_config_content(path)
            if matched_keys:
                kw_sample    = "/".join(matched_keys[:5])
                dynamic_note = (
                    f"Dynamic loading  : Config contains dynamic module loading directives "
                    f"({kw_sample})\n    "
                )

        # ── Severity: base P3, escalate per confirmed signal ─────────────────
        # Signal A: filename is in the high-risk watchlist
        # Signal B: file content contains dynamic module loading keywords
        # (B is only evaluated for SUCCESS — phantom configs don't exist yet)
        # Each confirmed signal adds one step; ceiling is P2 without
        # auto-trigger, P1 with auto-trigger.
        signals = (1 if is_high_risk else 0) + (1 if dynamic_note else 0)

        if "NAME NOT FOUND" in result:
            sev = _apply_escalation(_base_severity(rid, auto_trigger), signals, auto_trigger)
            trigger_note = (
                f"\n    Trigger      : {auto_trigger_desc}"
                if auto_trigger_desc else
                "\n    Trigger      : User-launched (manual execution required)"
            )
            # Only attach the priv-esc label when there is a confirmed vector
            if signals >= 1:
                msg_prefix = f"[{esc_lbl}] "
                msg_tag    = "Confirmed code-execution pathway" if signals >= 2 else "Probable tampering avenue"
            else:
                msg_prefix = ""
                msg_tag    = "Writable path — exploitability unconfirmed (no high-risk signals)"
            findings.append(finding(
                severity = sev,
                message  = f"{msg_prefix}Phantom config (plantable): {cfg_name}",
                detail   = (
                    f"Config file  : {path}\n"
                    f"Extension    : {ext}\n"
                    f"Result       : NAME NOT FOUND — file does not exist at this path\n"
                    f"Process IL   : {csv_integrity}  (PID {row_pid})\n"
                    f"Plant dir    : {check_dir}  ← writable by standard users\n"
                    f"Assessment   : {msg_tag}\n"
                    + (f"    {high_risk_note}" if high_risk_note else "")
                    + f"{trigger_note}\n"
                    f"Attack       : Create a malicious '{cfg_name}' at that path.\n"
                    f"               The {csv_integrity} process will read it on next run."
                ),
                module = MODULE_NAME,
            ))

        elif result == "SUCCESS":
            if not path_writable_by_non_admin(cfg_dir):
                continue
            sev = _apply_escalation(_base_severity(rid, auto_trigger), signals, auto_trigger)
            trigger_note = (
                f"\n    Trigger      : {auto_trigger_desc}"
                if auto_trigger_desc else
                "\n    Trigger      : User-launched (manual execution required)"
            )
            if signals >= 1:
                msg_prefix = f"[{esc_lbl}] "
                msg_tag    = "Confirmed code-execution pathway" if signals >= 2 else "Probable tampering avenue"
            else:
                msg_prefix = ""
                msg_tag    = "Writable path — exploitability unconfirmed (no high-risk signals)"
            findings.append(finding(
                severity = sev,
                message  = f"{msg_prefix}Config read by High/System process from writable dir: {cfg_name}",
                detail   = (
                    f"Config file  : {path}\n"
                    f"Extension    : {ext}\n"
                    f"Result       : SUCCESS — file was accessed\n"
                    f"Process IL   : {csv_integrity}  (PID {row_pid})\n"
                    f"Dir writable : {cfg_dir}  ← writable by standard users\n"
                    f"Assessment   : {msg_tag}\n"
                    + (f"    {high_risk_note}" if high_risk_note else "")
                    + (f"    {dynamic_note}" if dynamic_note else "")
                    + f"{trigger_note}\n"
                    f"Attack       : Replace '{cfg_name}' with a malicious copy that redirects\n"
                    f"               DLL/plugin/script loading to an attacker-controlled path."
                ),
                module = MODULE_NAME,
            ))

    return findings

def run(ctx: dict) -> List[dict]:
    findings: List[dict] = []

    exe_path    = ctx.get("exe_path")
    procmon_exe = procmon_session.get_procmon_exe(ctx)

    if not procmon_exe or not procmon_session.capture_exists():
        if not procmon_exe:
            print_warning("Procmon not available — config file runtime analysis skipped.")
        else:
            print_warning("No capture.pml — config file runtime analysis skipped.")
        print_info("No issues found.")
        return findings

    csv_path = procmon_session.export_filtered_csv(procmon_exe, "config")
    if not csv_path:
        # export_filtered_csv already printed the specific reason.
        print_info("No insecure config file access found.")
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

    if csv_findings:
        print_info(f"Config analysis: {len(csv_findings)} finding(s).")
    else:
        print_info("No insecure config file access found.")

    return findings
