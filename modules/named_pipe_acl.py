import os
import re
import csv
import io
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .utils import (
    finding, print_info, print_warning, print_error, print_success,
    is_windows, is_admin,
)

MODULE_NAME = "Named Pipe ACL"

# ── Tool locations ────────────────────────────────────────────────────────────
_TOOL_DIR           = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOGS_DIR           = os.path.join(_TOOL_DIR, "Logs")
_SYSINTERNALS_DIR   = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sysinternals")

# ── Low-privileged principals we care about ───────────────────────────────────
_LOW_PRIV_PRINCIPALS: Set[str] = {
    "everyone",
    "authenticated users",
    "nt authority\\authenticated users",
    "users",
    "builtin\\users",
}

# ── Dangerous permissions ─────────────────────────────────────────────────────
_PERM_WRITE_DATA       = "FILE_WRITE_DATA"
_PERM_ADD_FILE         = "FILE_ADD_FILE"         # alias for WRITE_DATA on pipes
_PERM_CREATE_INSTANCE  = "FILE_CREATE_PIPE_INSTANCE"
_PERM_ALL_ACCESS       = "FILE_ALL_ACCESS"
_PERM_READ_CONTROL     = "READ_CONTROL"
_PERM_READ_DATA        = "FILE_READ_DATA"

# ── Risk classification table ─────────────────────────────────────────────────
# (principal_pattern, permission_set, risk, exploit_path, explanation)
# Evaluated in order; first match wins per (principal, permission) pair.
_RISK_RULES: List[Tuple] = [
    # FILE_ALL_ACCESS by any low-priv principal → Critical impersonation
    (
        _LOW_PRIV_PRINCIPALS,
        {_PERM_ALL_ACCESS},
        "Critical",
        "Impersonation",
        "Full control enables token theft via ImpersonateNamedPipeClient",
    ),
    # Write + CreateInstance together → High impersonation primitive
    (
        _LOW_PRIV_PRINCIPALS,
        {_PERM_CREATE_INSTANCE, _PERM_WRITE_DATA},
        "High",
        "Impersonation + Protocol Manipulation",
        "Attacker can create a rogue instance and impersonate connecting clients",
    ),
    (
        _LOW_PRIV_PRINCIPALS,
        {_PERM_CREATE_INSTANCE, _PERM_ADD_FILE},
        "High",
        "Impersonation + Protocol Manipulation",
        "Attacker can create a rogue instance and impersonate connecting clients",
    ),
    # WRITE_DATA by Everyone → High protocol injection
    (
        {"everyone"},
        {_PERM_WRITE_DATA},
        "High",
        "Protocol Manipulation",
        "Arbitrary writes by Everyone may allow command injection into the service",
    ),
    (
        {"everyone"},
        {_PERM_ADD_FILE},
        "High",
        "Protocol Manipulation",
        "Arbitrary writes by Everyone may allow command injection into the service",
    ),
    # CreateInstance alone → Medium
    (
        _LOW_PRIV_PRINCIPALS,
        {_PERM_CREATE_INSTANCE},
        "Medium",
        "Impersonation",
        "Pipe instance creation allows a rogue server; impersonation possible if client connects",
    ),
    # Write alone by Authenticated Users / Users → Medium
    (
        {"authenticated users", "nt authority\\authenticated users", "users", "builtin\\users"},
        {_PERM_WRITE_DATA},
        "Medium",
        "Protocol Manipulation",
        "Authenticated users can inject data into the pipe protocol",
    ),
    # READ_CONTROL only → Low
    (
        _LOW_PRIV_PRINCIPALS,
        {_PERM_READ_CONTROL},
        "Low",
        "Information Disclosure",
        "ACL is readable by low-privileged users (information disclosure only)",
    ),
]

# ── Risk ordering (for deduplication — keep highest) ─────────────────────────
_RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class AclEntry:
    principal:   str
    permissions: List[str]
    ace_type:    str  # e.g. "ACCESS_ALLOWED_ACE_TYPE"


@dataclass
class PipeObject:
    pipe_name:    str           # bare name after \\Device\\NamedPipe\\[LOCAL\\]
    kernel_path:  str           # \Device\NamedPipe\...
    win32_path:   str           # \pipe\...
    process_name: str
    pid:          int
    acl:          List[AclEntry] = field(default_factory=list)
    status:       str = "OK"    # OK | BUSY_PIPE | ACL_ERROR


# ── Log directory helpers ─────────────────────────────────────────────────────

def _ensure_logs_dir() -> bool:
    """Create <tool root>/Logs if it does not exist. Returns False on failure."""
    try:
        os.makedirs(_LOGS_DIR, exist_ok=True)
        return True
    except Exception as exc:
        print_error(f"Cannot create Logs directory '{_LOGS_DIR}': {exc}")
        return False


def get_handle_csv_path(process_name: str) -> str:
    """
    Return the canonical path for a handle.exe CSV capture.

    Convention:  <tool root>/Logs/handle_<ProcessName>.csv
    This mirrors procmon_session's  <tool root>/Logs/<module>_capture.csv
    so all runtime artefacts are co-located under one directory.
    """
    safe_name = process_name.replace(" ", "_").replace("\\", "_").replace("/", "_")
    return os.path.join(_LOGS_DIR, f"handle_{safe_name}.csv")

def _find_tool(name: str, hint: Optional[str] = None) -> Optional[str]:
    """
    Locate a Sysinternals tool by name.
    Search order: hint path → PATH → common install dirs.
    """
    candidates = []
    if hint:
        candidates.append(hint)
    candidates.append(shutil.which(name) or "")
    for base in [
        _SYSINTERNALS_DIR,
        os.path.join(os.environ.get("ProgramFiles", ""), "Sysinternals"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # tool root
    ]:
        candidates.append(os.path.join(base, name))

    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _acquire_handle_exe(ctx: dict) -> Optional[str]:
    """
    Locate handle.exe from the context populated by bootstrap.

    The bootstrap phase (anvil._bootstrap_sysinternals) resolves and caches
    the path before any module runs.  This function reads that cached value
    and falls back to a PATH scan.  It does NOT download anything — downloads
    are centralised at startup so modules never block mid-scan.
    """
    cached = ctx.get("handle_exe")
    if cached and os.path.isfile(str(cached)):
        return str(cached)

    # Fallback: filesystem scan (covers unit-test / standalone module usage)
    found = _find_tool("handle.exe", ctx.get("handle_path"))
    if found:
        ctx["handle_exe"] = found
        return found
    found = _find_tool("handle64.exe")
    if found:
        ctx["handle_exe"] = found
        return found

    print_error(
        "handle.exe not found.  Run Anvil once to download it automatically, "
        "or use --handle <path> to supply it manually."
    )
    return None


def _acquire_accesschk_exe(ctx: dict) -> Optional[str]:
    """
    Locate accesschk.exe from the context populated by bootstrap.

    See _acquire_handle_exe for the rationale — no downloads here.
    """
    cached = ctx.get("accesschk_exe")
    if cached and os.path.isfile(str(cached)):
        return str(cached)

    found = _find_tool("accesschk.exe", ctx.get("accesschk_path"))
    if found:
        ctx["accesschk_exe"] = found
        return found
    found = _find_tool("accesschk64.exe")
    if found:
        ctx["accesschk_exe"] = found
        return found

    print_error(
        "accesschk.exe not found.  Run Anvil once to download it automatically, "
        "or use --accesschk <path> to supply it manually."
    )
    return None


# ── Phase 1 — handle.exe execution & CSV parsing ─────────────────────────────

def _run_handle_exe(
    handle_exe: str,
    process_name: str,
    output_csv: str,
) -> bool:
    """
    Run handle.exe for the given process name and write the result to output_csv.

    handle.exe -a pipe -p <ProcessName> -vt -nobanner -accepteula
    Output encoding: UTF-16-LE with BOM (Windows default for redirected CLI).
    """
    try:
        result = subprocess.run(
            [
                handle_exe,
                "-a", "pipe",
                "-p", process_name,
                "-vt",
                "-nobanner",
                "-accepteula",
            ],
            capture_output=True,
            timeout=60,
        )
        # handle.exe writes UTF-16-LE; write raw bytes directly
        with open(output_csv, "wb") as f:
            f.write(result.stdout)
        return True
    except subprocess.TimeoutExpired:
        print_warning(f"handle.exe timed out for process '{process_name}'.")
        return False
    except Exception as exc:
        print_warning(f"handle.exe failed: {exc}")
        return False


def _parse_handle_csv(csv_path: str) -> List[PipeObject]:
    """
    Parse handle.exe tab-delimited CSV output (UTF-16-LE with BOM).

    Filters:
      • Type == File  (or empty — handle.exe may leave Type blank)
      • Name contains \\Device\\NamedPipe\\

    Deduplicates by Win32 pipe name (same pipe, different handles → one entry).
    """
    pipes: Dict[str, PipeObject] = {}  # win32_path → PipeObject

    try:
        with open(csv_path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        print_warning(f"Cannot read handle CSV: {exc}")
        return []

    # Detect and decode encoding
    if raw[:2] == b"\xff\xfe":
        text = raw.decode("utf-16-le", errors="replace")
    elif raw[:2] == b"\xfe\xff":
        text = raw.decode("utf-16-be", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")

    # Strip BOM character if present
    text = text.lstrip("\ufeff")

    reader = csv.DictReader(io.StringIO(text), delimiter="\t")

    for row in reader:
        # Normalise column names (handle.exe may vary casing)
        row = {k.strip(): (v.strip() if v else "") for k, v in row.items()}

        proc  = row.get("Process") or row.get("ProcessName") or ""
        pid_s = row.get("PID", "0")
        typ   = row.get("Type", "")
        name  = row.get("Name", "")

        if not proc or not name:
            continue

        # Type is "File" for pipe handles (or may be empty in some handle versions)
        if typ and typ.lower() not in ("file", ""):
            continue

        if r"\Device\NamedPipe" not in name and r"\device\namedpipe" not in name.lower():
            continue

        try:
            pid = int(pid_s)
        except (ValueError, TypeError):
            pid = 0

        # ── Kernel path ──────────────────────────────────────────────────────
        kernel_path = name.strip()

        # ── Pipe name extraction ─────────────────────────────────────────────
        # Strip \Device\NamedPipe\ or \Device\NamedPipe\LOCAL\
        m = re.search(
            r"\\Device\\NamedPipe\\(?:LOCAL\\)?(.+)",
            kernel_path,
            re.IGNORECASE,
        )
        if not m:
            continue
        pipe_name = m.group(1).strip()

        # ── Win32 path ───────────────────────────────────────────────────────
        win32_path = r"\pipe" + "\\" + pipe_name

        # Deduplicate: keep first occurrence (lowest PID / first handle)
        if win32_path in pipes:
            continue

        pipes[win32_path] = PipeObject(
            pipe_name    = pipe_name,
            kernel_path  = kernel_path,
            win32_path   = win32_path,
            process_name = proc,
            pid          = pid,
        )

    return list(pipes.values())


# ── Phase 2 — accesschk.exe ACL analysis ─────────────────────────────────────

_ACE_TYPE_RE   = re.compile(r"^\s*(?:\[\d+\]\s*)?(ACCESS_(?:ALLOWED|DENIED)_ACE_TYPE)\s*:\s*(.+)$", re.IGNORECASE)
_PERM_LINE_RE  = re.compile(r"^\s+(FILE_\w+|READ_CONTROL|WRITE_DAC|WRITE_OWNER|SYNCHRONIZE|GENERIC_\w+)\s*$")


def _run_accesschk(accesschk_exe: str, win32_path: str) -> Tuple[str, List[AclEntry]]:
    """
    Run accesschk.exe for a single pipe Win32 path.

    Returns:
        ("OK", [AclEntry, …])
        ("BUSY_PIPE", [])
        ("ACL_ERROR", [])
    """
    try:
        result = subprocess.run(
            [
                accesschk_exe,
                "-wlv",
                win32_path,
                "-nobanner",
                "-accepteula",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "ACL_ERROR", []
    except Exception:
        return "ACL_ERROR", []

    if "All pipe instances are busy" in output or "all pipe instances are busy" in output.lower():
        return "BUSY_PIPE", []

    if not output.strip():
        return "ACL_ERROR", []

    return "OK", _parse_accesschk_output(output)


def _parse_accesschk_output(output: str) -> List[AclEntry]:
    """
    Parse accesschk -wlv output into AclEntry objects.

    accesschk output format (per ACE):

      ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\\Authenticated Users
            FILE_WRITE_DATA
            FILE_CREATE_PIPE_INSTANCE
            FILE_READ_DATA
            READ_CONTROL

    Multiple ACEs appear sequentially.
    """
    entries: List[AclEntry] = []
    current_ace_type:  Optional[str] = None
    current_principal: Optional[str] = None
    current_perms:     List[str]     = []

    def _flush():
        if current_principal:
            entries.append(AclEntry(
                principal   = current_principal,
                permissions = list(current_perms),
                ace_type    = current_ace_type or "",
            ))

    for line in output.splitlines():
        m_ace = _ACE_TYPE_RE.match(line)
        if m_ace:
            _flush()
            current_ace_type  = m_ace.group(1).strip()
            current_principal = m_ace.group(2).strip()
            current_perms     = []
            continue

        m_perm = _PERM_LINE_RE.match(line)
        if m_perm and current_principal:
            current_perms.append(m_perm.group(1).strip())

    _flush()
    return entries


# ── Phase 3 — Risk scoring ────────────────────────────────────────────────────

@dataclass
class RiskHit:
    principal:    str
    permissions:  List[str]
    risk:         str
    exploit_path: str
    explanation:  str


def _is_low_priv(principal: str) -> bool:
    """Return True if the principal is a low-privileged identity."""
    norm = principal.lower().strip()
    return any(lp in norm for lp in _LOW_PRIV_PRINCIPALS)


def _score_pipe(pipe: PipeObject) -> List[RiskHit]:
    """
    Evaluate the pipe's ACL against risk rules.
    Returns a list of RiskHit objects (may be empty if no risk found).
    """
    hits: List[RiskHit] = []

    for ace in pipe.acl:
        if not _is_low_priv(ace.principal):
            continue
        if ace.ace_type.upper().startswith("ACCESS_DENIED"):
            continue  # Explicit denies are not risk indicators

        perm_set  = set(ace.permissions)
        principal = ace.principal

        for rule_principals, rule_perms, risk, exploit, explanation in _RISK_RULES:
            # Normalise rule_principals for comparison
            rule_norm = {p.lower() for p in rule_principals}
            if not any(rp in principal.lower() for rp in rule_norm):
                continue
            if not rule_perms.issubset(perm_set):
                continue

            # Matched — record the most specific permission(s) that triggered this rule
            hits.append(RiskHit(
                principal    = principal,
                permissions  = sorted(rule_perms),
                risk         = risk,
                exploit_path = exploit,
                explanation  = explanation,
            ))
            break  # One rule match per ACE principal

    return hits


# ── Phase 4 — Finding construction ───────────────────────────────────────────

def _risk_to_severity(risk: str) -> str:
    return {
        "Critical": "P1",
        "High":     "P2",
        "Medium":   "P3",
        "Low":      "P4",
    }.get(risk, "P5")


def _pipe_to_findings(pipe: PipeObject) -> List[dict]:
    """Convert a scored PipeObject into Anvil finding dicts."""
    results: List[dict] = []
    hits = _score_pipe(pipe)
    if not hits:
        return results

    # Group hits by (principal, exploit_path) to avoid duplicate entries
    seen: Set[str] = set()
    for hit in hits:
        key = f"{hit.principal}|{hit.exploit_path}"
        if key in seen:
            continue
        seen.add(key)

        perm_list = "\n    ".join(hit.permissions)
        # Full ACL dump for the matching principal
        matching_aces = [
            ace for ace in pipe.acl
            if ace.principal.lower() == hit.principal.lower()
        ]
        full_perms = []
        for ace in matching_aces:
            full_perms.extend(ace.permissions)
        full_perm_str = "\n    ".join(sorted(set(full_perms)))

        # Build exploit sequence based on path
        if "Impersonation" in hit.exploit_path:
            exploit_seq = (
                "  1. CreateNamedPipe(win32_path, PIPE_ACCESS_DUPLEX, …)\n"
                "  2. ConnectNamedPipe(hPipe, NULL)   ← wait for privileged client\n"
                "  3. ImpersonateNamedPipeClient(hPipe)\n"
                "  4. DuplicateTokenEx → CreateProcessWithTokenW\n"
                "     (execute code as the connecting client's identity)"
            )
        else:
            exploit_seq = (
                "  1. Open pipe handle with write access\n"
                "  2. Send crafted protocol messages to the server\n"
                "     (command injection / privilege abuse via parser flaw)"
            )

        results.append(finding(
            severity = _risk_to_severity(hit.risk),
            message  = "",
            detail   = (
                f"Pipe Name    : {pipe.pipe_name}\n"
                f"Win32 Path   : {pipe.win32_path}\n"
                f"Kernel Path  : {pipe.kernel_path}\n"
                f"Owner Process: {pipe.process_name}  (PID {pipe.pid})\n"
                f"\n"
                f"Principal    : {hit.principal}\n"
                f"Trigger Perms: {perm_list}\n"
                f"Full ACL     :\n    {full_perm_str}\n"
                f"\n"
                f"Risk         : {hit.risk}\n"
                f"Exploit Path : {hit.exploit_path}\n"
                f"Explanation  : {hit.explanation}\n"
                f"\n"
                f"Exploit Sequence:\n{exploit_seq}"
            ),
            module = MODULE_NAME,
        ))

    return results


# ── Finding printer (tree format) ────────────────────────────────────────────

def _print_pipe_findings(pipes_with_hits: List[Tuple[PipeObject, List[RiskHit]]]):
    """
    Print vulnerable pipes in a compact tree format:

      [ - ] [P2] NvMessageBusBroadcastNVIDIA.Display.Driver
            ├─ Principal  : Everyone
            ├─ Permission : FILE_WRITE_DATA
            └─ Exploit    : Protocol Manipulation
    """
    if not pipes_with_hits:
        return

    _SEV_STYLE = {
        "Critical": "bold red",
        "High":     "red",
        "Medium":   "yellow",
        "Low":      "cyan",
    }
    _SEV_TO_P = {
        "Critical": "P1",
        "High":     "P2",
        "Medium":   "P3",
        "Low":      "P4",
    }

    try:
        from rich.console import Console
        console = Console(highlight=False)
        _rich = True
    except ImportError:
        _rich = False

    for pipe, hits in pipes_with_hits:
        for hit in hits:
            p_level   = _SEV_TO_P.get(hit.risk, "P5")
            sev_style = _SEV_STYLE.get(hit.risk, "white")
            perms     = " + ".join(hit.permissions)
            last_idx  = len(hits) - 1

            if _rich:
                console.print(
                    f"  [bold {sev_style}][ - ][/bold {sev_style}] "
                    f"[{sev_style}][{p_level}][/{sev_style}] "
                    f"[yellow]{pipe.pipe_name}[/yellow]"
                )
                console.print(f"        [dim]├─[/dim] Principal  : {hit.principal}")
                console.print(f"        [dim]├─[/dim] Permission : {perms}")
                console.print(f"        [dim]└─[/dim] Exploit    : {hit.exploit_path}")
            else:
                print(f"  [ - ] [{p_level}] {pipe.pipe_name}")
                print(f"        ├─ Principal  : {hit.principal}")
                print(f"        ├─ Permission : {perms}")
                print(f"        └─ Exploit    : {hit.exploit_path}")
            print()


# ── Public entry point ────────────────────────────────────────────────────────

def run(ctx: dict) -> List[dict]:
    """
    Main module entry point called by Anvil.

    Context keys consumed:
      exe_path        – target executable (used to derive process name)
      service_name    – target service name (alternative to exe_path)
      pid             – attach by PID
      launched_pid    – PID launched by Anvil during the Procmon capture phase
      handle_path     – optional explicit path to handle.exe
      accesschk_path  – optional explicit path to accesschk.exe

    Output:
      handle.exe CSV is saved to Logs/handle_<ProcessName>.csv alongside the
      Procmon capture logs.  The path is stored in ctx["handle_csv_path"] so
      callers can reference or archive it.
    """
    all_findings: List[dict] = []

    if not is_windows():
        print_warning("Named pipe ACL analysis requires Windows.")
        return all_findings

    # ── Determine process name to scan ───────────────────────────────────────
    exe_path     = ctx.get("exe_path")
    service_name = ctx.get("service_name")
    pid          = ctx.get("launched_pid") or ctx.get("pid")

    if exe_path:
        target_process = os.path.basename(exe_path)
    elif service_name:
        target_process = service_name
    elif pid:
        from .utils import get_process_path_from_pid
        resolved = get_process_path_from_pid(pid)
        target_process = os.path.basename(resolved) if resolved else ""
    else:
        print_warning("No target process specified — named pipe scan skipped.")
        return all_findings

    if not target_process:
        print_warning("Could not determine target process name — named pipe scan skipped.")
        return all_findings

    print_info(f"Target process for pipe enumeration: {target_process}")

    # ── Phase 1: Run handle.exe and save CSV to Logs/ ─────────────────────────
    handle_exe = _acquire_handle_exe(ctx)
    if not handle_exe:
        return all_findings

    if not _ensure_logs_dir():
        return all_findings

    log_csv = get_handle_csv_path(target_process)
    ctx["handle_csv_path"] = log_csv   # expose to caller / HTML report

    print_info(f"Running handle.exe against '{target_process}'…")

    if not _run_handle_exe(handle_exe, target_process, log_csv):
        return all_findings

    pipes = _parse_handle_csv(log_csv)

    if not pipes:
        print_info(f"No named pipes found for process '{target_process}'.")
        return all_findings

    # ── Phase 2: ACL analysis ─────────────────────────────────────────────────
    accesschk_exe = _acquire_accesschk_exe(ctx)
    if not accesschk_exe:
        print_warning("ACL analysis skipped — accesschk.exe unavailable.")
        all_findings.append(finding(
            severity = "P5",
            message  = f"Named pipes discovered for '{target_process}' (ACL check skipped)",
            detail   = "\n".join(
                f"  {p.win32_path}  (owner: {p.process_name} PID {p.pid})"
                for p in pipes
            ),
            module = MODULE_NAME,
        ))
        return all_findings

    busy_count  = 0
    error_count = 0
    pipes_with_hits: List[Tuple[PipeObject, List[RiskHit]]] = []

    for pipe in pipes:
        status, acl_entries = _run_accesschk(accesschk_exe, pipe.win32_path)

        if status == "BUSY_PIPE":
            pipe.status = "BUSY_PIPE"
            busy_count += 1
            continue

        if status == "ACL_ERROR":
            pipe.status = "ACL_ERROR"
            error_count += 1
            continue

        pipe.acl    = acl_entries
        pipe.status = "OK"

        hits = _score_pipe(pipe)
        if hits:
            pipes_with_hits.append((pipe, hits))

    # ── Summary lines ─────────────────────────────────────────────────────────
    skipped_parts = []
    if busy_count:
        skipped_parts.append(f"{busy_count} Busy")
    if error_count:
        skipped_parts.append(f"{error_count} Error")
    skipped_str = f" ({', '.join(skipped_parts)})" if skipped_parts else ""

    print_info(f"Pipes Discovered : {len(pipes)}")
    print_info(f"Pipes Skipped    : {busy_count + error_count}{skipped_str}")
    print()

    # ── Phase 4 + 5: Classify & Report ───────────────────────────────────────
    vuln_count = sum(len(hits) for _, hits in pipes_with_hits)

    if pipes_with_hits:
        print_info(f"Found {vuln_count} vulnerable named pipe{'s' if vuln_count != 1 else ''}")
        print()
        _print_pipe_findings(pipes_with_hits)
    else:
        print_info("No vulnerable named pipes found.")

    for pipe, _ in pipes_with_hits:
        all_findings.extend(_pipe_to_findings(pipe))

    return all_findings

