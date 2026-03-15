from __future__ import annotations

import os
import sys
import ctypes
import ctypes.wintypes
import dataclasses
import platform
from datetime import datetime
from typing import Optional, Tuple



def _enable_vt_processing() -> bool:
    """
    Attempt to enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout.
    Returns True if VT mode is now active, False if the console cannot support it.

    Also works for the special case of Windows Terminal running PowerShell 5.1:
    the mode bit can be set, so this returns True correctly there.
    """
    if not platform.system().lower() == "windows":
        return True   # POSIX terminals support ANSI natively
    try:
        kernel32 = ctypes.windll.kernel32
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        ENABLE_PROCESSED_OUTPUT            = 0x0001

        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle == ctypes.c_void_p(-1).value or handle == 0:
            return False

        mode = ctypes.wintypes.DWORD(0)
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # Not a console at all (piped/redirected) — let Rich handle colour
            # stripping via its own is_terminal detection.
            return False

        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT
        if kernel32.SetConsoleMode(handle, new_mode):
            return True

        # SetConsoleMode failed — old conhost that cannot process VT sequences.
        return False
    except Exception:
        return False


_VT_SUPPORTED: bool = _enable_vt_processing()


# ── Rich (optional — degrade gracefully if not installed) ────────────────────
# Suppress Rich if the terminal cannot render VT sequences; using Rich on a
# non-VT console produces a wall of escape-code garbage in cmd / legacy PS.
try:
    if not _VT_SUPPORTED:
        raise ImportError("VT sequences not supported on this console — skipping Rich")
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False
    Console = None  # type: ignore

# Shared console instance (stderr=False → goes to stdout)
console: "Console" = Console(highlight=False) if _RICH else None  # type: ignore


import contextlib
from typing import List as _List

class _ModuleLog:
    """Collects suppressed output from a module run."""
    def __init__(self):
        self.entries: _List[tuple] = []   # (level, message)  level ∈ info/warn/error/ok

    def append(self, level: str, msg: str):
        self.entries.append((level, msg))

    def summary(self) -> str:
        """Return the last non-empty entry as a short summary for the checklist."""
        for level, msg in reversed(self.entries):
            clean = msg.strip()
            if clean:
                # Strip Rich markup tags for plain display
                import re
                clean = re.sub(r"\[/?[a-zA-Z_ ]+\]", "", clean)
                return clean[:80]
        return ""

    def has_errors(self) -> bool:
        return any(lvl == "error" for lvl, _ in self.entries)


@contextlib.contextmanager
def silence_output():

    import io, sys

    log  = _ModuleLog()

    class _TtyStringIO(io.StringIO):
        """StringIO that claims to be a TTY so Rich retains ANSI colour codes."""
        def isatty(self) -> bool:
            return True

    _buf = _TtyStringIO()

    _orig_stdout = sys.stdout
    _orig_stderr = sys.stderr
    sys.stdout   = _buf
    sys.stderr   = _buf

    _console_originals: list = []
    def _redirect_console(console_obj):
        if console_obj is not None:
            _console_originals.append((console_obj, console_obj.file))
            console_obj.file = _buf

    _redirect_console(console)

    try:
        import modules.pe_security as _pesec  # type: ignore
        if hasattr(_pesec, "_console"):
            _redirect_console(_pesec._console)
    except Exception:
        pass

    try:
        import modules.named_pipe_acl as _pipes  # type: ignore
        if hasattr(_pipes, "console"):
            _redirect_console(_pipes.console)
    except Exception:
        pass

    try:
        yield log
    finally:
        # ── Restore stdout / stderr ───────────────────────────────────────────
        sys.stdout = _orig_stdout
        sys.stderr = _orig_stderr

        # ── Restore module-private console files ─────────────────────────────
        for console_obj, orig_file in _console_originals:
            try:
                console_obj.file = orig_file
            except Exception:
                pass

        # ── Store captured text in the log ────────────────────────────────────
        captured = _buf.getvalue()
        if captured:
            log.append("info", captured.rstrip())


RESET   = "\033[0m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
DIM     = "\033[2m"


def _c(color: str, text: str) -> str:
    if _VT_SUPPORTED and sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text


# ── CVSS Estimate Mapping (centralised — do not hardcode elsewhere) ───────────
#
# These ranges reflect cross-privilege-boundary exploitation potential.
# If a finding's process integrity is Medium and no privilege boundary is
# crossed, callers should downgrade to the Medium range at most.

CVSS_RANGES: dict[str, str] = {
    # P-Level model: severity reflects local privilege escalation potential.
    # Remote code execution (CVSS 9.0+) is outside this tool's scope.
    "P1": "8.0 \u2013 8.8",
    "P2": "7.0 \u2013 7.9",
    "P3": "4.0 \u2013 6.9",
    "P4": "0.1 \u2013 3.9",
    "P5": "N/A",
}


def cvss_range(severity: str) -> str:
    """Return the CVSS estimate range string for a given Anvil severity label."""
    return CVSS_RANGES.get(severity.upper(), "N/A")


# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER_ART = (
    "\n"
    "      _______             __ ___     \n"
    "     |   _   .-----.--.--|__|   |    \n"
    "     |.  1   |     |  |  |  |.  |    \n"
    "     |.  _   |__|__|\\___/|__|.  |___ \n"
    "     |:  |   |              |:  1   |\n"
    "     |::.|:. |              |::.. . |\n"
    "     `--- ---'              `-------'\n"
)


def banner():
    """
    ASCII art banner rendered in red. No box, no decorative frames.
    """
    if _RICH:
        console.print(f"[red]{_BANNER_ART}[/red]")
        console.print()
    else:
        print(_c(RED, _BANNER_ART))
        print("  Windows Thick Client Security Assessment")
        print()


# ── Section headers ───────────────────────────────────────────────────────────

def print_section(title: str):
    """Cyan section divider — one blank line before, no box."""
    if _RICH:
        console.print(f"\n[cyan]{title}[/cyan]")
        console.print(f"[cyan]{'─' * len(title)}[/cyan]")
    else:
        print()
        print(_c(CYAN, title))
        print(_c(CYAN, "─" * len(title)))


# ── Status-prefix output helpers ─────────────────────────────────────────────
#
# [ + ]  Positive / Secure
# [ - ]  Vulnerable
# [ * ]  Informational
# [ ! ]  Warning
#
# Only the value portion of path/ID fields is yellow — not the full line.

def print_info(msg: str):
    """[ * ] Informational."""
    if _RICH:
        console.print(f"[white][ * ][/white] {msg}")
    else:
        print(f"[ * ] {msg}")


def print_warning(msg: str):
    """[ ! ] Warning."""
    if _RICH:
        console.print(f"[yellow][ ! ][/yellow] {msg}")
    else:
        print(_c(YELLOW, f"[ ! ] {msg}"))


def print_error(msg: str):
    """[ - ] Vulnerable / error."""
    if _RICH:
        console.print(f"[red][ - ][/red] {msg}")
    else:
        print(_c(RED, f"[ - ] {msg}"))


def print_success(msg: str):
    """[ + ] Positive / secure."""
    if _RICH:
        console.print(f"[green][ + ][/green] {msg}")
    else:
        print(_c(GREEN, f"[ + ] {msg}"))


def hl(value: str) -> str:
    """
    Wrap a path, CLSID, EXE name, DLL name, registry key, or service name
    in yellow markup for Rich output, or ANSI yellow for plain output.
    Use for the *value portion only* — not the whole line.
    """
    if _RICH:
        return f"[yellow]{value}[/yellow]"
    return _c(YELLOW, value)


# ── Finding constructor ───────────────────────────────────────────────────────

def finding(severity: str, message: str, detail: str = "", module: str = "") -> dict:
    return {
        "severity":  severity.upper(),
        "message":   message,
        "detail":    detail,
        "module":    module,
        "timestamp": datetime.now().isoformat(),
    }


# ── Platform helpers ──────────────────────────────────────────────────────────

def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ── Process integrity level ───────────────────────────────────────────────────
_TOKEN_INTEGRITY_LEVEL         = 25
_SECURITY_MANDATORY_LOW_RID    = 0x1000
_SECURITY_MANDATORY_MEDIUM_RID = 0x2000
_SECURITY_MANDATORY_HIGH_RID   = 0x3000
_SECURITY_MANDATORY_SYSTEM_RID = 0x4000


def get_process_integrity(pid: Optional[int] = None) -> Optional[int]:
    """
    Return the mandatory integrity RID for a process (None = current process).

    Bug fix: the previous implementation called c_void_p.from_buffer_copy() on
    the TOKEN_MANDATORY_LABEL buffer and then dereferenced the result as an
    address in THIS process.  That pointer is only valid inside the target
    process — reading it here produces garbage or an access violation caught
    silently by the bare except, causing the function to always return None.

    Correct approach: GetTokenInformation with TokenIntegrityLevel returns a
    TOKEN_MANDATORY_LABEL whose Label.Sid field is a POINTER to a SID stored
    INLINE in the same buffer, immediately after the struct.  We parse the RID
    directly from the buffer bytes — no cross-process pointer dereference.

    Buffer layout (TOKEN_MANDATORY_LABEL):
      [0 .. ptr_size-1]     SID* pointer  (NOT dereferenceable here — skip)
      [ptr_size .. +3]      DWORD Attributes
      [ptr_size+4 ..]       Inline SID:
        +0  Revision        (1 byte)
        +1  SubAuthorityCount (1 byte, always 1 for integrity SIDs)
        +2  IdentifierAuthority (6 bytes)
        +8  SubAuthority[0] (4 bytes) ← RID
    RID offset from buf[0]: ptr_size + 4 + 8 = ptr_size + 12
    """
    if not is_windows():
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32

        if pid:
            hProcess = kernel32.OpenProcess(0x1000, False, pid)
            if not hProcess:
                return None
        else:
            hProcess = kernel32.GetCurrentProcess()

        hToken = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(hProcess, 0x0008, ctypes.byref(hToken)):
            if pid:
                kernel32.CloseHandle(hProcess)
            return None
        if pid:
            kernel32.CloseHandle(hProcess)

        # First call: get required buffer size
        cb = ctypes.wintypes.DWORD(0)
        advapi32.GetTokenInformation(
            hToken, _TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(cb)
        )
        if cb.value == 0:
            kernel32.CloseHandle(hToken)
            return None

        buf  = (ctypes.c_byte * cb.value)()
        cb2  = ctypes.wintypes.DWORD(cb.value)
        if not advapi32.GetTokenInformation(
            hToken, _TOKEN_INTEGRITY_LEVEL, buf, cb2, ctypes.byref(cb2)
        ):
            kernel32.CloseHandle(hToken)
            return None
        kernel32.CloseHandle(hToken)

        # Parse inline SID — no pointer dereference into another process.
        ptr_size   = ctypes.sizeof(ctypes.c_void_p)
        rid_offset = ptr_size + 4 + 8   # skip pointer, Attributes, SID header
        if cb.value < rid_offset + 4:
            return None
        rid = ctypes.c_ulong.from_buffer_copy(
            bytes(buf[rid_offset : rid_offset + 4])
        ).value
        return rid

    except Exception:
        return None


def integrity_label(rid: Optional[int]) -> str:
    if rid is None:
        return "Unknown"
    if rid >= _SECURITY_MANDATORY_SYSTEM_RID:
        return "System"
    if rid >= _SECURITY_MANDATORY_HIGH_RID:
        return "High"
    if rid >= _SECURITY_MANDATORY_MEDIUM_RID:
        return "Medium"
    return "Low"


def process_is_high_or_system(pid: Optional[int] = None) -> bool:
    rid = get_process_integrity(pid)
    return rid is not None and rid >= _SECURITY_MANDATORY_HIGH_RID


# ── Centralised protected-path guard ─────────────────────────────────────────
#
# IMPORTANT: Do NOT call os.path.abspath() on paths from Procmon CSV rows.
# Procmon emits fully-qualified device paths; abspath() would prepend the
# scanner's CWD and produce a wrong result.
# Pass from_procmon=True when the path originated from a Procmon CSV field.
#
_SYSTEM_ROOT = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
_PROTECTED_PATH_PREFIXES: Tuple[str, ...] = tuple(
    os.path.normcase(p) for p in [
        os.path.join(_SYSTEM_ROOT, "System32"),
        os.path.join(_SYSTEM_ROOT, "SysWOW64"),
        os.path.join(_SYSTEM_ROOT, "System"),
        _SYSTEM_ROOT,
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ]
)

# When running as a PyInstaller EXE, _MEIxxxxxx in %TEMP% is the extraction
# directory for bundled files. DLL lookups inside it are from the tool itself
# and must never be reported as findings.
def _get_mei_prefix() -> Optional[str]:
    import sys
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.normcase(sys._MEIPASS)
    return None

_MEI_PREFIX: Optional[str] = _get_mei_prefix()


def _is_protected_system_path(path: str, *, from_procmon: bool = False) -> bool:
    if from_procmon:
        norm = os.path.normcase(path)
    else:
        norm = os.path.normcase(os.path.abspath(path))
    if _MEI_PREFIX and norm.startswith(_MEI_PREFIX):
        return True
    return any(norm.startswith(p) for p in _PROTECTED_PATH_PREFIXES)


# ── Centralised severity helpers ──────────────────────────────────────────────

def _esc_label(il_rid: Optional[int]) -> str:
    """Human-readable escalation label for a finding detail block."""
    if il_rid is None or il_rid < _SECURITY_MANDATORY_HIGH_RID:
        return "Code execution as current user"
    if il_rid >= _SECURITY_MANDATORY_SYSTEM_RID:
        return "Privilege escalation to SYSTEM"
    return "Privilege escalation to High integrity"


def _severity_phantom(il_rid: Optional[int], auto_trigger: bool = False) -> str:
    """
    Severity for a phantom (non-existent) hijack opportunity.

    P1 requires ALL of:
      - Process runs as High or SYSTEM integrity
      - Trigger is automatic (service / scheduled task / updater)
        i.e. no user interaction required

    If the process requires a user to manually launch it → P2.
    """
    if il_rid is None:
        return "P2"
    if il_rid >= _SECURITY_MANDATORY_HIGH_RID:
        return "P1" if auto_trigger else "P2"
    return "P2"


def _severity_replace(il_rid: Optional[int], auto_trigger: bool = False) -> str:
    """
    Severity for replacing an existing file in a user-writable directory.

    P2 requires High/SYSTEM IL.  auto_trigger has no further uplift here
    (replacing an existing file always needs at least some interaction to
    restart the process), but is kept for consistency.
    """
    if il_rid is None:
        return "P3"
    if il_rid >= _SECURITY_MANDATORY_HIGH_RID:
        return "P2"
    return "P3"


def _rid_from_label(label: str) -> int:
    """Convert an integrity label string to a RID integer (best-effort)."""
    lbl = label.strip().lower()
    if "system" in lbl:
        return _SECURITY_MANDATORY_SYSTEM_RID
    if "high" in lbl:
        return _SECURITY_MANDATORY_HIGH_RID
    if "medium" in lbl:
        return _SECURITY_MANDATORY_MEDIUM_RID
    return _SECURITY_MANDATORY_LOW_RID


# ── Auto-trigger detection (P1 gate) ─────────────────────────────────────────
#
# A finding is only P1 when the vulnerable process starts automatically
# without user interaction.  We check whether the exe is a Windows service
# or scheduled task.  If it requires a user to manually launch it → P2.

def _query_service_account(service_name: str) -> str:
    """Return the ObjectName (logon account) for a service, or empty string."""
    try:
        import winreg
        key_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            try:
                val, _ = winreg.QueryValueEx(k, "ObjectName")
                return str(val)
            except FileNotFoundError:
                return "LocalSystem"
    except Exception:
        return ""


def _is_auto_triggered(exe_path: Optional[str]) -> Tuple[bool, str]:
    """
    Return (True, description) if exe_path is started automatically without
    user interaction (Windows service or scheduled task), else (False, "").

    Checks:
      1. HKLM\\SYSTEM\\CurrentControlSet\\Services — ImagePath match
      2. schtasks /query — task action path match (best-effort)

    The result is used by callers to decide P1 vs P2:
      Auto-triggered + High/SYSTEM IL  → P1
      User-launched  + High/SYSTEM IL  → P2
    """
    if not is_windows() or not exe_path:
        return False, ""

    try:
        norm_exe = os.path.normcase(os.path.abspath(exe_path))
    except Exception:
        norm_exe = os.path.normcase(exe_path)

    # ── Windows service registry scan ─────────────────────────────────────────
    try:
        import winreg
        services_key = r"SYSTEM\CurrentControlSet\Services"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key) as sk:
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(sk, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        rf"{services_key}\{svc_name}",
                    ) as svck:
                        try:
                            img, _ = winreg.QueryValueEx(svck, "ImagePath")
                        except FileNotFoundError:
                            continue

                        img = os.path.expandvars(str(img)).strip()
                        if img.startswith('"'):
                            img_exe = img[1:].split('"')[0]
                        else:
                            img_exe = img.split(" ")[0]

                        try:
                            candidate = os.path.normcase(os.path.abspath(img_exe))
                        except Exception:
                            candidate = os.path.normcase(img_exe)

                        if candidate == norm_exe:
                            try:
                                start_type, _ = winreg.QueryValueEx(svck, "Start")
                            except FileNotFoundError:
                                start_type = 3  # SERVICE_DEMAND_START
                            # 0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled
                            # Demand-start services are still SCM-managed — the SCM
                            # runs them as LocalSystem/LocalService, not the logged-in
                            # user.  All start types 0–3 qualify as auto-triggered.
                            if start_type > 3:
                                continue  # Disabled — skip
                            account = _query_service_account(svc_name)
                            start_lbl = {0: "boot", 1: "system", 2: "auto", 3: "demand"}.get(
                                start_type, str(start_type)
                            )
                            desc = (
                                f"Windows service '{svc_name}'"
                                + (f" (account: {account})" if account else "")
                                + f" [{start_lbl}-start]"
                            )
                            return True, desc
                except (PermissionError, Exception):
                    continue
    except Exception:
        pass

    # ── Scheduled task scan (best-effort) ─────────────────────────────────────
    try:
        import subprocess
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if norm_exe in os.path.normcase(line):
                    task_name = line.split(",")[0].strip().strip('"')
                    return True, f"Scheduled task '{task_name}'"
    except Exception:
        pass

    return False, ""


# ── AccessCheck-based writability test ────────────────────────────────────────

class _GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [
        ("GenericRead",    ctypes.wintypes.DWORD),
        ("GenericWrite",   ctypes.wintypes.DWORD),
        ("GenericExecute", ctypes.wintypes.DWORD),
        ("GenericAll",     ctypes.wintypes.DWORD),
    ]


class _PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.wintypes.DWORD),
        ("Control",        ctypes.wintypes.DWORD),
        ("Privilege",      ctypes.c_byte * 128),
    ]


_FILE_GENERIC_MAPPING = _GENERIC_MAPPING(
    0x00120089,
    0x00120116,
    0x001200A0,
    0x001F01FF,
)

_GENERIC_WRITE         = 0x40000000
_TOKEN_QUERY           = 0x0008
_TOKEN_DUPLICATE       = 0x0002
_SecurityImpersonation = 2


def _get_impersonation_token() -> Optional[ctypes.wintypes.HANDLE]:
    advapi32 = ctypes.windll.advapi32
    kernel32  = ctypes.windll.kernel32

    hSelf  = kernel32.GetCurrentProcess()
    hToken = ctypes.wintypes.HANDLE()
    if not advapi32.OpenProcessToken(hSelf, _TOKEN_QUERY | _TOKEN_DUPLICATE, ctypes.byref(hToken)):
        return None

    hImp = ctypes.wintypes.HANDLE()
    ok = advapi32.DuplicateToken(hToken, _SecurityImpersonation, ctypes.byref(hImp))
    kernel32.CloseHandle(hToken)
    return hImp if ok else None


def path_writable_by_non_admin(path: str, *, from_procmon: bool = False) -> bool:
    """
    Ask Windows: can a standard (non-admin) user write to path?

    Correctly avoids os.path.abspath() on Procmon CSV paths
    (from_procmon=True) to prevent CWD contamination.
    """
    if not is_windows():
        return False

    if _is_protected_system_path(path, from_procmon=from_procmon):
        return False

    check_path = path
    if not os.path.exists(check_path):
        check_path = os.path.dirname(path)
    if not check_path or not os.path.exists(check_path):
        return False

    pSd   = ctypes.c_void_p(None)
    hToken = None
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32  = ctypes.windll.kernel32

        advapi32.GetNamedSecurityInfoW.restype = ctypes.wintypes.DWORD
        ret = advapi32.GetNamedSecurityInfoW(
            check_path, 1, 4, None, None, None, None, ctypes.byref(pSd)
        )
        if ret != 0 or not pSd.value:
            return os.access(check_path, os.W_OK)

        hToken = _get_impersonation_token()
        if not hToken:
            return os.access(check_path, os.W_OK)

        desired_val = ctypes.wintypes.DWORD(_GENERIC_WRITE)
        gm_copy = _GENERIC_MAPPING(
            _FILE_GENERIC_MAPPING.GenericRead,
            _FILE_GENERIC_MAPPING.GenericWrite,
            _FILE_GENERIC_MAPPING.GenericExecute,
            _FILE_GENERIC_MAPPING.GenericAll,
        )
        advapi32.MapGenericMask(ctypes.byref(desired_val), ctypes.byref(gm_copy))

        priv_set      = _PRIVILEGE_SET()
        priv_set_size = ctypes.wintypes.DWORD(ctypes.sizeof(priv_set))
        granted       = ctypes.wintypes.DWORD(0)
        status        = ctypes.wintypes.BOOL(0)

        advapi32.AccessCheck.restype = ctypes.wintypes.BOOL
        result = advapi32.AccessCheck(
            pSd, hToken, desired_val, ctypes.byref(gm_copy),
            ctypes.byref(priv_set), ctypes.byref(priv_set_size),
            ctypes.byref(granted), ctypes.byref(status),
        )

        if not result:
            return os.access(check_path, os.W_OK)

        return bool(status.value)

    except Exception:
        try:
            return os.access(check_path, os.W_OK)
        except Exception:
            return False
    finally:
        if pSd and pSd.value:
            ctypes.windll.kernel32.LocalFree(pSd)
        if hToken:
            ctypes.windll.kernel32.CloseHandle(hToken)


# ── Service / PID resolution ──────────────────────────────────────────────────

def resolve_exe_from_service(service_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (exe_path, error_message)."""
    try:
        import winreg
        key_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            image_path, _ = winreg.QueryValueEx(key, "ImagePath")
        image_path = os.path.expandvars(str(image_path)).strip()
        if image_path.startswith('"'):
            image_path = image_path[1:].split('"')[0]
        else:
            image_path = image_path.split(" ")[0]
        return image_path, None
    except FileNotFoundError:
        return None, f"Service '{service_name}' not found in registry."
    except PermissionError:
        return None, "Access denied reading service registry key."
    except Exception as exc:
        return None, str(exc)


def get_process_path_from_pid(pid: int) -> Optional[str]:
    try:
        handle = ctypes.windll.kernel32.OpenProcess(0x0410, False, pid)
        if not handle:
            return None
        buf  = ctypes.create_unicode_buffer(260)
        size = ctypes.wintypes.DWORD(260)
        if ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            ctypes.windll.kernel32.CloseHandle(handle)
            return buf.value
        ctypes.windll.kernel32.CloseHandle(handle)
        return None
    except Exception:
        return None


def resolve_exe_from_pid(pid: int) -> Optional[str]:
    return get_process_path_from_pid(pid)


def get_file_owner(path: str) -> str:
    try:
        import win32security
        sd         = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid  = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{name}"
    except Exception:
        return "Unknown"


# ── Process-tree enumeration helper ──────────────────────────────────────────

def _enumerate_child_pids(parent_pid: int) -> list[int]:
    """
    Return a flat list of all descendant PIDs of parent_pid using
    CreateToolhelp32Snapshot. Does not include parent_pid itself.
    """
    if not is_windows():
        return []
    try:
        TH32CS_SNAPPROCESS = 0x00000002

        class _PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize",              ctypes.wintypes.DWORD),
                ("cntUsage",            ctypes.wintypes.DWORD),
                ("th32ProcessID",       ctypes.wintypes.DWORD),
                ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID",        ctypes.wintypes.DWORD),
                ("cntThreads",          ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase",      ctypes.c_long),
                ("dwFlags",             ctypes.wintypes.DWORD),
                ("szExeFile",           ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == ctypes.wintypes.HANDLE(-1).value:
            return []

        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)

        parent_map: dict[int, list[int]] = {}
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                ppid = entry.th32ParentProcessID
                pid  = entry.th32ProcessID
                parent_map.setdefault(ppid, []).append(pid)
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        kernel32.CloseHandle(snap)

        result: list[int] = []
        queue = list(parent_map.get(parent_pid, []))
        while queue:
            child = queue.pop(0)
            result.append(child)
            queue.extend(parent_map.get(child, []))
        return result
    except Exception:
        return []


# ── Medium-integrity process launcher ────────────────────────────────────────

_TOKEN_ASSIGN_PRIMARY   = 0x0001
_TOKEN_ADJUST_DEFAULT   = 0x0080
_TOKEN_ADJUST_SESSIONID = 0x0100
_PROCESS_QUERY_INFO     = 0x0400
_SecurityImpersonation2 = 2
_TokenPrimary           = 1


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              ctypes.wintypes.DWORD),
        ("lpReserved",      ctypes.wintypes.LPWSTR),
        ("lpDesktop",       ctypes.wintypes.LPWSTR),
        ("lpTitle",         ctypes.wintypes.LPWSTR),
        ("dwX",             ctypes.wintypes.DWORD),
        ("dwY",             ctypes.wintypes.DWORD),
        ("dwXSize",         ctypes.wintypes.DWORD),
        ("dwYSize",         ctypes.wintypes.DWORD),
        ("dwXCountChars",   ctypes.wintypes.DWORD),
        ("dwYCountChars",   ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags",         ctypes.wintypes.DWORD),
        ("wShowWindow",     ctypes.wintypes.WORD),
        ("cbReserved2",     ctypes.wintypes.WORD),
        ("lpReserved2",     ctypes.wintypes.LPBYTE),
        ("hStdInput",       ctypes.wintypes.HANDLE),
        ("hStdOutput",      ctypes.wintypes.HANDLE),
        ("hStdError",       ctypes.wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    ctypes.wintypes.HANDLE),
        ("hThread",     ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId",  ctypes.wintypes.DWORD),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid",        ctypes.c_void_p),
        ("Attributes", ctypes.wintypes.DWORD),
    ]


class _TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", _SID_AND_ATTRIBUTES)]


_MEDIUM_IL_SID_BYTES = bytes([
    0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x20, 0x00, 0x00,
])


def _find_explorer_pid() -> Optional[int]:
    if not is_windows():
        return None
    try:
        TH32CS_SNAPPROCESS = 0x00000002

        class _PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize",              ctypes.wintypes.DWORD),
                ("cntUsage",            ctypes.wintypes.DWORD),
                ("th32ProcessID",       ctypes.wintypes.DWORD),
                ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID",        ctypes.wintypes.DWORD),
                ("cntThreads",          ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase",      ctypes.c_long),
                ("dwFlags",             ctypes.wintypes.DWORD),
                ("szExeFile",           ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == ctypes.wintypes.HANDLE(-1).value:
            return None

        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        pids = []
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == "explorer.exe":
                    pids.append(entry.th32ProcessID)
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        kernel32.CloseHandle(snap)

        cur_session = ctypes.wintypes.DWORD(0)
        kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(cur_session))
        for pid in pids:
            sess = ctypes.wintypes.DWORD(0)
            kernel32.ProcessIdToSessionId(pid, ctypes.byref(sess))
            if sess.value == cur_session.value:
                return pid
        return pids[0] if pids else None
    except Exception:
        return None


def _get_medium_primary_token() -> Optional[ctypes.wintypes.HANDLE]:
    if not is_windows():
        return None

    explorer_pid = _find_explorer_pid()
    if not explorer_pid:
        return None

    kernel32 = ctypes.windll.kernel32
    advapi32  = ctypes.windll.advapi32

    hExplorer = kernel32.OpenProcess(_PROCESS_QUERY_INFO, False, explorer_pid)
    if not hExplorer:
        return None

    hToken  = ctypes.wintypes.HANDLE()
    access  = _TOKEN_DUPLICATE | _TOKEN_QUERY | _TOKEN_ASSIGN_PRIMARY
    ok = advapi32.OpenProcessToken(hExplorer, access, ctypes.byref(hToken))
    kernel32.CloseHandle(hExplorer)
    if not ok or not hToken:
        return None

    hPrimary   = ctypes.wintypes.HANDLE()
    dup_access = (
        _TOKEN_ASSIGN_PRIMARY | _TOKEN_DUPLICATE | _TOKEN_QUERY
        | _TOKEN_ADJUST_DEFAULT | _TOKEN_ADJUST_SESSIONID
    )
    ok = advapi32.DuplicateTokenEx(
        hToken, dup_access, None,
        _SecurityImpersonation2, _TokenPrimary,
        ctypes.byref(hPrimary),
    )
    kernel32.CloseHandle(hToken)
    if not ok or not hPrimary:
        return None

    sid_buf  = (ctypes.c_byte * len(_MEDIUM_IL_SID_BYTES))(*_MEDIUM_IL_SID_BYTES)
    label    = _TOKEN_MANDATORY_LABEL()
    label.Label.Sid        = ctypes.cast(sid_buf, ctypes.c_void_p)
    label.Label.Attributes = 0x20
    advapi32.SetTokenInformation(
        hPrimary, _TOKEN_INTEGRITY_LEVEL,
        ctypes.byref(label),
        ctypes.sizeof(label) + ctypes.sizeof(sid_buf),
    )

    return hPrimary


def launch_as_medium_integrity(
    exe_path: str,
    cwd: Optional[str] = None,
) -> Tuple[Optional[int], Optional[ctypes.wintypes.HANDLE], bool]:
    """
    Launch exe_path at Medium integrity level using explorer.exe's token.

    Returns (pid, process_handle, medium_il_succeeded).
    The caller is responsible for closing process_handle via CloseHandle.
    """
    if not is_windows():
        return None, None, False

    hToken = _get_medium_primary_token()
    if not hToken:
        try:
            import subprocess
            proc = subprocess.Popen([exe_path])
            hProc = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x0400, False, proc.pid)
            return proc.pid, hProc if hProc else None, False
        except Exception as exc:
            print_error(f"Launch failed: {exc}")
            return None, None, False

    si  = _STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi  = _PROCESS_INFORMATION()

    creation_flags = 0x10 | 0x20   # CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS
    cmd_buf = ctypes.create_unicode_buffer(exe_path)
    cwd_buf = ctypes.create_unicode_buffer(cwd or os.path.dirname(exe_path) or os.getcwd())

    ok = ctypes.windll.advapi32.CreateProcessWithTokenW(
        hToken, 0, None, cmd_buf, creation_flags, None, cwd_buf,
        ctypes.byref(si), ctypes.byref(pi),
    )
    ctypes.windll.kernel32.CloseHandle(hToken)

    if not ok:
        err = ctypes.windll.kernel32.GetLastError()
        if err == 740:
            # ERROR_ELEVATION_REQUIRED — target requires elevation, retry silently with admin token
            try:
                import subprocess
                proc = subprocess.Popen([exe_path])
                hProc = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x0400, False, proc.pid)
                return proc.pid, hProc if hProc else None, False
            except Exception as exc2:
                print_error(f"Admin-token launch failed: {exc2}")
                return None, None, False
        else:
            print_error(f"CreateProcessWithTokenW failed (error {err}). Attempting direct launch.")
            try:
                import subprocess
                proc = subprocess.Popen([exe_path])
                hProc = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x0400, False, proc.pid)
                return proc.pid, hProc if hProc else None, False
            except Exception as exc2:
                print_error(f"Direct launch failed: {exc2}")
                return None, None, False

    if pi.hThread:
        ctypes.windll.kernel32.CloseHandle(pi.hThread)

    return pi.dwProcessId, pi.hProcess, True


def shutdown_process_gracefully(
    pid: int,
    handle=None,
    timeout_sec: int = 5,
) -> bool:
    """
    Shut down a process and its entire child process tree.

    After TerminateProcess on the parent, enumerates all descendant
    processes via CreateToolhelp32Snapshot and terminates them too.

    Returns True if parent exited gracefully, False if forced.
    """
    if not is_windows() or not pid:
        return False

    import time as _time
    kernel32 = ctypes.windll.kernel32
    user32   = ctypes.windll.user32

    WM_CLOSE          = 0x0010
    WAIT_OBJECT_0     = 0x00000000
    PROCESS_TERMINATE = 0x0001

    def _raw(h):
        if h is None:
            return None
        if isinstance(h, int):
            return h if h else None
        try:
            v = h.value
            return v if v else None
        except AttributeError:
            try:
                return int(h)
            except Exception:
                return None

    raw_handle = _raw(handle)

    child_pids = _enumerate_child_pids(pid)

    @ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    def _enum_cb(hwnd, lparam):
        win_pid = ctypes.wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
        if win_pid.value == pid:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return True

    try:
        user32.EnumWindows(_enum_cb, 0)
    except Exception:
        pass

    for cpid in child_pids:
        @ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        def _child_enum_cb(hwnd, lparam, _cpid=cpid):
            win_pid = ctypes.wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
            if win_pid.value == _cpid:
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            return True
        try:
            user32.EnumWindows(_child_enum_cb, 0)
        except Exception:
            pass

    deadline = _time.time() + timeout_sec
    graceful = False
    while _time.time() < deadline:
        if raw_handle:
            ret = kernel32.WaitForSingleObject(raw_handle, 200)
            if ret == WAIT_OBJECT_0:
                graceful = True
                break
        else:
            hCheck = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not hCheck:
                graceful = True
                break
            kernel32.CloseHandle(hCheck)
            _time.sleep(0.2)

    if not graceful:
        if raw_handle:
            kernel32.TerminateProcess(raw_handle, 1)
            kernel32.WaitForSingleObject(raw_handle, 5000)
        else:
            hProc = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if hProc:
                kernel32.TerminateProcess(hProc, 1)
                kernel32.WaitForSingleObject(hProc, 5000)
                kernel32.CloseHandle(hProc)

    for cpid in child_pids:
        try:
            hChild = kernel32.OpenProcess(PROCESS_TERMINATE, False, cpid)
            if hChild:
                kernel32.TerminateProcess(hChild, 1)
                kernel32.WaitForSingleObject(hChild, 2000)
                kernel32.CloseHandle(hChild)
        except Exception:
            pass

    return graceful


from .json_report import write_json_report


# Backwards-compatibility shim
class ResultLogger:
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file

    def write(self, findings: list, ctx: dict):
        if not self.output_file:
            return
        try:
            write_json_report(findings, ctx, self.output_file)
        except Exception as exc:
            print_error(f"Failed to write report: {exc}")


# ── ScanContext dataclass ─────────────────────────────────────────────────────

@dataclasses.dataclass
class ScanContext:
    """
    Typed container for the scan context dict.
    Modules that still use plain dict access work because ScanContext
    supports __getitem__ / get() via the helper methods below.
    """
    exe_path:          Optional[str]  = None
    service_name:      Optional[str]  = None
    pid:               Optional[int]  = None
    launched_pid:      Optional[int]  = None
    install_dir:       Optional[str]  = None
    extra_strings:     list           = dataclasses.field(default_factory=list)
    verbose:           bool           = False
    is_admin:          bool           = False
    procmon_path:      Optional[str]  = None
    etw_timeout:       int            = 30
    skip_authenticode: bool           = False
    il_label:          str            = "Unknown"
    il_rid:            Optional[int]  = None
    pesec_scan_dir:    bool           = False

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key: str):
        return getattr(self, key)

    def __setitem__(self, key: str, value):
        setattr(self, key, value)
