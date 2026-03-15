import os
import csv as _csv
import dataclasses
import shutil
import subprocess
import sys
import time
import threading
import zipfile
import urllib.request
from typing import Optional, Tuple

from .utils import (print_info, print_warning, print_error, print_success,
                    is_windows, launch_as_medium_integrity, shutdown_process_gracefully)

def _resolve_tool_dir() -> str:

    path = os.path.realpath(__file__)          # resolve symlinks too
    # If loaded from __pycache__, climb out of it first
    if os.path.basename(os.path.dirname(path)) == "__pycache__":
        path = os.path.dirname(os.path.dirname(path))  # up to modules/
    else:
        path = os.path.dirname(path)           # up to modules/
    return os.path.dirname(path)               # up to tool root


_TOOL_DIR    = _resolve_tool_dir()
_LOGS_DIR    = os.path.join(_TOOL_DIR, "Logs")
_FILTERS_DIR = os.path.join(_TOOL_DIR, "filters")

CAPTURE_PML = os.path.join(_LOGS_DIR, "capture.pml")

DEFAULT_RUNTIME_SECONDS = 30
MIN_RUNTIME_SECONDS     = 7

_SYSINTERNALS_INSTALL_DIR = os.path.join(_TOOL_DIR, "sysinternals")
_PROCMON_ZIP_URL          = "https://download.sysinternals.com/files/ProcessMonitor.zip"

# ---------------------------------------------------------------------------
# Service info dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ServiceInfo:
    service_name:    str
    display_name:    str
    exe_path:        str
    current_pid:     Optional[int]
    start_type:      int          # 0=Boot 1=System 2=Auto 3=Demand 4=Disabled
    current_state:   str          # "running", "stopped", "paused", etc.

    # Start-type labels for display
    START_LABELS = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}

    def start_label(self) -> str:
        return self.START_LABELS.get(self.start_type, str(self.start_type))

    def is_running(self) -> bool:
        return self.current_state.lower() == "running"

    def is_critical(self) -> bool:
        """
        Heuristic: a service is treated as potentially critical if it is a
        boot/system-start service OR if its name matches known Windows
        infrastructure service names.  This is used to gate the restart
        warning prompt — it is NOT a security classification.
        """
        _CRITICAL_NAMES = {
            "wininit", "lsass", "services", "smss", "csrss", "winlogon",
            "svchost", "rpcss", "dcomlaunch", "nsi", "plugplay", "eventlog",
            "cryptsvc", "wuauserv", "bfe", "mpssvc", "lanmanserver",
            "lanmanworkstation", "netlogon", "samss", "schedule", "spooler",
        }
        if self.start_type in (0, 1):          # boot or system-start
            return True
        return self.service_name.lower() in _CRITICAL_NAMES


# ---------------------------------------------------------------------------
# Service resolution helpers
# ---------------------------------------------------------------------------

def _sc_queryex(service_name: str) -> Tuple[Optional[int], str]:
    """
    Query service state and PID via ``sc queryex <name>``.

    Primary query method — zero struct alignment risk, works on all Windows
    versions.  Returns (pid, state_string) where state_string is one of:
      running / stopped / paused / start_pending / stop_pending /
      continue_pending / pause_pending / unknown
    """
    _STATE_TOKENS = {
        "RUNNING":          "running",
        "STOPPED":          "stopped",
        "PAUSED":           "paused",
        "START_PENDING":    "start_pending",
        "STOP_PENDING":     "stop_pending",
        "CONTINUE_PENDING": "continue_pending",
        "PAUSE_PENDING":    "pause_pending",
    }
    try:
        result = subprocess.run(
            ["sc", "queryex", service_name],
            capture_output=True, text=True, timeout=10,
        )
        pid:   Optional[int] = None
        state: str           = "unknown"
        for line in result.stdout.splitlines():
            stripped = line.strip()
            upper    = stripped.upper()
            # "STATE              : 4  RUNNING"
            if upper.startswith("STATE"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    for tok in parts[1].split():
                        mapped = _STATE_TOKENS.get(tok.upper())
                        if mapped:
                            state = mapped
                            break
            # "PID                : 44912"
            elif upper.startswith("PID"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    val = parts[1].strip()
                    if val.isdigit() and int(val) != 0:
                        pid = int(val)
        return pid, state
    except Exception:
        return None, "unknown"


def _scm_query_service_state(service_name: str) -> Tuple[Optional[int], str]:
    """
    Return (pid, state_string) for a service.

    Primary:  _sc_queryex  (subprocess — reliable, no struct alignment issues)
    Fallback: QueryServiceStatusEx via ctypes
    """
    if not is_windows():
        return None, "unknown"

    # Primary
    pid, state = _sc_queryex(service_name)
    if state != "unknown":
        return pid, state

    # Fallback: ctypes QueryServiceStatusEx
    try:
        import ctypes, ctypes.wintypes

        SC_MANAGER_CONNECT   = 0x0001
        SERVICE_QUERY_STATUS = 0x0004

        _STATE_MAP_RID = {
            1: "stopped",
            2: "start_pending",
            3: "stop_pending",
            4: "running",
            5: "continue_pending",
            6: "pause_pending",
            7: "paused",
        }

        class SERVICE_STATUS_PROCESS(ctypes.Structure):
            _fields_ = [
                ("dwServiceType",             ctypes.wintypes.DWORD),
                ("dwCurrentState",            ctypes.wintypes.DWORD),
                ("dwControlsAccepted",        ctypes.wintypes.DWORD),
                ("dwWin32ExitCode",           ctypes.wintypes.DWORD),
                ("dwServiceSpecificExitCode", ctypes.wintypes.DWORD),
                ("dwCheckPoint",              ctypes.wintypes.DWORD),
                ("dwWaitHint",                ctypes.wintypes.DWORD),
                ("dwProcessId",               ctypes.wintypes.DWORD),
                ("dwServiceFlags",            ctypes.wintypes.DWORD),
            ]

        advapi32 = ctypes.windll.advapi32
        hSCM = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not hSCM:
            return None, "unknown"

        hSvc = advapi32.OpenServiceW(hSCM, service_name, SERVICE_QUERY_STATUS)
        if not hSvc:
            advapi32.CloseServiceHandle(hSCM)
            return None, "unknown"

        ssp    = SERVICE_STATUS_PROCESS()
        needed = ctypes.wintypes.DWORD(0)
        ok = advapi32.QueryServiceStatusEx(
            hSvc, 0,
            ctypes.byref(ssp), ctypes.sizeof(ssp), ctypes.byref(needed),
        )
        advapi32.CloseServiceHandle(hSvc)
        advapi32.CloseServiceHandle(hSCM)

        if not ok:
            return None, "unknown"

        state = _STATE_MAP_RID.get(ssp.dwCurrentState, "unknown")
        pid   = int(ssp.dwProcessId) if ssp.dwProcessId else None
        return pid, state

    except Exception:
        return None, "unknown"


def _scm_restart_service(
    service_name: str,
    old_pid: Optional[int],
    timeout_sec: int = 45,
) -> Optional[int]:
    """
    Restart a service and return the new PID.

    Sequence
    --------
    1. Send STOP via sc.exe and wait until SCM reports STOPPED (up to 20 s).
    2. Send START via sc.exe and wait until SCM reports RUNNING + new PID
       (up to timeout_sec).
    3. If PID equals old_pid (shared svchost reuse), still return it.

    Without explicit state-wait between STOP and START there is a race where
    START is sent before the SCM has fully torn down the old process, which
    causes sc start to return ERROR_SERVICE_ALREADY_RUNNING (1056) even though
    the service is mid-shutdown.
    """
    # ── Step 1: Stop and wait for STOPPED ────────────────────────────────────
    try:
        subprocess.run(
            ["sc", "stop", service_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
    except Exception as exc:
        print_warning(f"sc stop: {exc}")

    stop_deadline = time.time() + 20
    while time.time() < stop_deadline:
        _, state = _scm_query_service_state(service_name)
        if state == "stopped":
            break
        time.sleep(0.5)
    else:
        _, state = _scm_query_service_state(service_name)
        if state not in ("stopped", "unknown"):
            print_warning(
                f"Service did not reach STOPPED within 20 s (state: {state}). "
                "Attempting START anyway."
            )

    # ── Step 2: Start ─────────────────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["sc", "start", service_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
        if result.returncode not in (0, 1056):
            print_warning(f"sc start returned exit code {result.returncode}.")
    except Exception as exc:
        print_error(f"sc start failed: {exc}")
        return None

    # ── Step 3: Wait for RUNNING + distinct PID ───────────────────────────────
    run_deadline = time.time() + timeout_sec
    while time.time() < run_deadline:
        new_pid, state = _scm_query_service_state(service_name)
        if state == "running" and new_pid and new_pid != old_pid:
            return new_pid
        time.sleep(0.5)

    # Fallback: accept same PID (shared svchost) if state is running
    new_pid, state = _scm_query_service_state(service_name)
    if state == "running" and new_pid:
        return new_pid

    return None


def resolve_service_for_target(
    exe_path: Optional[str] = None,
    service_name: Optional[str] = None,
    pid: Optional[int] = None,
) -> Optional[ServiceInfo]:
    """
    Given any one of the three target specifiers, determine whether the target
    corresponds to a Windows service.  Returns a populated ServiceInfo or None.

    Resolution rules
    ----------------
    --service NAME  → query SCM directly for that service name.
    --exe PATH      → normalise path, enumerate all services, match ImagePath.
    --pid PID       → resolve exe from PID, then match via --exe path.
    """
    if not is_windows():
        return None

    try:
        import winreg
    except ImportError:
        return None

    def _read_service_info(svc_name: str) -> Optional[ServiceInfo]:
        """Read all needed fields from the registry + SCM for svc_name."""
        try:
            key_path = rf"SYSTEM\CurrentControlSet\Services\{svc_name}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                try:
                    img, _ = winreg.QueryValueEx(k, "ImagePath")
                except FileNotFoundError:
                    return None
                img = os.path.expandvars(str(img)).strip()
                # Strip quotes and arguments to get the bare exe path
                if img.startswith('"'):
                    bare_exe = img[1:].split('"')[0]
                else:
                    bare_exe = img.split(" ")[0]

                try:
                    disp, _ = winreg.QueryValueEx(k, "DisplayName")
                    disp = str(disp)
                except Exception:
                    disp = svc_name

                try:
                    start_type, _ = winreg.QueryValueEx(k, "Start")
                    start_type = int(start_type)
                except Exception:
                    start_type = 3

        except Exception:
            return None

        current_pid, current_state = _scm_query_service_state(svc_name)
        return ServiceInfo(
            service_name  = svc_name,
            display_name  = disp,
            exe_path      = bare_exe,
            current_pid   = current_pid,
            start_type    = start_type,
            current_state = current_state,
        )

    # ── --service NAME ────────────────────────────────────────────────────────
    if service_name:
        return _read_service_info(service_name)

    # ── --pid PID → resolve exe, then fall through to exe matching ───────────
    if pid and not exe_path:
        try:
            import ctypes, ctypes.wintypes
            buf  = ctypes.create_unicode_buffer(260)
            size = ctypes.wintypes.DWORD(260)
            h    = ctypes.windll.kernel32.OpenProcess(0x0410, False, pid)
            if h:
                ctypes.windll.kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
                ctypes.windll.kernel32.CloseHandle(h)
                exe_path = buf.value or None
        except Exception:
            pass

    if not exe_path:
        return None

    # ── --exe PATH → enumerate services and compare normalised ImagePath ──────
    try:
        norm_target = os.path.normcase(os.path.abspath(exe_path))
    except Exception:
        norm_target = os.path.normcase(exe_path)

    try:
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
                            bare = img[1:].split('"')[0]
                        else:
                            bare = img.split(" ")[0]
                        try:
                            norm_img = os.path.normcase(os.path.abspath(bare))
                        except Exception:
                            norm_img = os.path.normcase(bare)
                        if norm_img == norm_target:
                            return _read_service_info(svc_name)
                except (PermissionError, Exception):
                    continue
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Auto-install Procmon (Issue 1)
# ---------------------------------------------------------------------------

def _install_procmon(hint: Optional[str] = None) -> Optional[str]:
    _ctx_procmon_hint = hint
    """
    Attempt to install Procmon automatically.

    Strategy:
      1. winget install Microsoft.Sysinternals.ProcessMonitor
      2. Direct ZIP download from the Sysinternals CDN, extracted to
         <tool root>\\sysinternals\\.

    Returns the path to Procmon64.exe if installation succeeded, else None.
    """
    print_info("Attempting automatic Procmon installation…")

    # ── Method 0: Copy from user-supplied path ────────────────────────────────
    user_sysint_path = _ctx_procmon_hint  # set by caller if --procmon was given
    if user_sysint_path and os.path.isfile(user_sysint_path):
        os.makedirs(_SYSINTERNALS_INSTALL_DIR, exist_ok=True)
        dest = os.path.join(_SYSINTERNALS_INSTALL_DIR, os.path.basename(user_sysint_path))
        if os.path.normcase(os.path.abspath(user_sysint_path)) != os.path.normcase(os.path.abspath(dest)):
            shutil.copy2(user_sysint_path, dest)
            print_success(f"  Copied {os.path.basename(user_sysint_path)} → {_SYSINTERNALS_INSTALL_DIR}")
        return dest

    # ── Method 1: winget ─────────────────────────────────────────────────────
    winget = shutil.which("winget")
    if winget:
        print_info("  Trying: winget install Microsoft.Sysinternals.ProcessMonitor")
        try:
            result = subprocess.run(
                [
                    winget, "install",
                    "--id", "Microsoft.Sysinternals.ProcessMonitor",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            if result.returncode == 0:
                # winget installs to the user's local AppData or Program Files
                # Re-run discovery — path is now on PATH or in default locations
                found = _find_procmon()
                if found:
                    print_success(f"  winget install succeeded → {found}")
                    return found
                print_warning("  winget returned 0 but Procmon still not found on PATH.")
        except subprocess.TimeoutExpired:
            print_warning("  winget timed out.")
        except Exception as exc:
            print_warning(f"  winget failed: {exc}")

    # ── Method 2: Direct ZIP download ────────────────────────────────────────
    print_info(f"  Trying: direct download from {_PROCMON_ZIP_URL}")
    zip_tmp = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "ProcessMonitor.zip")
    try:
        os.makedirs(_SYSINTERNALS_INSTALL_DIR, exist_ok=True)
        urllib.request.urlretrieve(_PROCMON_ZIP_URL, zip_tmp)

        with zipfile.ZipFile(zip_tmp, "r") as zf:
            zf.extractall(_SYSINTERNALS_INSTALL_DIR)

        os.remove(zip_tmp)

        candidate = os.path.join(_SYSINTERNALS_INSTALL_DIR, "Procmon64.exe")
        if os.path.isfile(candidate):
            print_success(f"  Direct download succeeded → {candidate}")
            return candidate

        # Older ZIP may contain plain "Procmon.exe"
        candidate2 = os.path.join(_SYSINTERNALS_INSTALL_DIR, "Procmon.exe")
        if os.path.isfile(candidate2):
            print_success(f"  Direct download succeeded → {candidate2}")
            return candidate2

        print_warning("  ZIP extracted but Procmon64.exe / Procmon.exe not found inside.")
        return None

    except Exception as exc:
        print_error(f"  Direct download failed: {exc}")
        try:
            if os.path.exists(zip_tmp):
                os.remove(zip_tmp)
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Procmon discovery
# ---------------------------------------------------------------------------

def _find_procmon(hint: Optional[str] = None) -> Optional[str]:
    if hint and os.path.isfile(hint):
        return hint
    # Preferred install location from _install_procmon()
    for name in ("Procmon64.exe", "Procmon.exe"):
        candidate = os.path.join(_SYSINTERNALS_INSTALL_DIR, name)
        if os.path.isfile(candidate):
            return candidate
    for name in ("Procmon64.exe", "Procmon.exe", "procmon64.exe", "procmon.exe"):
        found = shutil.which(name)
        if found:
            return found
    user = os.environ.get("USERPROFILE", "")
    for root in (
        os.environ.get("ProgramFiles",      r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Tools"),
    ):
        if not root:
            continue
        for sub in ("", "Sysinternals", "SysinternalsSuite"):
            for name in ("Procmon64.exe", "Procmon.exe"):
                p = os.path.join(root, sub, name)
                if os.path.isfile(p):
                    return p
    return None


def _ensure_logs_dir() -> bool:
    try:
        os.makedirs(_LOGS_DIR, exist_ok=True)
        return True
    except Exception as exc:
        print_error(f"Cannot create Logs directory '{_LOGS_DIR}': {exc}")
        return False


def _prepare_procmon_environment() -> None:
    """
    Silently prepare a clean slate before starting any Procmon capture.

    Three actions, all failures swallowed — none of these emit terminal output
    because they are housekeeping, not findings, and a partial failure here does
    not prevent a valid capture:

    1. Force-terminate every running Procmon instance (Procmon64.exe / Procmon.exe).
       This prevents the "Unable to open capture.pml for reading" message box that
       appears when a previous instance left a stale file handle open on the PML.

    2. Delete capture.pml from the Logs directory before Procmon is started so
       Procmon always creates a fresh file.  A truncated PML from an aborted
       previous run cannot be opened by Procmon and triggers the same error box.

    3. Clear the REG_SZ value "Logfile" under
       HKCU\\Software\\Sysinternals\\Process Monitor.
       Procmon persists the last-used backing-file path in this key.  On the next
       launch it attempts to re-open that path; if the file is missing or corrupt
       it shows an error message box.  Blanking the value prevents the lookup.
    """
    # ── 1. Kill existing Procmon instances ────────────────────────────────────
    for exe_name in ("Procmon64.exe", "Procmon.exe"):
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", exe_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except Exception:
            pass

    # Brief pause so the kernel releases any file handles before we delete PML
    time.sleep(0.5)

    # ── 2. Delete stale capture.pml ───────────────────────────────────────────
    if os.path.isfile(CAPTURE_PML):
        try:
            os.remove(CAPTURE_PML)
        except Exception:
            pass

    # ── 3. Clear the Logfile registry value ──────────────────────────────────
    try:
        import winreg
        key_path = r"Software\Sysinternals\Process Monitor"
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            key_path,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(key, "Logfile", 0, winreg.REG_SZ, "")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_procmon_exe(ctx: dict) -> Optional[str]:
    """
    Locate Procmon64.exe.  Caches the result in ctx["procmon_exe"].
    If not found, automatically attempts installation via _install_procmon().
    """
    # Return cached path if already resolved this session
    if ctx.get("procmon_exe"):
        return ctx["procmon_exe"]

    exe = _find_procmon(ctx.get("procmon_path"))
    if exe:
        ctx["procmon_exe"] = exe
        return exe

    print_warning("Procmon64.exe not found — attempting automatic installation.")
    exe = _install_procmon(hint=ctx.get("procmon_path"))
    if exe:
        ctx["procmon_exe"] = exe
        return exe

    print_warning(
        "Procmon could not be installed automatically.\n"
        "    Manual options:\n"
        "      winget install Microsoft.Sysinternals.ProcessMonitor\n"
        "      https://learn.microsoft.com/sysinternals/downloads/procmon\n"
        "      Then use --procmon <path> to point Anvil at the binary."
    )
    return None


def get_filter_path(module_name: str) -> str:
    return os.path.join(_FILTERS_DIR, f"{module_name}.pmc")


def get_csv_path(module_name: str) -> str:
    return os.path.join(_LOGS_DIR, f"{module_name}_capture.csv")


def capture_exists() -> bool:
    return os.path.isfile(CAPTURE_PML)


# ---------------------------------------------------------------------------
# Spinner + countdown (runs in a background thread)
# ---------------------------------------------------------------------------
_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _spinner_thread(total_seconds: int, stop_event: threading.Event):
    """Print a live countdown line that updates in place."""
    frame_idx = 0
    start     = time.time()
    while not stop_event.is_set():
        elapsed   = time.time() - start
        remaining = max(0, total_seconds - int(elapsed))
        frame     = _SPINNER_FRAMES[frame_idx % len(_SPINNER_FRAMES)]
        sys.stdout.write(f"\r    {frame} Capturing... {remaining:3d}s remaining  ")
        sys.stdout.flush()
        frame_idx += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 55 + "\r")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Target process lifecycle
# ---------------------------------------------------------------------------

def _shutdown_target(pid: int, handle: Optional[object]):
    """Shut down the launched target process and its entire process tree."""
    print_info(f"Shutting down target (PID {pid})…")
    graceful = shutdown_process_gracefully(pid, handle, timeout_sec=5)
    if graceful:
        print_success(f"Target (PID {pid}) exited gracefully.")
    else:
        print_info(f"Target (PID {pid}) terminated (process tree cleaned up).")
    if handle is not None:
        try:
            import ctypes
            raw = handle.value if hasattr(handle, "value") else int(handle)
            if raw:
                ctypes.windll.kernel32.CloseHandle(raw)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# PART 1 — Single broad capture + auto-launch target exe
# ---------------------------------------------------------------------------

def run_procmon_capture(
    procmon_exe: str,
    target_exe: Optional[str],
    runtime_seconds: int = DEFAULT_RUNTIME_SECONDS,
) -> Tuple[Optional[str], Optional[int], Optional[object], Optional[int]]:
    """
    Start Procmon, launch target_exe (with Issue 2 messaging), show countdown,
    wait for Procmon's /Runtime to expire, then return
    (pml_path, launched_pid, launched_handle, il_rid).

    il_rid is captured immediately after launch while the process is alive —
    it must NOT be read after the capture window because the process may have
    exited by then (especially installer/launcher EXEs).
    """
    if not is_windows():
        print_warning("Procmon capture requires Windows.")
        return None, None, None, None

    runtime_seconds = max(runtime_seconds, MIN_RUNTIME_SECONDS)

    if not _ensure_logs_dir():
        return None, None, None, None

    _prepare_procmon_environment()

    cmd = [
        procmon_exe,
        "/AcceptEula",
        "/Quiet",
        "/Minimized",
        "/BackingFile", CAPTURE_PML,
        "/Runtime",     str(runtime_seconds),
    ]

    print_info(f"Starting Procmon  ({runtime_seconds}s capture window)…")

    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print_error(f"Procmon executable not found: {procmon_exe}")
        return None, None, None, None
    except Exception as exc:
        print_error(f"Procmon failed to start: {exc}")
        return None, None, None, None

    # Give Procmon 2s to load its kernel driver before launching the target
    time.sleep(2)

    # ── Issue 2: neutral launch messaging ────────────────────────────────────
    launched_pid:    Optional[int]    = None
    launched_handle: Optional[object] = None
    launched_il_rid: Optional[int]    = None   # captured immediately while alive

    if target_exe and os.path.isfile(target_exe):
        print_info(f"Launching target: {target_exe}")
        launched_pid, launched_handle, medium_il_ok = launch_as_medium_integrity(
            exe_path=target_exe,
            cwd=os.path.dirname(target_exe),
        )
        if launched_pid:
            il_tag = " [Medium IL]" if medium_il_ok else ""
            print_info(f"Target PID        : {launched_pid}{il_tag}")
            # Read IL now — process is guaranteed alive at this point.
            # After the capture window it may have already exited.
            from .utils import get_process_integrity as _gpi
            launched_il_rid = _gpi(launched_pid)
        elif not medium_il_ok and launched_pid is None:
            pass
        else:
            print_warning("Target launch failed — capture will proceed without auto-launch.")
    elif target_exe:
        print_warning(f"Target exe not found, skipping auto-launch: {target_exe}")

    print_info("Interact with the application to trigger all code paths.")
    print()

    # ── Countdown spinner — then simple sleep (Issue: WaitForIdle was a no-op) ─
    stop_event = threading.Event()
    spinner    = threading.Thread(
        target=_spinner_thread,
        args=(runtime_seconds, stop_event),
        daemon=True,
    )
    spinner.start()

    # Procmon's /Runtime flag is reliable; just sleep the declared duration.
    time.sleep(runtime_seconds)

    stop_event.set()
    spinner.join()

    # Give Procmon a moment to flush the PML to disk after /Runtime expiry
    time.sleep(3)

    if not os.path.isfile(CAPTURE_PML):
        print_error(f"Capture file not produced: {CAPTURE_PML}")
        print_warning("Possible cause: Procmon requires elevated privileges to load its driver.")
        return None, launched_pid, launched_handle, launched_il_rid

    size_mb = os.path.getsize(CAPTURE_PML) / (1024 * 1024)
    print_success(f"Capture complete : {os.path.basename(CAPTURE_PML)}  ({size_mb:.1f} MB)")
    return CAPTURE_PML, launched_pid, launched_handle, launched_il_rid


# ---------------------------------------------------------------------------
# PART 2 — Per-module filter + CSV export
# ---------------------------------------------------------------------------

def export_filtered_csv(
    procmon_exe: str,
    module_name: str,
    pml_path: Optional[str] = None,
) -> Optional[str]:
    """
    Apply module-specific .pmc filter to the PML and export a CSV.

    Return values
    -------------
    str   — path to the CSV file (may have zero data rows — callers should
            iterate it normally; an empty result set simply means no findings).
    None  — a genuine failure: PML missing, .pmc filter file missing, Procmon
            crashed, or no CSV file was produced at all.

    Distinguishing "filter ran but matched nothing" from "filter is missing"
    is critical: both previously returned None, causing callers to print a
    misleading "filter missing" warning even when the filter existed and ran
    correctly but the application produced no matching events.
    """
    if not is_windows():
        return None

    pml = pml_path or CAPTURE_PML
    if not os.path.isfile(pml):
        print_error(f"[{module_name}] PML not found: {pml}")
        return None

    pmc_path = get_filter_path(module_name)
    if not os.path.isfile(pmc_path):
        # Genuine missing filter — callers may print actionable guidance here.
        print_warning(
            f"[{module_name}] Filter file not found: {pmc_path}\n"
            f"    Create it in Procmon (Filter → Save Filter…) and save to that path."
        )
        return None

    csv_path = get_csv_path(module_name)
    if os.path.isfile(csv_path):
        try:
            os.remove(csv_path)
        except Exception:
            pass

    cmd = [
        procmon_exe,
        "/AcceptEula",
        "/Quiet",
        "/OpenLog",         pml,
        "/LoadConfig",      pmc_path,
        "/SaveApplyFilter",
        "/SaveAs",          csv_path,
    ]

    print_info(f"Exporting filtered CSV for [{module_name}]…")

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        print_error(f"[{module_name}] Procmon CSV export timed out.")
        return None
    except Exception as exc:
        print_error(f"[{module_name}] Procmon export failed: {exc}")
        return None

    time.sleep(2)

    if not os.path.isfile(csv_path):
        print_warning(f"[{module_name}] No CSV file produced — Procmon may have crashed or the filter rejected all events.")
        return None

    row_count = _count_csv_rows(csv_path)

    if row_count == 0:
        # Filter ran successfully but the application produced no matching events
        # during the capture window.  This is NOT an error — return the (empty)
        # CSV path so callers iterate zero rows and produce zero findings silently.
        print_info(
            f"[{module_name}] Filter matched 0 events — "
            "no matching activity observed during capture window."
        )
    else:
        print_success(f"[{module_name}] {row_count} rows exported → {os.path.basename(csv_path)}")

    return csv_path


# ---------------------------------------------------------------------------
# PART 1b — Service-aware capture (start Procmon → restart service → capture)
# ---------------------------------------------------------------------------

def run_procmon_capture_service(
    procmon_exe: str,
    svc_info: "ServiceInfo",
    runtime_seconds: int = DEFAULT_RUNTIME_SECONDS,
) -> Tuple[Optional[str], Optional[int]]:

    if not is_windows():
        print_warning("Procmon capture requires Windows.")
        return None, None

    runtime_seconds = max(runtime_seconds, MIN_RUNTIME_SECONDS)

    if not _ensure_logs_dir():
        return None, None

    _prepare_procmon_environment()

    # old_pid comes from the caller-populated svc_info (already a live query)
    old_pid = svc_info.current_pid

    # ── Step 1: Start Procmon ─────────────────────────────────────────────────
    cmd = [
        procmon_exe,
        "/AcceptEula",
        "/Quiet",
        "/Minimized",
        "/BackingFile", CAPTURE_PML,
        "/Runtime",     str(runtime_seconds),
    ]

    print_info("Starting Procmon…")
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print_error(f"Procmon executable not found: {procmon_exe}")
        return None, None
    except Exception as exc:
        print_error(f"Procmon failed to start: {exc}")
        return None, None

    # ── Step 2: Driver initialisation window ──────────────────────────────────
    time.sleep(2)

    # ── Step 3 + 4: Restart service and detect new PID ────────────────────────
    print_info(f"Restarting service '{svc_info.service_name}'…")
    new_pid = _scm_restart_service(svc_info.service_name, old_pid, timeout_sec=45)

    # Read IL immediately while the service process is guaranteed alive.
    service_il_rid: Optional[int] = None
    if new_pid:
        from .utils import get_process_integrity as _gpi
        service_il_rid = _gpi(new_pid)

    if new_pid and new_pid != old_pid:
        print_success(f"Service restart detected  (PID {old_pid} → {new_pid})")
    elif new_pid:
        print_info(
            f"Service restarted (PID unchanged: {new_pid} — "
            "likely a shared svchost host process)"
        )
    else:
        print_warning(
            "Could not confirm new service PID after restart. "
            "Capture will continue but startup events may be incomplete."
        )

    # ── Step 5: Run capture window ────────────────────────────────────────────
    print_info("Capturing service startup activity…")

    stop_event = threading.Event()
    spinner    = threading.Thread(
        target=_spinner_thread,
        args=(runtime_seconds, stop_event),
        daemon=True,
    )
    spinner.start()
    time.sleep(runtime_seconds)
    stop_event.set()
    spinner.join()

    # Flush delay
    time.sleep(3)

    if not os.path.isfile(CAPTURE_PML):
        print_error(f"Capture file not produced: {CAPTURE_PML}")
        print_warning("Possible cause: Procmon requires elevated privileges to load its driver.")
        return None, new_pid, service_il_rid

    size_mb = os.path.getsize(CAPTURE_PML) / (1024 * 1024)
    print_success(f"Capture complete : {os.path.basename(CAPTURE_PML)}  ({size_mb:.1f} MB)")
    return CAPTURE_PML, new_pid, service_il_rid




def restore_service_state(service_name: str, initial_state: str) -> None:
    """
    Restore a service to its recorded initial state after the scan.

    If the service was RUNNING before the scan, ensure it is running now.
    If it was STOPPED, ensure it is stopped now.
    """
    if not is_windows() or not initial_state:
        return

    current_pid, current_state = _scm_query_service_state(service_name)

    if initial_state == "running" and current_state != "running":
        print_info(f"Restoring service '{service_name}' to RUNNING state…")
        try:
            subprocess.run(
                ["sc", "start", service_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
            # Wait up to 20 s for RUNNING
            deadline = time.time() + 20
            while time.time() < deadline:
                _, state = _scm_query_service_state(service_name)
                if state == "running":
                    print_success(f"Service '{service_name}' is RUNNING.")
                    return
                time.sleep(0.5)
            print_warning(f"Service '{service_name}' did not reach RUNNING within 20 s.")
        except Exception as exc:
            print_warning(f"Could not start service '{service_name}': {exc}")

    elif initial_state in ("stopped", "unknown") and current_state == "running":
        print_info(f"Restoring service '{service_name}' to STOPPED state…")
        try:
            subprocess.run(
                ["sc", "stop", service_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
            deadline = time.time() + 20
            while time.time() < deadline:
                _, state = _scm_query_service_state(service_name)
                if state == "stopped":
                    print_success(f"Service '{service_name}' is STOPPED.")
                    return
                time.sleep(0.5)
            print_warning(f"Service '{service_name}' did not reach STOPPED within 20 s.")
        except Exception as exc:
            print_warning(f"Could not stop service '{service_name}': {exc}")


def cleanup():
    deleted = []
    for fname in (os.listdir(_LOGS_DIR) if os.path.isdir(_LOGS_DIR) else []):
        if fname.endswith(".pml") or fname.endswith(".csv"):
            fpath = os.path.join(_LOGS_DIR, fname)
            try:
                os.remove(fpath)
                deleted.append(fname)
            except Exception:
                pass
    if deleted:
        print_info(f"Cleaned up capture artefacts: {', '.join(deleted)}")


# ---------------------------------------------------------------------------
# CSV utilities
# ---------------------------------------------------------------------------

def _count_csv_rows(csv_path: str) -> int:
    try:
        with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
            return max(0, sum(1 for _ in f) - 1)   # subtract header row
    except Exception:
        return 0


def parse_procmon_csv(csv_path: str):
    """Parse a Procmon-exported CSV and yield normalised row dicts."""
    if not csv_path or not os.path.isfile(csv_path):
        return

    with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            yield {k.strip(): v.strip() for k, v in row.items() if k}


# ---------------------------------------------------------------------------
# PART 1c — Split start / stop capture (used by the new unified scan engine)
# ---------------------------------------------------------------------------
# These two functions replace run_procmon_capture's /Runtime model with an
# explicit start → user-interaction → stop flow so Procmon stays open until
# the assessor has finished interacting with the target.

def start_procmon_capture(procmon_exe: str) -> bool:
    """
    Start Procmon capture without a /Runtime limit.
    Procmon runs indefinitely until stop_procmon_capture() is called.

    Returns True on success, False on failure.
    """
    if not is_windows():
        print_warning("Procmon capture requires Windows.")
        return False

    if not _ensure_logs_dir():
        return False

    _prepare_procmon_environment()

    cmd = [
        procmon_exe,
        "/AcceptEula",
        "/Quiet",
        "/Minimized",
        "/BackingFile", CAPTURE_PML,
    ]

    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print_error(f"Procmon executable not found: {procmon_exe}")
        return False
    except Exception as exc:
        print_error(f"Procmon failed to start: {exc}")
        return False

    # Wait for the kernel driver to initialise before the target is launched
    time.sleep(2)
    return True


def stop_procmon_capture(procmon_exe: str) -> Tuple[Optional[str], float]:
    """
    Stop the running Procmon instance and wait for the PML to be flushed.

    Returns (pml_path, size_mb) on success, (None, 0.0) on failure.
    The caller is responsible for all UI feedback (spinners, success messages).
    """
    try:
        subprocess.run(
            [procmon_exe, "/Terminate"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except Exception as exc:
        print_warning(f"Procmon /Terminate failed: {exc}")

    # Give Procmon time to flush the PML to disk
    time.sleep(3)

    if not os.path.isfile(CAPTURE_PML):
        print_error(f"Capture file not produced: {CAPTURE_PML}")
        print_warning("Possible cause: Procmon requires elevated privileges to load its driver.")
        return None, 0.0

    size_mb = os.path.getsize(CAPTURE_PML) / (1024 * 1024)
    return CAPTURE_PML, size_mb
