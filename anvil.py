#!/usr/bin/env python3
"""
anvil.py – Anvil: Windows Thick Client Security Assessment Tool
===============================================================
Platform : Windows (requires Python 3.8+, must run as Administrator)
"""

# ── Dependency bootstrap (runs before any other import) ──────────────────────
# On first run, any missing packages are installed automatically via pip.
# The process then re-launches itself so all imports resolve cleanly.

import sys
import subprocess
import importlib

_REQUIRED: list[tuple[str, str]] = [
    # (import_name, pip_package_name)
    ("rich",   "rich"),
    ("pefile", "pefile"),
]

def _bootstrap_dependencies() -> bool:
    """
    Check for required packages. Install any that are missing.
    Returns True if any package was installed (caller should re-launch).
    """
    missing = []
    for import_name, pip_name in _REQUIRED:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)

    if not missing:
        return False

    print(f"[ * ] Missing packages: {', '.join(missing)}")
    print(f"[ * ] Installing via pip...")

    for pkg in missing:
        print(f"[ * ]   Installing {pkg}...", end=" ", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg],
            capture_output=True,
        )
        if result.returncode == 0:
            print("done")
        else:
            print("FAILED")
            print(f"[ ! ] Could not install {pkg}. Install manually:")
            print(f"      {sys.executable} -m pip install {pkg}")
            print(result.stderr.decode(errors="replace").strip())
            sys.exit(1)

    return True


if _bootstrap_dependencies():
    # Re-launch with the same arguments so all imports resolve with new packages
    print("[ * ] Re-launching with installed packages...")
    result = subprocess.run([sys.executable] + sys.argv)
    sys.exit(result.returncode)

# ─────────────────────────────────────────────────────────────────────────────

import argparse
import os
import ctypes
from datetime import datetime
from typing import Optional

from modules import (
    dll_hijacking,
    com_hijacking,
    registry_privesc,
    binary_hijacking,
    insecure_configs,
    insecure_install_dir,
    memory_strings,
    symlink_attacks,
    unquoted_service_path,
    pe_security,
    named_pipe_acl,
    procmon_session,
)
from modules.procmon_session import ServiceInfo, resolve_service_for_target
from modules.utils import (
    banner,
    print_section,
    print_info,
    print_warning,
    print_error,
    print_success,
    cvss_range,
    CVSS_RANGES,
    is_windows,
    is_admin,
    resolve_exe_from_service,
    get_process_path_from_pid,
    get_process_integrity,
    integrity_label,
    launch_as_medium_integrity,
    _SECURITY_MANDATORY_SYSTEM_RID,
    _SECURITY_MANDATORY_HIGH_RID,
    BOLD, RED, CYAN, RESET,
)
from modules.json_report import write_json_report
from modules.html_report import generate_html_report

# Rich is optional — only use it when the terminal supports VT sequences
try:
    from modules.utils import _VT_SUPPORTED as _anvil_vt
except ImportError:
    _anvil_vt = True   # assume capable if utils not yet loaded

try:
    if not _anvil_vt:
        raise ImportError("VT not supported")
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich import box
    import sys as _sys
    _RICH = True
    _console = Console(highlight=False, file=_sys.stderr)
except ImportError:
    _RICH = False
    _console = None

_ANVIL_REG_KEY   = r"Software\Anvil"
_ANVIL_TOOLS_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
    "Anvil", "sysinternals",
)

_TOOL_URLS = {
    "Procmon64.exe": {
        "zip":  "https://download.sysinternals.com/files/ProcessMonitor.zip",
        "direct": "https://live.sysinternals.com/procmon.exe",
        "alt_name": "Procmon.exe",
    },
    "handle.exe": {
        "zip":    "https://download.sysinternals.com/files/Handle.zip",
        "direct": "https://live.sysinternals.com/handle.exe",
        "alt_name": "handle64.exe",
    },
    "accesschk.exe": {
        "zip":    "https://download.sysinternals.com/files/AccessChk.zip",
        "direct": "https://live.sysinternals.com/accesschk.exe",
        "alt_name": "accesschk64.exe",
    },
}

_REG_VALUE_MAP = {
    "Procmon64.exe":  "ProcmonPath",
    "handle.exe":     "HandlePath",
    "accesschk.exe":  "AccesschkPath",
}


def _reg_read_tool_paths() -> dict:
    """Read cached tool paths from HKCU\\Software\\Anvil. Returns {exe_name: path}."""
    paths = {}
    if not is_windows():
        return paths
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _ANVIL_REG_KEY) as k:
            for exe_name, val_name in _REG_VALUE_MAP.items():
                try:
                    val, _ = winreg.QueryValueEx(k, val_name)
                    if val and os.path.isfile(str(val)):
                        paths[exe_name] = str(val)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return paths


def _reg_write_tool_path(exe_name: str, path: str) -> None:
    """Persist a resolved tool path under HKCU\\Software\\Anvil."""
    if not is_windows():
        return
    try:
        import winreg
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, _ANVIL_REG_KEY,
            0, winreg.KEY_SET_VALUE
        ) as k:
            val_name = _REG_VALUE_MAP.get(exe_name)
            if val_name:
                winreg.SetValueEx(k, val_name, 0, winreg.REG_SZ, path)
    except Exception:
        pass


def _download_tool(exe_name: str, dest_dir: str) -> Optional[str]:
    """
    Download a single Sysinternals tool to dest_dir.
    Tries direct URL first (if available), then ZIP fallback.
    Returns full path on success, None on failure.
    """
    import urllib.request
    import zipfile as _zipfile

    info     = _TOOL_URLS[exe_name]
    dest     = os.path.join(dest_dir, exe_name)
    os.makedirs(dest_dir, exist_ok=True)

    # ── Direct EXE download ───────────────────────────────────────────────────
    if info["direct"]:
        try:
            print_info(f"Downloading {exe_name} from {info['direct']} …")
            urllib.request.urlretrieve(info["direct"], dest)
            if os.path.isfile(dest) and os.path.getsize(dest) > 4096:
                return dest
            if os.path.exists(dest):
                os.remove(dest)
        except Exception as exc:
            print_warning(f"Direct download failed: {exc}")

    # ── ZIP download + extract ────────────────────────────────────────────────
    zip_url = info["zip"]
    if zip_url:
        tmp_zip = os.path.join(
            os.environ.get("TEMP", dest_dir),
            os.path.basename(zip_url),
        )
        try:
            print_info(f"Downloading {os.path.basename(zip_url)} …")
            urllib.request.urlretrieve(zip_url, tmp_zip)
            with _zipfile.ZipFile(tmp_zip, "r") as zf:
                # Try primary name, then alt name
                for target in (exe_name, info.get("alt_name") or ""):
                    if not target:
                        continue
                    matches = [n for n in zf.namelist()
                               if n.lower().endswith(target.lower())]
                    if matches:
                        out_path = os.path.join(dest_dir, exe_name)
                        with zf.open(matches[0]) as src, open(out_path, "wb") as dst:
                            dst.write(src.read())
                        if os.path.isfile(out_path):
                            return out_path
            print_warning(f"{exe_name} not found inside ZIP.")
        except Exception as exc:
            print_warning(f"ZIP download/extract failed: {exc}")
        finally:
            try:
                if os.path.exists(tmp_zip):
                    os.remove(tmp_zip)
            except Exception:
                pass

    return None


def _bootstrap_sysinternals(ctx: dict) -> None:
    """
    Ensure all Sysinternals tools are available before any module runs.

    Resolution order for each tool:
      1. Explicit CLI flag (--procmon / --handle / --accesschk)
         → binary is copied into %LOCALAPPDATA%\\Anvil\\sysinternals\\ and
           the path is written to the registry cache so subsequent runs are
           fully automatic (flag never needs to be supplied again).
      2. HKCU\\Software\\Anvil registry cache (persistent across runs)
      3. Already on PATH / known install dirs
      4. Download to %LOCALAPPDATA%\\Anvil\\sysinternals\\ (one-time per tool)

    If any tool cannot be resolved via steps 1-4 the function prints a clear
    error message instructing the user which flag(s) to use and calls
    sys.exit(1) — no scan is attempted with missing tools.
    """
    if not is_windows():
        return

    print_section("Dependencies")
    cached = _reg_read_tool_paths()

    # ── Procmon ───────────────────────────────────────────────────────────────
    procmon_path = ctx.get("procmon_path")   # from --procmon flag
    if procmon_path and os.path.isfile(procmon_path):
        dest = os.path.join(_ANVIL_TOOLS_DIR, "Procmon64.exe")
        if os.path.normcase(os.path.abspath(procmon_path)) != os.path.normcase(dest):
            import shutil as _shutil
            os.makedirs(_ANVIL_TOOLS_DIR, exist_ok=True)
            _shutil.copy2(procmon_path, dest)
            print_info(f"Procmon : copied to {dest}")
            procmon_path = dest
        ctx["procmon_exe"] = procmon_path
        _reg_write_tool_path("Procmon64.exe", procmon_path)
        print_success(f"Procmon : {procmon_path}  (--procmon flag)")
    elif cached.get("Procmon64.exe"):
        ctx["procmon_exe"] = cached["Procmon64.exe"]
        print_success(f"Procmon : {cached['Procmon64.exe']}  (cached)")
    else:
        # Try PATH / known dirs first
        found = procmon_session._find_procmon()
        if found:
            ctx["procmon_exe"] = found
            _reg_write_tool_path("Procmon64.exe", found)
            print_success(f"Procmon : {found}  (found on PATH)")
        else:
            print_warning("Procmon not found — downloading …")
            downloaded = _download_tool("Procmon64.exe", _ANVIL_TOOLS_DIR)
            if downloaded:
                ctx["procmon_exe"] = downloaded
                _reg_write_tool_path("Procmon64.exe", downloaded)
                print_success(f"Procmon : {downloaded}  (downloaded)")
            else:
                ctx["_tool_download_failed"] = ctx.get("_tool_download_failed", [])
                ctx["_tool_download_failed"].append(("Procmon64.exe", "--procmon"))

    # ── handle.exe ────────────────────────────────────────────────────────────
    handle_path = ctx.get("handle_path")   # from --handle flag
    if handle_path and os.path.isfile(handle_path):
        dest = os.path.join(_ANVIL_TOOLS_DIR, "handle.exe")
        if os.path.normcase(os.path.abspath(handle_path)) != os.path.normcase(dest):
            import shutil as _shutil
            os.makedirs(_ANVIL_TOOLS_DIR, exist_ok=True)
            _shutil.copy2(handle_path, dest)
            print_info(f"handle  : copied to {dest}")
            handle_path = dest
        ctx["handle_exe"] = handle_path
        _reg_write_tool_path("handle.exe", handle_path)
        print_success(f"handle  : {handle_path}  (--handle flag)")
    elif cached.get("handle.exe"):
        ctx["handle_exe"] = cached["handle.exe"]
        print_success(f"handle  : {cached['handle.exe']}  (cached)")
    else:
        import shutil as _shutil
        found = (_shutil.which("handle.exe") or _shutil.which("handle64.exe") or
                 _shutil.which("handle"))
        if found:
            ctx["handle_exe"] = found
            _reg_write_tool_path("handle.exe", found)
            print_success(f"handle  : {found}  (found on PATH)")
        else:
            print_warning("handle.exe not found — downloading …")
            downloaded = _download_tool("handle.exe", _ANVIL_TOOLS_DIR)
            if downloaded:
                ctx["handle_exe"] = downloaded
                _reg_write_tool_path("handle.exe", downloaded)
                print_success(f"handle  : {downloaded}  (downloaded)")
            else:
                ctx["_tool_download_failed"] = ctx.get("_tool_download_failed", [])
                ctx["_tool_download_failed"].append(("handle.exe", "--handle"))

    # ── accesschk.exe ─────────────────────────────────────────────────────────
    accesschk_path = ctx.get("accesschk_path")   # from --accesschk flag
    if accesschk_path and os.path.isfile(accesschk_path):
        dest = os.path.join(_ANVIL_TOOLS_DIR, "accesschk.exe")
        if os.path.normcase(os.path.abspath(accesschk_path)) != os.path.normcase(dest):
            import shutil as _shutil
            os.makedirs(_ANVIL_TOOLS_DIR, exist_ok=True)
            _shutil.copy2(accesschk_path, dest)
            print_info(f"accesschk: copied to {dest}")
            accesschk_path = dest
        ctx["accesschk_exe"] = accesschk_path
        _reg_write_tool_path("accesschk.exe", accesschk_path)
        print_success(f"accesschk: {accesschk_path}  (--accesschk flag)")
    elif cached.get("accesschk.exe"):
        ctx["accesschk_exe"] = cached["accesschk.exe"]
        print_success(f"accesschk: {cached['accesschk.exe']}  (cached)")
    else:
        import shutil as _shutil
        found = (_shutil.which("accesschk.exe") or _shutil.which("accesschk64.exe") or
                 _shutil.which("accesschk"))
        if found:
            ctx["accesschk_exe"] = found
            _reg_write_tool_path("accesschk.exe", found)
            print_success(f"accesschk: {found}  (found on PATH)")
        else:
            print_warning("accesschk.exe not found — downloading …")
            downloaded = _download_tool("accesschk.exe", _ANVIL_TOOLS_DIR)
            if downloaded:
                ctx["accesschk_exe"] = downloaded
                _reg_write_tool_path("accesschk.exe", downloaded)
                print_success(f"accesschk: {downloaded}  (downloaded)")
            else:
                ctx["_tool_download_failed"] = ctx.get("_tool_download_failed", [])
                ctx["_tool_download_failed"].append(("accesschk.exe", "--accesschk"))

    # ── Abort if any tool failed to download ──────────────────────────────────
    failed = ctx.get("_tool_download_failed", [])
    if failed:
        print()
        if _RICH and _console:
            _console.print("  [bold red][ - ][/bold red] [red]Required Sysinternals tools missing[/red]")
            for i, (exe_name, _) in enumerate(failed):
                connector = "└─" if i == len(failed) - 1 else "├─"
                _console.print(f"        [dim]{connector}[/dim] {exe_name}")
            print()
            _console.print("  [bold white][ * ][/bold white] Possible causes")
            _console.print("        [dim]├─[/dim] Network connectivity issues")
            _console.print("        [dim]└─[/dim] Firewall / proxy blocking downloads")
            print()
            _console.print("  [bold white][ * ][/bold white] Manual download")
            _console.print("        https://learn.microsoft.com/en-us/sysinternals/downloads/")
            print()
            _console.print("  [bold white][ * ][/bold white] Re-run with explicit paths")
            for i, (exe_name, flag) in enumerate(failed):
                connector = "└─" if i == len(failed) - 1 else "├─"
                _console.print(f"        [dim]{connector}[/dim] {flag:<13} [yellow]<Path>[/yellow]")
        else:
            print("  [ - ] Required Sysinternals tools missing")
            for i, (exe_name, _) in enumerate(failed):
                connector = "└─" if i == len(failed) - 1 else "├─"
                print(f"        {connector} {exe_name}")
            print()
            print("  [ * ] Possible causes")
            print("        ├─ Network connectivity issues")
            print("        └─ Firewall / proxy blocking downloads")
            print()
            print("  [ * ] Manual download")
            print("        https://learn.microsoft.com/en-us/sysinternals/downloads/")
            print()
            print("  [ * ] Re-run with explicit paths")
            for i, (exe_name, flag) in enumerate(failed):
                connector = "└─" if i == len(failed) - 1 else "├─"
                print(f"        {connector} {flag:<13} <Path>")
        print()
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI help
# ---------------------------------------------------------------------------

def _print_help():
    if not _RICH:
        print("Anvil — Windows Thick Client Security Assessment Tool")
        print()
        print("Usage: python anvil.py [--exe PATH | --service NAME | --pid PID] [options]")
        return

    _console.print()
    _console.print("[bold cyan]Anv1L[/bold cyan]  [white]Windows Thick Client Security Assessment[/white]")
    _console.print("[cyan]─────────────────────────────────────────────[/cyan]")
    _console.print()

    # Target
    t = Table(show_header=True, header_style="bold cyan", border_style="cyan",
              box=box.SQUARE, show_lines=True, expand=False)
    t.add_column("Flag",        style="white",  min_width=28, no_wrap=True)
    t.add_column("Description", style="white")
    t.add_row("--exe PATH",     "Target executable. Launched at Medium IL for capture.")
    t.add_row("--service NAME", "Windows service name. Exe resolved from registry.")
    t.add_row("--pid PID",      "Attach to an already-running process by PID.")
    _console.print("[cyan]Target (one required)[/cyan]")
    _console.print(t)
    _console.print()

    # Modules
    m = Table(show_header=True, header_style="bold cyan", border_style="cyan",
              box=box.SQUARE, show_lines=True, expand=False)
    m.add_column("Flag",        style="white",  min_width=28, no_wrap=True)
    m.add_column("Default",     style="yellow", min_width=10)
    m.add_column("Description", style="white")
    m.add_row("--modules LIST",  "all",   "Comma-separated module names.")
    m.add_row("  dll",           "",      "DLL hijacking (Procmon + static PE import)")
    m.add_row("  com",           "",      "COM server hijacking (binary scan + registry)")
    m.add_row("  registry",      "",      "Insecure registry key ACLs")
    m.add_row("  binary",        "",      "Binary / phantom EXE hijacking")
    m.add_row("  configs",       "",      "Insecure configuration files (writable .ini/.xml)")
    m.add_row("  installdir",    "",      "Insecure installation directory ACLs")
    m.add_row("  memory",        "",      "Sensitive strings in process memory")
    m.add_row("  symlink",       "",      "Symlink attack vectors")
    m.add_row("  unquoted",      "",      "Unquoted service path privilege escalation")
    m.add_row("  pesec",         "",      "PE binary mitigation flags (ASLR, DEP, CFG...)")
    m.add_row("  pipes",         "",      "Named pipe ACL & impersonation surface (handle.exe)")
    _console.print("[cyan]Modules[/cyan]")
    _console.print(m)
    _console.print()

    # Procmon + Handle / Accesschk (combined)
    p = Table(show_header=True, header_style="bold cyan", border_style="cyan",
              box=box.SQUARE, show_lines=True, expand=False)
    p.add_column("Flag",        style="white",  min_width=28, no_wrap=True)
    p.add_column("Default",     style="yellow", min_width=10)
    p.add_column("Description", style="white")
    p.add_row("--procmon PATH",        "auto", "Path to Procmon64.exe. Auto-installed if absent.")
    p.add_row("--procmon-runtime SEC", "30",   f"Capture window (minimum {procmon_session.MIN_RUNTIME_SECONDS}s).")
    p.add_row("--handle PATH",         "auto", "Path to handle.exe. Auto-downloaded if absent.")
    p.add_row("--accesschk PATH",      "auto", "Path to accesschk.exe. Auto-downloaded if absent.")
    _console.print("[cyan]Sysinternals Tools[/cyan]")
    _console.print(p)
    _console.print()

    # Output
    o = Table(show_header=True, header_style="bold cyan", border_style="cyan",
              box=box.SQUARE, show_lines=True, expand=False)
    o.add_column("Flag",        style="white",  min_width=28, no_wrap=True)
    o.add_column("Default",     style="yellow", min_width=10)
    o.add_column("Description", style="white")
    o.add_row("--report FILE",           "none",  "Generate a report (.json or .html — extension determines format).")
    o.add_row("--verbose",               "off",   "Print full finding details in terminal.")
    o.add_row("--no-color",              "off",   "Disable ANSI colour output.")
    o.add_row("--skip-authenticode",     "off",   "Skip Authenticode checks (faster for large dirs).")
    o.add_row("--scan-install-dir",      "off",   "Scan all DLLs in install dir for PE mitigations.")
    o.add_row("--memory-strings STR,...","none",  "Extra comma-separated strings to match in memory.")
    _console.print("[cyan]Output[/cyan]")
    _console.print(o)
    _console.print()

    _console.print("[cyan]Examples[/cyan]")
    _console.print('  python anvil.py --exe "C:\\\\App\\\\app.exe" --report report.html')
    _console.print('  python anvil.py --exe "C:\\\\App\\\\app.exe" --procmon-runtime 60 --scan-install-dir')
    _console.print('  python anvil.py --service VulnSvc --modules dll,symlink,unquoted')
    _console.print('  python anvil.py --pid 1234 --report report.html --verbose')
    _console.print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

class _HelpAction(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest,
                         default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        _print_help()
        parser.exit()


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="anvil",
        description="Anvil — Windows Thick Client Security Assessment Tool",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action=_HelpAction)

    target = parser.add_mutually_exclusive_group(required=False)
    target.add_argument("--exe",     metavar="PATH", help="Target executable path.")
    target.add_argument("--service", metavar="NAME", help="Windows service name.")
    target.add_argument("--pid",     metavar="PID",  type=int, help="PID of running process.")

    parser.add_argument("--modules",  metavar="LIST",    default="all")
    parser.add_argument("--report",   metavar="FILE",    default=None)
    parser.add_argument("--procmon",  metavar="PATH",    default=None)
    parser.add_argument("--procmon-runtime", metavar="SECONDS", type=int, default=30)
    parser.add_argument("--memory-strings",  metavar="STRINGS", default="")
    parser.add_argument("--verbose",          action="store_true")
    parser.add_argument("--no-color",         action="store_true")
    parser.add_argument("--skip-authenticode", dest="skip_authenticode", action="store_true")
    parser.add_argument("--scan-install-dir",  dest="scan_install_dir",  action="store_true")
    parser.add_argument("--handle",     metavar="PATH", default=None,
                        help="Path to handle.exe. Auto-downloaded if absent.")
    parser.add_argument("--accesschk",  metavar="PATH", default=None,
                        help="Path to accesschk.exe. Auto-downloaded if absent.")

    args = parser.parse_args()

    if not args.exe and not args.service and not args.pid:
        _print_help()
        parser.exit(1)

    return args


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

def select_modules(module_arg: str) -> tuple:
    """
    Returns (procmon_mods, live_mods, static_mods, needs_procmon, needs_live_process)

    procmon_mods  — modules requiring a Procmon PML capture
    live_mods     — modules requiring a running PID but no Procmon
    static_mods   — modules that operate on the binary/registry with no live process
    needs_procmon       — True when procmon_mods is non-empty
    needs_live_process  — True when procmon_mods or live_mods is non-empty
    """
    # (display_name, run_func, category)
    ALL_MODULE_DEFS = {
        "dll":        ("DLL Hijacking",                   dll_hijacking.run,         "procmon"),
        "com":        ("COM Hijacking",                   com_hijacking.run,         "procmon"),
        "binary":     ("Binary / Phantom EXE Hijacking",  binary_hijacking.run,      "procmon"),
        "configs":    ("Insecure Configuration Files",    insecure_configs.run,      "procmon"),
        "symlink":    ("Symlink Attack Vectors",          symlink_attacks.run,       "procmon"),
        "memory":     ("Sensitive Strings in Memory",     memory_strings.run,        "live"),
        "pipes":      ("Named Pipe ACL",                  named_pipe_acl.run,        "live"),
        "registry":   ("Insecure Registry Keys",          registry_privesc.run,      "static"),
        "installdir": ("Insecure Installation Directory", insecure_install_dir.run,  "static"),
        "unquoted":   ("Unquoted Service Path",           unquoted_service_path.run, "static"),
        "pesec":      ("PE Security Mitigations",         pe_security.run,           "static"),
    }

    if module_arg.strip().lower() == "all":
        keys = list(ALL_MODULE_DEFS.keys())
    else:
        keys = []
        for k in module_arg.split(","):
            k = k.strip().lower()
            if k in ALL_MODULE_DEFS:
                keys.append(k)
            else:
                print_warning(f"Unknown module '{k}' — skipping.")

    procmon_mods = [(n, f) for k in keys
                    if ALL_MODULE_DEFS[k][2] == "procmon"
                    for n, f, _ in (ALL_MODULE_DEFS[k],)]
    live_mods    = [(n, f) for k in keys
                    if ALL_MODULE_DEFS[k][2] == "live"
                    for n, f, _ in (ALL_MODULE_DEFS[k],)]
    static_mods  = [(n, f) for k in keys
                    if ALL_MODULE_DEFS[k][2] == "static"
                    for n, f, _ in (ALL_MODULE_DEFS[k],)]

    needs_procmon      = bool(procmon_mods)
    needs_live_process = bool(procmon_mods or live_mods)

    return procmon_mods, live_mods, static_mods, needs_procmon, needs_live_process


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def build_context(args) -> dict:
    ctx = {
        "exe_path":          None,
        "service_name":      None,
        "pid":               None,
        "launched_pid":      None,
        "install_dir":       None,
        "extra_strings":     [s.strip() for s in args.memory_strings.split(",") if s.strip()],
        "verbose":           args.verbose,
        "is_admin":          is_admin(),
        "procmon_path":      args.procmon,
        "procmon_exe":       None,
        "etw_timeout":       args.procmon_runtime,
        "skip_authenticode": getattr(args, "skip_authenticode", False),
        "pesec_scan_dir":    getattr(args, "scan_install_dir", False),
        "handle_path":       getattr(args, "handle",    None),
        "accesschk_path":    getattr(args, "accesschk", None),
        "il_label":          "Unknown",
        "il_rid":            None,
    }

    if args.exe:
        exe = os.path.abspath(args.exe)
        if not os.path.isfile(exe):
            print_error(f"Executable not found: {exe}")
            sys.exit(1)
        ctx["exe_path"]    = exe
        ctx["install_dir"] = os.path.dirname(exe)

    elif args.service:
        ctx["service_name"] = args.service
        exe, error = resolve_exe_from_service(args.service)
        if error:
            print_error(f"Could not resolve service binary: {error}")
            sys.exit(1)
        ctx["exe_path"]    = exe
        ctx["install_dir"] = os.path.dirname(exe) if exe else None
        print_info(f"Service [yellow]{args.service}[/yellow] resolved to: [yellow]{exe}[/yellow]"
                   if _RICH else f"Service '{args.service}' resolved to: {exe}")

    elif args.pid:
        ctx["pid"] = args.pid
        # Validate the PID exists before doing anything else
        import ctypes as _ct
        _SYNCHRONIZE = 0x00100000
        _h = _ct.windll.kernel32.OpenProcess(_SYNCHRONIZE, False, args.pid) if is_windows() else None
        if _h:
            _ct.windll.kernel32.CloseHandle(_h)
            _pid_alive = True
        else:
            _pid_alive = not is_windows()   # non-Windows: assume alive (no OpenProcess)
        if not _pid_alive:
            print_error(f"PID {args.pid} does not exist or has already exited.")
            print_error("Aborting scan.")
            sys.exit(1)
        exe = get_process_path_from_pid(args.pid)
        if exe:
            ctx["exe_path"]    = exe
            ctx["install_dir"] = os.path.dirname(exe)
            print_info(f"PID {args.pid} resolved to: [yellow]{exe}[/yellow]"
                       if _RICH else f"PID {args.pid} resolved to: {exe}")
        else:
            print_error(f"Could not resolve executable for PID {args.pid}.")
            print_error("Aborting scan.")
            sys.exit(1)

    return ctx


# ---------------------------------------------------------------------------
# Finding printer
# ---------------------------------------------------------------------------

def _print_finding(f: dict, verbose: bool):
    severity = f.get("severity", "P5")
    msg      = f.get("message",  "")
    detail   = f.get("detail",   "")

    if not msg:
        return  # tree-format modules print their own output; nothing to show here

    # Findings marked as tree-printed are displayed by the module's own tree
    # printer — skip them here to avoid duplicating output.
    if f.get("_tree_printed"):
        return

    if _RICH:
        sev_style = {
            "P1": "[bold red]",
            "P2": "[red]",
            "P3": "[yellow]",
            "P4": "[cyan]",
            "P5": "[white]",
        }.get(severity, "[white]")
        prefix = "[ - ]" if severity in ("P1", "P2", "P3") else "[ * ]"
        _console.print(f"  {sev_style}{prefix}[/] [{severity}] {msg}")
    else:
        if severity in ("P1", "P2"):
            prefix = "[ - ]"
            print(f"\033[91m  {prefix} [{severity}] {msg}\033[0m")
        elif severity == "P3":
            print(f"\033[93m  [ - ] [{severity}] {msg}\033[0m")
        elif severity == "P4":
            print(f"\033[96m  [ * ] [{severity}] {msg}\033[0m")
        else:
            print(f"  [ * ] [{severity}] {msg}")

    if detail and verbose:
        for line in detail.strip().splitlines():
            print(f"          {line}")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def _print_summary(all_findings: list, scan_start: str, scan_end: str):
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0}
    for f in all_findings:
        sev = f.get("severity", "P5")
        counts[sev] = counts.get(sev, 0) + 1

    if _RICH:
        tbl = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="cyan",
            box=box.SQUARE,
            show_lines=True,
            expand=False,
        )
        tbl.add_column("Severity",           style="bold",  min_width=14, justify="left")
        tbl.add_column("Count",              style="white", min_width=7,  justify="center")
        tbl.add_column("Typical CVSS Range", style="white", min_width=20, justify="center")

        _STYLES = {
            "P1": "bold red",
            "P2": "red",
            "P3": "yellow",
            "P4": "cyan",
            "P5": "white",
        }
        _LABELS = {
            "P1": "P1 – Critical",
            "P2": "P2 – High",
            "P3": "P3 – Misconfiguration",
            "P4": "P4 – Low Impact",
            "P5": "P5 – Informational",
        }
        for sev in ["P1", "P2", "P3", "P4", "P5"]:
            cvss = cvss_range(sev)
            cvss_cell = f"[dim]{cvss}[/dim]" if sev == "P5" else cvss
            tbl.add_row(
                f"[{_STYLES[sev]}]{_LABELS[sev]}[/{_STYLES[sev]}]",
                str(counts[sev]),
                cvss_cell,
            )

        _console.print()
        _console.print(tbl)
        _console.print(f"  Started : {scan_start}")
        _console.print(f"  Ended   : {scan_end}")
        _console.print()
    else:
        print_section("SUMMARY")
        print(f"  {'Severity':<14} {'Count':>5}   CVSS Range")
        print(f"  {'─' * 40}")
        for sev in ["P1", "P2", "P3", "P4", "P5"]:
            print(f"  {sev:<14} {counts[sev]:>5}   {cvss_range(sev)}")
        print(f"\n  Started : {scan_start}")
        print(f"  Ended   : {scan_end}\n")


def _print_progress_bar(done: int, total: int, width: int = 40):
    """Print an in-place progress bar: [████░░░░░░]  N/M  module name."""
    filled = int(width * done / total) if total else width
    bar    = "█" * filled + "░" * (width - filled)
    pct    = int(100 * done / total) if total else 100
    if _RICH:
        _console.print(f"  [cyan][{bar}][/cyan]  {pct}%", end="\r")
    else:
        print(f"  [{bar}]  {pct}%", end="\r", flush=True)




def _prompt_running_service(svc_info: ServiceInfo) -> bool:
    """
    Warn that the target is a running service and ask the user to confirm.
    Returns True to proceed, False to abort.
    """
    if _RICH:
        _console.print()
        _console.print("[yellow][ ! ][/yellow] The target is a running Windows service.")
        _console.print(
            "[yellow][ ! ][/yellow] Stopping or restarting it may cause dependent "
            "applications to crash or lead to system instability. Proceed? [Y/N]"
        )
    else:
        print()
        print("[ ! ] The target is a running Windows service.")
        print("[ ! ] Stopping or restarting it may cause dependent applications to crash "
              "or lead to system instability. Proceed? [Y/N]")
    try:
        answer = input("  > ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        answer = "n"
    print()
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    if not is_windows():
        print_error("Anvil requires Windows.")
        sys.exit(1)

    if not is_admin():
        if _RICH:
            _console.print()
            _console.print("[red][ - ] Anvil must be run as Administrator.[/red]")
            _console.print("      Right-click your terminal and select 'Run as administrator'.")
            _console.print()
        else:
            print(f"\n  [ - ] Anvil must be run as Administrator.")
            print(f"        Right-click your terminal and select 'Run as administrator'.\n")
        sys.exit(1)

    runtime = args.procmon_runtime
    if runtime < procmon_session.MIN_RUNTIME_SECONDS:
        print_warning(
            f"--procmon-runtime {runtime}s is below minimum "
            f"({procmon_session.MIN_RUNTIME_SECONDS}s). Adjusted."
        )
        runtime = procmon_session.MIN_RUNTIME_SECONDS

    banner()
    print_success("Running as Administrator.")

    scan_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_info(f"Scan started: {scan_start}")
    print()

    ctx = build_context(args)

    # ── Sysinternals bootstrap (download all tools upfront if needed) ─────────
    # This runs before ANY module starts so no module ever blocks mid-scan
    # waiting for a network download.  Resolved paths are cached in the registry
    # at HKCU\Software\Anvil so subsequent runs are instant.
    _bootstrap_sysinternals(ctx)

    procmon_mods, live_mods, static_mods, needs_procmon, needs_live_process = \
        select_modules(args.modules)
    all_modules_ordered = procmon_mods + live_mods + static_mods
    all_findings        = []
    launched_handle     = None
    anvil_launched      = False   # True only when Anvil spawned the process itself
    _initial_svc_state  = None    # Recorded before any service restart; restored at end

    # ── Step 1: Target identification ─────────────────────────────────────────
    svc_info: Optional[ServiceInfo] = resolve_service_for_target(
        exe_path     = ctx.get("exe_path"),
        service_name = ctx.get("service_name"),
        pid          = ctx.get("pid"),
    )

    if svc_info:
        if not ctx.get("service_name"):
            ctx["service_name"] = svc_info.service_name
        if not ctx.get("exe_path") and svc_info.exe_path:
            ctx["exe_path"]    = svc_info.exe_path
            ctx["install_dir"] = os.path.dirname(svc_info.exe_path)

        live_pid, live_state = procmon_session._sc_queryex(svc_info.service_name)
        svc_info.current_pid   = live_pid
        svc_info.current_state = live_state

    # ── Step 2: Launch target (once) if any module needs a live process ───────
    # Rules:
    #   - If caller supplied --pid, attach to that PID — never launch anything.
    #   - If target is a service, read running PID from SCM (no restart here;
    #     service Procmon path restarts atomically in Step 3).
    #   - Otherwise launch the exe at Medium IL once and track launched_pid.
    #   - Static-only scans skip this step entirely.
    procmon_exe = None

    _target_warnings: list = []

    medium_il_ok = False

    if needs_live_process:
        if ctx.get("pid"):
            il_direct = get_process_integrity(ctx["pid"])
            if il_direct is not None:
                ctx["il_rid_captured"] = il_direct

        elif svc_info:
            live_pid, _ = procmon_session._sc_queryex(svc_info.service_name)
            if live_pid:
                ctx["pid"] = live_pid
                il_direct  = get_process_integrity(live_pid)
                if il_direct is not None:
                    ctx["il_rid_captured"] = il_direct
            else:
                _target_warnings.append(
                    f"Service '{svc_info.service_name}' is not running — "
                    "live-process modules may produce no results."
                )

        else:
            exe_path = ctx.get("exe_path")
            if exe_path and os.path.isfile(exe_path):
                launched_pid, launched_handle, medium_il_ok = launch_as_medium_integrity(
                    exe_path = exe_path,
                    cwd      = os.path.dirname(exe_path),
                )
                if launched_pid:
                    ctx["launched_pid"] = launched_pid
                    ctx["pid"]          = launched_pid
                    anvil_launched      = True
                    il_direct = get_process_integrity(launched_pid)
                    if il_direct is not None:
                        ctx["il_rid_captured"] = il_direct
                else:
                    _target_warnings.append("Target launch failed — live-process modules may produce no results.")
            else:
                _target_warnings.append("No exe path available — live-process modules will produce no results.")

    # ── Print Target section (all fields together) ────────────────────────────
    def _exe_arch(path: str) -> str:
        """Return 'x64', 'x86', or 'Unknown' by reading the PE header."""
        try:
            with open(path, "rb") as _f:
                _f.seek(0x3C)
                pe_offset = int.from_bytes(_f.read(4), "little")
                _f.seek(pe_offset + 4)          # skip "PE\0\0"
                machine = int.from_bytes(_f.read(2), "little")
            if machine == 0x8664:
                return "x64"
            if machine in (0x014C, 0x0200):
                return "x86"
            return f"Unknown (0x{machine:04X})"
        except Exception:
            return "Unknown"

    def _file_size_str(path: str) -> str:
        try:
            size = os.path.getsize(path)
            for unit in ("B", "KB", "MB", "GB"):
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        except Exception:
            return "N/A"

    def _manifest_integrity(path: str) -> str:
        """
        Read the requested execution level from the PE manifest.
        Returns 'Requires Administrator', 'Highest Available', 'Medium IL (asInvoker)', or 'Unknown'.
        """
        try:
            with open(path, "rb") as _f:
                data = _f.read()
            if b"requireAdministrator" in data:
                return "Requires Administrator"
            if b"highestAvailable" in data:
                return "Highest Available"
            if b"asInvoker" in data:
                return "Medium IL (asInvoker)"
            return "No elevation manifest"
        except Exception:
            return "Unknown"

    print_section("Target")

    exe_path_display = ctx.get("exe_path") or (svc_info.exe_path if svc_info else "N/A")
    pid_display      = ctx.get("pid")

    # Integrity source depends on target type:
    #   Service  → query the actual process token (services run as SYSTEM/High,
    #              not what the manifest says — manifest is irrelevant here).
    #   EXE      → read the requestedExecutionLevel from the PE manifest.
    if svc_info and pid_display:
        _svc_il_rid = get_process_integrity(pid_display)
        il_str = integrity_label(_svc_il_rid).upper() if _svc_il_rid is not None else "Unknown"
    elif exe_path_display and exe_path_display != "N/A":
        il_str = _manifest_integrity(exe_path_display)
    else:
        il_str = "Unknown"

    if svc_info:
        state_str = svc_info.current_state.upper() + (
            f" (PID: {svc_info.current_pid})" if svc_info.current_pid else ""
        )
        if _RICH:
            print_info(f"Service  : [yellow]{svc_info.display_name}[/yellow]")
            print_info(f"Binary   : [yellow]{exe_path_display}[/yellow]")
            print_info(f"State    : [yellow]{state_str}[/yellow]")
        else:
            print_info(f"Service  : {svc_info.display_name}")
            print_info(f"Binary   : {exe_path_display}")
            print_info(f"State    : {state_str}")
    else:
        if _RICH:
            print_info(f"Binary   : [yellow]{exe_path_display}[/yellow]")
        else:
            print_info(f"Binary   : {exe_path_display}")
        # Only show PID for non-service targets (services show it in State line)
        if pid_display:
            il_tag = "  [Medium IL]" if (anvil_launched and medium_il_ok) else ""
            print_info(f"Target PID       : {pid_display}{il_tag}")

    print_info(f"Target Integrity  : {il_str}")

    if exe_path_display and exe_path_display != "N/A":
        print_info(f"Architecture     : {_exe_arch(exe_path_display)}")
        print_info(f"File Size        : {_file_size_str(exe_path_display)}")

    for _w in _target_warnings:
        print_warning(_w)

    print()

    # ── Step 3: Start Procmon (if required) ───────────────────────────────────
    _service_capture_complete = False   # True after run_procmon_capture_service returns

    # ── Live-only interaction gate ────────────────────────────────────────────
    # When only live modules (e.g. memory, pipes) are requested — no Procmon —
    # the process is already running but the user still needs time to interact
    # with the application before scanning begins.  Show the same spinner
    # prompt here so they can exercise the app before we scan its memory/pipes.
    if needs_live_process and not needs_procmon and not svc_info:
        if _RICH:
            from rich.live    import Live as _Live
            from rich.spinner import Spinner as _Spinner
            from rich.text    import Text as _Text
            from rich.columns import Columns as _Columns
            _prompt = _Text.assemble(
                (" ", "white"),
                ("Interact with the application — press ", "white"),
                ("ENTER", "bold yellow"),
                (" when done.", "white"),
            )
            _spinner = _Spinner("dots", style="cyan")
            with _Live(
                _Columns([_spinner, _prompt]),
                console=_console,
                refresh_per_second=12,
                transient=True,
            ):
                try:
                    try:
                        import msvcrt as _msvcrt
                        while True:
                            ch = _msvcrt.getwch()
                            if ch in ("\r", "\n"):
                                break
                            if ch == "\x03":
                                raise KeyboardInterrupt
                    except ImportError:
                        input()
                except (EOFError, KeyboardInterrupt):
                    raise KeyboardInterrupt
        else:
            print_info("Interact with the application and press ENTER when done.")
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                raise KeyboardInterrupt
        print()

    if needs_procmon:
        print_section("Procmon Capture")
        procmon_exe = procmon_session.get_procmon_exe(ctx)

        if not procmon_exe:
            print_warning("Procmon not available — Procmon modules will be skipped.")
            _service_capture_complete = True
        elif svc_info:
            # Service path: prompt user if the service is currently running,
            # record its initial state so we can restore it after the scan.
            _initial_svc_state = svc_info.current_state   # "running" or "stopped"

            if svc_info.current_state == "running":
                confirmed = _prompt_running_service(svc_info)
                if not confirmed:
                    print_warning("Scan aborted by user.")
                    sys.exit(0)

            if procmon_exe:
                pml_path, new_pid, svc_il_rid = procmon_session.run_procmon_capture_service(
                    procmon_exe     = procmon_exe,
                    svc_info        = svc_info,
                    runtime_seconds = runtime,
                )
                if new_pid:
                    ctx["launched_pid"] = new_pid
                    ctx["pid"]          = new_pid
                    anvil_launched      = True
                if svc_il_rid is not None:
                    ctx["il_rid_captured"] = svc_il_rid
                if not pml_path:
                    print_error("Service capture failed — Procmon modules will use static fallback.")
                    procmon_exe = None
            _service_capture_complete = True
        else:
            # Non-service: target already running from Step 2 — start Procmon now.
            started = procmon_session.start_procmon_capture(procmon_exe)
            if not started:
                print_error("Procmon failed to start — Procmon modules will use static fallback.")
                procmon_exe = None
        print()

    # ── Step 4: Interaction phase (non-service with live Procmon only) ────────
    # Show the prompt whenever we have a live non-service target that needs
    # user interaction — regardless of whether Anvil launched it or the user
    # supplied --pid. Services are headless so the prompt is skipped there.
    if needs_procmon and procmon_exe and not _service_capture_complete:
        needs_interaction = not svc_info   # services are headless
        if needs_interaction:
            if _RICH:
                from rich.live    import Live as _Live
                from rich.spinner import Spinner as _Spinner
                from rich.text    import Text as _Text
                from rich.columns import Columns as _Columns
                _prompt = _Text.assemble(
                    (" ", "white"),
                    ("Interact with the application — press ", "white"),
                    ("ENTER", "bold yellow"),
                    (" when done.", "white"),
                )
                _spinner = _Spinner("dots", style="cyan")
                with _Live(
                    _Columns([_spinner, _prompt]),
                    console=_console,
                    refresh_per_second=12,
                    transient=True,        # erases the line when the context exits
                ):
                    try:
                        try:
                            import msvcrt as _msvcrt
                            # Use msvcrt.getwch() instead of input() so no newline
                            # is echoed to the terminal — an echoed \n moves the
                            # cursor down before Live can erase, breaking transient.
                            while True:
                                ch = _msvcrt.getwch()
                                if ch in ("\r", "\n"):
                                    break
                                if ch == "\x03":   # Ctrl-C
                                    raise KeyboardInterrupt
                        except ImportError:
                            input()            # non-Windows fallback
                    except (EOFError, KeyboardInterrupt):
                        raise KeyboardInterrupt
            else:
                print_info("Interact with the application and press ENTER when done.")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    raise KeyboardInterrupt
        print()

    # ── Step 5: Stop Procmon capture ──────────────────────────────────────────
    if needs_procmon and procmon_exe and not _service_capture_complete:
        if _RICH:
            from rich.live    import Live as _Live
            from rich.spinner import Spinner as _Spinner
            from rich.text    import Text as _Text
            from rich.columns import Columns as _Columns
            import os as _os
            _save_spinner = _Spinner("dots", style="white")
            _save_msg = _Text.assemble((" ", "white"), ("Saving PML File...", "white"))
            with _Live(
                _Columns([_save_spinner, _save_msg]),
                console=_console,
                refresh_per_second=12,
                transient=True,
            ):
                _pml_path, _size_mb = procmon_session.stop_procmon_capture(procmon_exe)
            if _pml_path:
                _console.print(
                    f"[green][ + ][/green] [white]Capture saved :[/white] "
                    f"[yellow]{_os.path.basename(_pml_path)}[/yellow]"
                    f"[white]  ({_size_mb:.1f} MB)[/white]"
                )
        else:
            procmon_session.stop_procmon_capture(procmon_exe)

    # ── IL resolution ─────────────────────────────────────────────────────────
    il_rid: Optional[int] = ctx.get("il_rid_captured")

    if il_rid is None and svc_info:
        try:
            import winreg
            key_path = rf"SYSTEM\CurrentControlSet\Services\{svc_info.service_name}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                try:
                    account, _ = winreg.QueryValueEx(k, "ObjectName")
                    account = str(account).strip().lower()
                except FileNotFoundError:
                    account = ""
            _SYSTEM_ACCOUNTS = {
                "", "localsystem", "localservice", "networkservice",
                "local service", "network service",
                "nt authority\\localservice",
                "nt authority\\networkservice",
                "nt authority\\system",
            }
            il_rid = (
                _SECURITY_MANDATORY_SYSTEM_RID if account in _SYSTEM_ACCOUNTS
                else _SECURITY_MANDATORY_HIGH_RID
            )
        except Exception:
            pass

    il_label = integrity_label(il_rid)
    ctx["il_rid"]   = il_rid
    ctx["il_label"] = il_label

    # ── Step 6 + 7: Analysis — counter + progress bar ────────────────────────
    from modules.utils import silence_output
    from rich.live     import Live
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.console  import Group
    from rich.text     import Text

    total_mods = len(all_modules_ordered)
    _done      = 0

    def _counter_text() -> Text:
        return Text.assemble(
            ("[ + ] Modules Executed : [", "white"),
            (str(_done),                   "cyan"),
            ("/",                           "white"),
            (str(total_mods),              "cyan"),
            ("]",                          "white"),
        )

    progress = Progress(
        BarColumn(bar_width=42),
        TextColumn("[cyan]{task.percentage:>3.0f}%[/cyan]"),
        TimeElapsedColumn(),
        expand=False,
    )
    task_id = progress.add_task("", total=total_mods)

    print_section("Parsing Data")

    mod_results  = {}
    mod_logs     = {}

    with Live(
        Group(_counter_text(), progress),
        console=_console,
        refresh_per_second=12,
    ) as live:
        for name, run_func in all_modules_ordered:
            with silence_output() as log:
                try:
                    findings = run_func(ctx) or []
                except Exception as exc:
                    findings = []
                    log.append("error", f"Module '{name}' error: {exc}")
                    if args.verbose:
                        import traceback
                        log.append("error", traceback.format_exc())

            mod_results[name] = findings
            mod_logs[name]    = log
            all_findings.extend(findings)

            _done += 1
            progress.update(task_id, advance=1)
            live.update(Group(_counter_text(), progress))

    print()


    # ── Step 8: Print consolidated findings ───────────────────────────────────
    # Both separators share the same arm width so their total lengths match.
    # " Scan Summary " is the longer label (14 chars); " Findings " is 10.
    # Arm: <============================> (31 chars).  Total = 31 + label + 31.
    _SEP_ARM = "<" + "=" * 29 + ">"
    def _make_sep(label: str) -> str:
        return f"{_SEP_ARM} {label} {_SEP_ARM}"

    if _RICH:
        _console.print(f"\n[cyan]{_make_sep('Findings')}[/cyan]\n")
    else:
        print(f"\n{_make_sep('Findings')}\n")
    print_section("Findings")

    # Lines from the captured module logs that are no longer relevant in the
    # findings section (they belong to the analysis/capture phase).
    _SUPPRESS_PATTERNS = (
        "Exporting filtered CSV for",
        "rows exported →",
    )

    def _should_suppress(line: str) -> bool:
        # Strip ANSI escape codes before matching
        import re as _re
        plain = _re.sub(r"\x1b\[[0-9;]*m", "", line)
        return any(p in plain for p in _SUPPRESS_PATTERNS)

    any_findings = False
    for name, _ in all_modules_ordered:
        findings   = mod_results.get(name, [])
        log        = mod_logs.get(name)
        log_lines  = []
        if log:
            for _, msg in log.entries:
                for line in msg.splitlines():
                    line = line.rstrip()
                    if line and not _should_suppress(line):
                        log_lines.append(line)

        if not findings and not log_lines:
            continue

        any_findings = any_findings or bool(findings)

        if _RICH:
            _console.print(f"[bold cyan]{name}[/bold cyan]")
            _console.print("[cyan]" + "─" * len(name) + "[/cyan]")
        else:
            print(f"{name}")
            print("─" * len(name))

        # ── Log output first (context / stats), then findings ─────────────────
        for line in log_lines:
            print(line)

        for f in findings:
            _print_finding(f, args.verbose)

        print()

    if not any_findings:
        print_success("No issues found across all modules.")
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    scan_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if _RICH:
        _console.print(f"\n[cyan]{_make_sep('Scan Summary')}[/cyan]\n")
    else:
        print(f"\n{_make_sep('Scan Summary')}\n")

    _print_summary(all_findings, scan_start, scan_end)

    # ── Assessment Reports directory ──────────────────────────────────────────
    # Use sys.executable when frozen (PyInstaller EXE) so the reports land next
    # to the EXE itself, not inside the _MEIxxxxxx temp extraction directory.
    if getattr(sys, "frozen", False):
        _tool_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        _tool_dir = os.path.dirname(os.path.abspath(__file__))
    _reports_dir = os.path.join(_tool_dir, "Assessment Reports")
    os.makedirs(_reports_dir, exist_ok=True)

    def _resolve_report_path(name: str, fallback_ext: str) -> str:
        """Route bare filenames into Assessment Reports/; preserve explicit paths."""
        base = name if os.path.dirname(name) else os.path.join(_reports_dir, name)
        if not base.lower().endswith(fallback_ext):
            base += fallback_ext
        return os.path.abspath(base)

    # ── JSON output (--report *.json) ─────────────────────────────────────────
    _json_target = args.report if args.report and args.report.lower().endswith(".json") else None
    if _json_target:
        _out_abs = _resolve_report_path(_json_target, ".json")
        try:
            write_json_report(all_findings, ctx, _out_abs)
            if _RICH:
                _console.print(f"[green][ + ][/green] JSON report  : {_out_abs}")
            else:
                print(f"[ + ] JSON report  : {_out_abs}")
        except Exception as exc:
            print_error(f"Failed to write JSON report: {exc}")

    # ── HTML report (--report *.html or any non-.json --report value) ─────────
    _html_target = args.report if args.report and not args.report.lower().endswith(".json") else None
    if _html_target:
        html_path = _resolve_report_path(_html_target, ".html")
        try:
            generate_html_report(
                findings    = all_findings,
                ctx         = ctx,
                output_path = html_path,
                scan_start  = scan_start,
                scan_end    = scan_end,
            )
            if _RICH:
                _console.print(f"[green][ + ][/green] HTML report  : {html_path}")
            else:
                print(f"[ + ] HTML report  : {html_path}")
        except Exception as e:
            print_error(f"Failed to write HTML report: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    # ── Step 9: Cleanup ───────────────────────────────────────────────────────
    procmon_session.cleanup()

    # Restore service to its initial state if we changed it during the scan.
    if svc_info and _initial_svc_state is not None:
        procmon_session.restore_service_state(svc_info.service_name, _initial_svc_state)

    _launched_pid = ctx.get("launched_pid")
    if _launched_pid and anvil_launched and not svc_info:
        # Anvil spawned this process — terminate it on exit.
        # Services are handled via restore_service_state above; leave them alone here.
        print_info(f"Terminating target process (PID {_launched_pid})…")
        procmon_session._shutdown_target(_launched_pid, launched_handle)

    print_info(f"Scan completed: {scan_end}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Graceful Ctrl+C — stop Procmon, wipe logs, exit cleanly.
        print()
        if _RICH and _console:
            from rich.text import Text as _T
            _console.print(_T.assemble(
                ("\n[ ! ] ", "yellow"), ("Scan interrupted by user.", "white")
            ))
        else:
            print("\n[ ! ] Scan interrupted by user.")
        try:
            from modules import procmon_session as _ps
            _procmon = _ps.get_procmon_exe({})
            if _procmon:
                import subprocess as _sp
                _sp.run([_procmon, "/Terminate"],
                        stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, timeout=10)
            _ps.cleanup()
        except Exception:
            pass
        sys.exit(0)
