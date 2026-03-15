import os
import re
from typing import List, Optional, Tuple

from .utils import finding, print_info, print_warning, path_writable_by_non_admin, is_windows

MODULE_NAME = "Unquoted Service Path"


def _resolve_service_from_pid(pid: int) -> Optional[str]:
    """
    Ask the SCM which service is running in the given process.
    Uses EnumServicesStatusEx to find a service whose ProcessId matches.
    """
    if not is_windows():
        return None
    try:
        import ctypes, ctypes.wintypes

        SC_MANAGER_ENUMERATE_SERVICE = 0x0004
        SERVICE_WIN32   = 0x30
        SERVICE_ACTIVE  = 0x01

        hSCM = ctypes.windll.advapi32.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
        if not hSCM:
            return None

        needed = ctypes.wintypes.DWORD(0)
        returned = ctypes.wintypes.DWORD(0)
        resume = ctypes.wintypes.DWORD(0)

        # First call to get required buffer size
        ctypes.windll.advapi32.EnumServicesStatusExW(
            hSCM, 0, SERVICE_WIN32, SERVICE_ACTIVE,
            None, 0, ctypes.byref(needed), ctypes.byref(returned),
            ctypes.byref(resume), None
        )

        buf = (ctypes.c_byte * needed.value)()
        returned = ctypes.wintypes.DWORD(0)
        resume = ctypes.wintypes.DWORD(0)

        if not ctypes.windll.advapi32.EnumServicesStatusExW(
            hSCM, 0, SERVICE_WIN32, SERVICE_ACTIVE,
            buf, needed, ctypes.byref(needed), ctypes.byref(returned),
            ctypes.byref(resume), None
        ):
            ctypes.windll.advapi32.CloseServiceHandle(hSCM)
            return None

        # ENUM_SERVICE_STATUS_PROCESS: lpServiceName (ptr), lpDisplayName (ptr),
        # ServiceStatusProcess (SERVICE_STATUS_PROCESS = 7 DWORDs + ProcessId at offset 24)
        # Struct layout varies by pointer size; parse via winreg cross-check instead.
        ctypes.windll.advapi32.CloseServiceHandle(hSCM)
    except Exception:
        pass

    # Fallback: scan registry ImagePath for the exe of that PID
    try:
        from .utils import get_process_path_from_pid
        exe = get_process_path_from_pid(pid)
        if not exe:
            return None
        return _resolve_service_from_exe(exe)
    except Exception:
        return None


def _resolve_service_from_exe(exe_path: str) -> Optional[str]:
    """Find a service name whose ImagePath matches the given exe."""
    if not is_windows() or not exe_path:
        return None
    try:
        import winreg
        norm_exe = os.path.normcase(exe_path)
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
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        rf"{services_key}\{svc_name}") as svck:
                        img, _ = winreg.QueryValueEx(svck, "ImagePath")
                        img = os.path.expandvars(str(img)).strip()
                        if img.startswith('"'):
                            img = img[1:].split('"')[0]
                        else:
                            img = img.split(" ")[0]
                        if os.path.normcase(img) == norm_exe:
                            return svc_name
                except Exception:
                    continue
    except Exception:
        pass
    return None


def _get_service_image_path(svc_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (image_path, display_name) for a given service name."""
    try:
        import winreg
        key_path = rf"SYSTEM\CurrentControlSet\Services\{svc_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            image_path, _ = winreg.QueryValueEx(key, "ImagePath")
            try:
                display_name, _ = winreg.QueryValueEx(key, "DisplayName")
            except Exception:
                display_name = svc_name
        return str(image_path), str(display_name)
    except Exception as exc:
        return None, None


def _get_all_services() -> List[Tuple[str, str, str]]:
    """Return (svc_name, display_name, image_path) for every registered service."""
    services = []
    if not is_windows():
        return services
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
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        rf"{services_key}\{svc_name}") as svck:
                        try:
                            img, _ = winreg.QueryValueEx(svck, "ImagePath")
                        except FileNotFoundError:
                            continue
                        try:
                            disp, _ = winreg.QueryValueEx(svck, "DisplayName")
                        except Exception:
                            disp = svc_name
                        services.append((svc_name, str(disp), str(img)))
                except (PermissionError, Exception):
                    continue
    except Exception:
        pass
    return services


def _is_unquoted_with_spaces(image_path: str) -> bool:
    stripped = image_path.strip()
    if stripped.startswith('"'):
        return False
    # Normalise forward-slash separators (valid in Windows ImagePath values)
    stripped = stripped.replace("/", "\\")
    # Must be an absolute path (drive letter or UNC)
    if not re.match(r"[A-Za-z]:\\", stripped) and not stripped.startswith("\\\\"):
        return False
    # Skip kernel driver paths (.sys) — they are not exploitable via the
    # SCM phantom-path attack (kernel loader handles them differently).
    m_exe = re.search(r"\.exe", stripped, re.IGNORECASE)
    m_sys = re.search(r"\.sys", stripped, re.IGNORECASE)
    if m_sys and (not m_exe or m_sys.start() < m_exe.start()):
        return False
    if not m_exe:
        # No .exe boundary found — check for spaces anyway
        return " " in stripped
    exe_part = stripped[:m_exe.end()]
    return " " in exe_part


def _get_intermediate_paths(image_path: str) -> List[str]:
    """
    Given:  C:\\Program Files\\My App\\service.exe /args
    Returns: ["C:\\Program.exe", "C:\\Program Files\\My.exe"]
    (the real path is the last one, not included as it's legitimate)
    """
    stripped = image_path.strip().replace("/", "\\")  # normalise separators
    m = re.search(r"\.exe", stripped, re.IGNORECASE)
    if not m:
        return []
    exe_path = stripped[:m.end()]
    parts = exe_path.split(" ")
    candidates = []
    accumulated = ""
    for part in parts[:-1]:
        accumulated = (accumulated + " " + part).strip()
        candidate = accumulated + ".exe"
        if re.match(r"[A-Za-z]:\\", candidate):
            candidates.append(candidate)
    return candidates


def _check_single_service(svc_name: str, display_name: str, image_path: str) -> List[dict]:
    results = []
    expanded = os.path.expandvars(image_path).strip()

    if not _is_unquoted_with_spaces(expanded):
        return results

    intermediates = _get_intermediate_paths(expanded)
    if not intermediates:
        return results

    writable_plants = []
    detail_lines = [
        f"Service    : {svc_name} ({display_name})",
        f"ImagePath  : {expanded}",
        f"",
        f"Intermediate executable candidates Windows SCM will try:",
    ]

    for candidate in intermediates:
        c_dir   = os.path.dirname(candidate)
        exists  = os.path.isfile(candidate)
        dir_ok  = os.path.isdir(c_dir)
        writable = path_writable_by_non_admin(c_dir) if dir_ok else False

        status_parts = []
        status_parts.append("EXISTS" if exists else "NAME NOT FOUND")
        status_parts.append(f"dir {'WRITABLE ← EXPLOITABLE' if writable else 'not writable'}")
        detail_lines.append(f"  {candidate}  [{', '.join(status_parts)}]")

        if writable and not exists:
            writable_plants.append(candidate)

    severity = "P1" if writable_plants else "P3"

    if writable_plants:
        detail_lines += [
            "",
            "EXPLOITABLE: Plant a binary at these writable phantom locations:",
        ]
        for p in writable_plants:
            detail_lines.append(f"  {p}")
        detail_lines += [
            "",
            "When the service starts, the SCM will execute your planted binary with SYSTEM privileges.",
        ]
    else:
        detail_lines += [
            "",
            "Path is unquoted but no intermediate directories are writable by standard users.",
            "Not exploitable by standard users on this system.",
        ]

    results.append(finding(
        severity=severity,
        message=f"Unquoted service path: {svc_name}",
        detail="\n".join(detail_lines),
        module=MODULE_NAME,
    ))
    return results


def run(ctx: dict) -> List[dict]:
    findings = []

    if not is_windows():
        print_warning("Unquoted service path check requires Windows.")
        return findings

    try:
        import winreg  # noqa
    except ImportError:
        print_warning("winreg unavailable.")
        return findings

    specific_service = ctx.get("service_name")
    exe_path         = ctx.get("exe_path")
    pid              = ctx.get("pid")

    # ── Determine scope ──────────────────────────────────────────────────────
    if specific_service:
        # Explicit service name given
        print_info(f"Checking service '{specific_service}' for unquoted path…")
        img, disp = _get_service_image_path(specific_service)
        if img is None:
            print_warning(f"Service '{specific_service}' not found or access denied.")
        else:
            findings.extend(_check_single_service(specific_service, disp or specific_service, img))

    elif pid:
        # Resolve service from PID
        print_info(f"Resolved service for PID {pid}…")
        svc = _resolve_service_from_pid(pid)
        if svc:
            print_info(f"PID {pid} belongs to service '{svc}'.")
            img, disp = _get_service_image_path(svc)
            if img:
                findings.extend(_check_single_service(svc, disp or svc, img))
        else:
            print_info(
                f"PID {pid} does not appear to belong to a Windows service "
                f"(it may be a regular process). Unquoted service path check not applicable."
            )
            return findings

    elif exe_path:
        # Find services whose ImagePath matches the exe
        print_info(f"Looking for services associated with: {exe_path}")
        svc = _resolve_service_from_exe(exe_path)
        if svc:
            print_info(f"Found associated service: '{svc}'")
            img, disp = _get_service_image_path(svc)
            if img:
                findings.extend(_check_single_service(svc, disp or svc, img))
        else:
            print_info(
                f"No service found with ImagePath matching '{exe_path}'. "
                f"If this is a standalone application (not a service), "
                f"unquoted service path does not apply."
            )
            return findings

    else:
        # Fallback: enumerate all — only reached if none of the above matched
        print_warning(
            "No specific service/pid/exe targeted. Enumerating ALL services system-wide. "
            "This is a broad scan — use --service, --pid, or --exe to scope to your target."
        )
        all_services = _get_all_services()
        print_info(f"Found {len(all_services)} service(s).")
        for svc_name, disp, img in all_services:
            findings.extend(_check_single_service(svc_name, disp, img))

    if not findings:
        print_info("No unquoted service path vulnerabilities found for the target.")

    return findings
