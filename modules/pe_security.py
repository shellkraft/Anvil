import os
import struct
import ctypes
import ctypes.wintypes
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .utils import (
    finding, print_info, print_warning,
    is_windows,
    _SECURITY_MANDATORY_HIGH_RID,
    get_process_integrity, integrity_label,
)

# Rich is optional — degrade to the ANSI table if not installed
try:
    from rich.console import Console as _Console
    from rich.table import Table as _Table
    from rich import box as _box
    _RICH = True
    _console = _Console(highlight=False)
except ImportError:
    _RICH = False

MODULE_NAME = "PE Security Mitigations"

# Deferred rendering: the last built Rich Table is stored here so anvil.py
# can render it in the Findings section after the Live analysis context exits.
_last_pe_table = None

# Maximum number of DLLs to check in the install directory (avoid scanning huge dirs)
MAX_DLL_SCAN = 40

# DllCharacteristics flags
_DYNAMIC_BASE    = 0x0040   # ASLR
_HIGH_ENTROPY_VA = 0x0020   # 64-bit high-entropy ASLR
_NX_COMPAT       = 0x0100   # DEP / NX
_NO_SEH          = 0x0400   # SEH not used (N/A marker)
_GUARD_CF        = 0x4000   # Control Flow Guard

# FileCharacteristics flags
_RELOCS_STRIPPED = 0x0001
_IMAGE_DLL       = 0x2000

# Load config GuardFlags
_IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100


# Machine type → human-readable string (mirrors PS script IMAGE_FILE_MACHINE enum)
_MACHINE_NAMES = {
    0x0000: "UNKNOWN",
    0x014C: "I386",
    0x0162: "R3000",
    0x0166: "R4000",
    0x0168: "R10000",
    0x0169: "WCEMIPSV2",
    0x0184: "ALPHA",
    0x01A2: "SH3",
    0x01A3: "SH3DSP",
    0x01A4: "SH3E",
    0x01A6: "SH4",
    0x01A8: "SH5",
    0x01C0: "ARM",
    0x01C2: "THUMB",
    0x01C4: "ARMNT",
    0x01D3: "AM33",
    0x01F0: "POWERPC",
    0x01F1: "POWERPCFP",
    0x0200: "IA64",
    0x0266: "MIPS16",
    0x0284: "ALPHA64",
    0x0366: "MIPSFPU",
    0x0466: "MIPSFPU16",
    0x0520: "TRICORE",
    0x0CEF: "CEF",
    0x0EBC: "EBC",
    0x8664: "AMD64",
    0x9041: "M32R",
    0xC0EE: "CEE",
    0xAA64: "ARM64",
}

# DataDirectory indices
_DIR_LOAD_CONFIG = 10
_DIR_CLR_RUNTIME = 14


# ---------------------------------------------------------------------------
# PE header parser (pure Python, no external deps)
# ---------------------------------------------------------------------------
class PEInfo:
    """Lightweight PE header reader — parses enough for mitigation checks."""

    __slots__ = (
        "path", "valid", "is_64", "machine", "is_dotnet", "is_dll",
        "dll_characteristics", "file_characteristics",
        "seh_table", "seh_count", "guard_flags",
        "has_load_config", "load_config_size",
        "error",
    )

    def __init__(self, path: str):
        self.path              = path
        self.valid             = False
        self.is_64             = False
        self.machine           = 0        # raw machine type word
        self.is_dotnet         = False
        self.is_dll            = False
        self.dll_characteristics = 0
        self.file_characteristics = 0
        self.seh_table         = 0
        self.seh_count         = 0
        self.guard_flags       = 0
        self.has_load_config   = False
        self.load_config_size  = 0
        self.error             = ""
        self._parse()

    def _parse(self):
        try:
            with open(self.path, "rb") as f:
                # Read enough to safely cover e_lfanew + COFF header (24) +
                # optional header (up to 240 bytes) + data directory table
                # (16 entries × 8 bytes = 128 bytes).  8 KiB is a safe ceiling.
                data = f.read(0x2000)
            if len(data) < 0x40 or data[:2] != b"MZ":
                self.error = "Not a valid PE (bad MZ)"
                return

            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 24 > len(data):
                self.error = "PE header offset out of range"
                return
            if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
                self.error = "PE signature not found"
                return

            machine       = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            self.machine  = machine
            self.is_64    = (machine == 0x8664)
            num_sections  = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            opt_hdr_size  = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            file_chars    = struct.unpack_from("<H", data, e_lfanew + 22)[0]
            self.file_characteristics = file_chars
            self.is_dll   = bool(file_chars & _IMAGE_DLL)

            opt_off = e_lfanew + 24
            if opt_off + 2 > len(data):
                self.error = "Optional header truncated"
                return

            magic = struct.unpack_from("<H", data, opt_off)[0]
            if magic == 0x010B:     # PE32
                if opt_off + 96 > len(data): return
                dll_chars_off = opt_off + 94
                dd_off        = opt_off + 96
            elif magic == 0x020B:   # PE32+
                if opt_off + 112 > len(data): return
                dll_chars_off = opt_off + 110
                dd_off        = opt_off + 112
            else:
                self.error = f"Unknown optional header magic: {magic:#06x}"
                return

            if dll_chars_off + 2 > len(data):
                return
            self.dll_characteristics = struct.unpack_from("<H", data, dll_chars_off)[0]

            # Read full file for data directories (they may be beyond 4 KiB)
            with open(self.path, "rb") as f:
                full = f.read()

            # Build section table for RVA→offset translation
            sec_off = opt_off + opt_hdr_size
            sections: List[Tuple[int, int, int]] = []   # (vaddr, vsize, raw_off)
            for i in range(num_sections):
                b = sec_off + i * 40
                if b + 40 > len(full):
                    break
                vaddr   = struct.unpack_from("<I", full, b + 12)[0]
                vsize   = struct.unpack_from("<I", full, b + 16)[0]
                raw_off = struct.unpack_from("<I", full, b + 20)[0]
                sections.append((vaddr, vsize, raw_off))

            def rva2off(rva: int) -> Optional[int]:
                for va, vs, ro in sections:
                    if va <= rva < va + max(vs, 1):
                        return ro + (rva - va)
                return None

            # Number of data directories
            num_dd_off = opt_off + (92 if magic == 0x010B else 108)
            if num_dd_off + 4 > len(full):
                self.valid = True
                return
            num_dd = struct.unpack_from("<I", full, num_dd_off)[0]

            def read_dd(idx: int) -> Tuple[int, int]:
                """Return (VirtualAddress, Size) for data directory idx."""
                off = dd_off + idx * 8
                if idx >= num_dd or off + 8 > len(full):
                    return 0, 0
                return struct.unpack_from("<II", full, off)

            # CLR runtime header (DataDirectory[14]) → DotNET flag
            clr_rva, _ = read_dd(_DIR_CLR_RUNTIME)
            self.is_dotnet = (clr_rva != 0)

            # Load config directory (DataDirectory[10]) → SEH + CFG
            lc_rva, lc_size = read_dd(_DIR_LOAD_CONFIG)
            if lc_rva:
                self.has_load_config = True
                lc_off = rva2off(lc_rva)
                if lc_off is not None and lc_off + 4 <= len(full):
                    self.load_config_size = struct.unpack_from("<I", full, lc_off)[0]

                    # SEHandlerTable / SEHandlerCount (32-bit only, offsets 72/76)
                    if not self.is_64 and lc_off + 80 <= len(full):
                        self.seh_table = struct.unpack_from("<I", full, lc_off + 72)[0]
                        self.seh_count = struct.unpack_from("<I", full, lc_off + 76)[0]

                    # GuardFlags (offset 100 in 32-bit, 148 in 64-bit load config)
                    guard_off = lc_off + (148 if self.is_64 else 100)
                    if guard_off + 4 <= len(full):
                        self.guard_flags = struct.unpack_from("<I", full, guard_off)[0]

            self.valid = True

        except Exception as exc:
            self.error = str(exc)


# ---------------------------------------------------------------------------
# Per-binary mitigation evaluation
# ---------------------------------------------------------------------------
def _eval_mitigations(pe: PEInfo) -> Dict[str, str]:
    """
    Return a dict of {mitigation: status} where status is one of:
      "PASS"  — mitigation present
      "FAIL"  — mitigation absent
      "N/A"   — not applicable for this binary type
      "WARN"  — present but ineffective (e.g. ASLR + relocs stripped)
    """
    m: Dict[str, str] = {}
    dc = pe.dll_characteristics
    fc = pe.file_characteristics

    # ── ASLR ──────────────────────────────────────────────────────────────────
    # Match PS script logic: stripped relocs only defeats ASLR on Windows < 8 (build < 9200).
    # Win8+ introduced mandatory ASLR (force-ASLR) which relocates images even without a
    # reloc table, so the stripped-relocs condition is only flagged on older targets.
    if dc & _DYNAMIC_BASE:
        if (fc & _RELOCS_STRIPPED) and not pe.is_dotnet:
            # Check OS version — only warn if running on pre-Win8
            try:
                import sys
                if sys.platform == "win32":
                    import ctypes
                    vi = ctypes.windll.kernel32.GetVersion()
                    build = (vi >> 16) & 0xFFFF
                    win_old = (build < 9200)
                else:
                    win_old = True   # Conservative: non-Windows analysis
            except Exception:
                win_old = True
            m["ASLR"] = "WARN" if win_old else "PASS"
        else:
            m["ASLR"] = "PASS"
    else:
        m["ASLR"] = "FAIL"

    # ── High Entropy VA (64-bit only) ─────────────────────────────────────────
    if pe.is_64:
        m["HighEntropyVA"] = "PASS" if (dc & _HIGH_ENTROPY_VA) else "FAIL"
    else:
        m["HighEntropyVA"] = "N/A"

    # ── DEP / NX ──────────────────────────────────────────────────────────────
    m["DEP"] = "PASS" if (dc & _NX_COMPAT) else "FAIL"

    # ── SafeSEH (32-bit only) ─────────────────────────────────────────────────
    if pe.is_64 or pe.is_dotnet:
        m["SafeSEH"] = "N/A"
    elif dc & _NO_SEH:
        m["SafeSEH"] = "N/A"   # Binary explicitly declares no SEH
    elif pe.has_load_config and pe.load_config_size >= 72:
        m["SafeSEH"] = "PASS" if (pe.seh_table != 0 and pe.seh_count != 0) else "FAIL"
    else:
        m["SafeSEH"] = "FAIL"  # No load config → no SafeSEH table

    # ── Control Flow Guard ────────────────────────────────────────────────────
    if pe.is_dotnet:
        m["CFG"] = "N/A"   # CFG for managed code is handled differently
    elif dc & _GUARD_CF:
        m["CFG"] = "PASS"
    else:
        m["CFG"] = "FAIL"

    # ── DotNET (informational) ────────────────────────────────────────────────
    m["DotNET"] = "YES" if pe.is_dotnet else "NO"

    return m


# ---------------------------------------------------------------------------
# Authenticode check (Windows only, via WinVerifyTrust)
# ---------------------------------------------------------------------------
def _check_authenticode(path: str) -> str:
    """Return 'PASS', 'FAIL', or 'N/A'."""
    if not is_windows():
        return "N/A"
    try:
        # Use ctypes to call WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2
        import ctypes.wintypes as W

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
            b"\xaa\xac\x03\x00\xc8\x05\x6d\x47\xb3\x1e\xa8\xf2\x98\x96\x0b\x1c"
        )

        class _WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct",       W.DWORD),
                ("pcwszFilePath",  ctypes.c_wchar_p),
                ("hFile",          W.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class _WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct",                 W.DWORD),
                ("pPolicyCallbackData",       ctypes.c_void_p),
                ("pSIPClientData",            ctypes.c_void_p),
                ("dwUIChoice",               W.DWORD),
                ("fdwRevocationChecks",       W.DWORD),
                ("dwUnionChoice",            W.DWORD),
                ("pFile",                    ctypes.c_void_p),
                ("dwStateAction",            W.DWORD),
                ("hWVTStateData",            W.HANDLE),
                ("pwszURLReference",         ctypes.c_wchar_p),
                ("dwProvFlags",              W.DWORD),
                ("dwUIContext",              W.DWORD),
            ]

        file_info = _WINTRUST_FILE_INFO()
        file_info.cbStruct       = ctypes.sizeof(file_info)
        file_info.pcwszFilePath  = path
        file_info.hFile          = None
        file_info.pgKnownSubject = None

        wd = _WINTRUST_DATA()
        wd.cbStruct             = ctypes.sizeof(wd)
        wd.pPolicyCallbackData  = None
        wd.pSIPClientData       = None
        wd.dwUIChoice           = 2   # WTD_UI_NONE
        wd.fdwRevocationChecks  = 0   # WTD_REVOKE_NONE (faster, avoids network)
        wd.dwUnionChoice        = 1   # WTD_CHOICE_FILE
        wd.pFile                = ctypes.cast(ctypes.byref(file_info), ctypes.c_void_p)
        wd.dwStateAction        = 0   # WTD_STATEACTION_IGNORE
        wd.hWVTStateData        = None
        wd.pwszURLReference     = None
        wd.dwProvFlags          = 0x00000010  # WTD_CACHE_ONLY_URL_RETRIEVAL

        guid_buf = (ctypes.c_byte * 16)(*WINTRUST_ACTION_GENERIC_VERIFY_V2)

        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.restype  = ctypes.c_ulong
        wintrust.WinVerifyTrust.argtypes = [W.HWND, ctypes.c_void_p, ctypes.c_void_p]

        ret = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(guid_buf),
            ctypes.byref(wd),
        )
        # 0 = valid; 0x800B0100 = TRUST_E_NOSIGNATURE; anything else = invalid/error
        return "PASS" if ret == 0 else "FAIL"
    except Exception:
        return "N/A"


# ---------------------------------------------------------------------------
# StrongNaming check (.NET only, via reflection COM)
# ---------------------------------------------------------------------------
def _check_strong_naming(path: str) -> str:
    """Return 'PASS', 'FAIL', or 'N/A' (native/non-dotnet)."""
    if not is_windows():
        return "N/A"
    try:
        import subprocess
        # Use PowerShell one-liner — avoids loading .NET into the Python process
        ps_cmd = (
            f"try {{"
            f"  $t = [System.Reflection.AssemblyName]::GetAssemblyName('{path}').GetPublicKeyToken();"
            f"  if ($t -and $t.Count -gt 0) {{ 'PASS' }} else {{ 'FAIL' }}"
            f"}} catch {{ 'N/A' }}"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=8,
        )
        out = result.stdout.strip()
        if out in ("PASS", "FAIL", "N/A"):
            return out
        return "N/A"
    except Exception:
        return "N/A"


# ---------------------------------------------------------------------------
# Finding generator for a single binary
# ---------------------------------------------------------------------------
def _findings_for_binary(
    path: str,
    mitigations: Dict[str, str],
    authenticode: str,
    strong_naming: str,
    il_rid: Optional[int],
) -> List[dict]:
    """Convert missing mitigations into structured findings."""
    results   = []
    fname     = os.path.basename(path)
    il_label  = integrity_label(il_rid)
    is_high   = il_rid is not None and il_rid >= _SECURITY_MANDATORY_HIGH_RID

    # Helper: only flag if the process may run at High/System (worst case)
    # For install-dir DLLs we don't know their IL — treat as HIGH for severity
    # since they'll be loaded by the target process.
    def sev(high_sev: str, med_sev: str) -> str:
        return high_sev if is_high else med_sev

    # ── ASLR ──────────────────────────────────────────────────────────────────
    if mitigations.get("ASLR") == "FAIL":
        results.append(finding(
            severity = sev("P2", "P3"),
            message  = f"ASLR disabled: {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Flag         : DYNAMIC_BASE (0x0040) NOT set in DllCharacteristics\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : The binary loads at a predictable base address.\n"
                f"               Memory corruption exploits (buffer overflows, use-after-free)\n"
                f"               do not need to defeat ASLR to control execution flow.\n"
                f"Fix          : Recompile with /DYNAMICBASE linker flag."
            ),
            module = MODULE_NAME,
        ))
    elif mitigations.get("ASLR") == "WARN":
        results.append(finding(
            severity = sev("P2", "P3"),
            message  = f"ASLR ineffective (DYNAMIC_BASE set but relocation table stripped): {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Flag         : DYNAMIC_BASE is SET but IMAGE_RELOCS_STRIPPED is also SET\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : Without a relocation table the loader cannot rebase the image.\n"
                f"               The binary loads at its preferred base address every time.\n"
                f"Fix          : Recompile without /FIXED and without stripping relocations."
            ),
            module = MODULE_NAME,
        ))

    # ── DEP ───────────────────────────────────────────────────────────────────
    if mitigations.get("DEP") == "FAIL":
        results.append(finding(
            severity = sev("P2", "P3"),
            message  = f"DEP/NX disabled: {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Flag         : NX_COMPAT (0x0100) NOT set in DllCharacteristics\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : Hardware DEP (Data Execution Prevention) will not be enforced\n"
                f"               for this binary. An attacker can execute shellcode injected\n"
                f"               into data pages (stack, heap).\n"
                f"Fix          : Recompile with /NXCOMPAT linker flag."
            ),
            module = MODULE_NAME,
        ))

    # ── SafeSEH ───────────────────────────────────────────────────────────────
    if mitigations.get("SafeSEH") == "FAIL":
        results.append(finding(
            severity = "P3",
            message  = f"SafeSEH not present (32-bit binary): {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Architecture : 32-bit\n"
                f"Status       : No SEHandlerTable in Load Configuration directory\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : Structured Exception Handler overwrite attacks are possible.\n"
                f"               An attacker who controls stack data can redirect execution\n"
                f"               through a crafted SEH chain.\n"
                f"Fix          : Recompile with /SAFESEH linker flag."
            ),
            module = MODULE_NAME,
        ))

    # ── CFG ───────────────────────────────────────────────────────────────────
    if mitigations.get("CFG") == "FAIL":
        results.append(finding(
            severity = "P3",
            message  = f"Control Flow Guard (CFG) not enabled: {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Flag         : GUARD_CF (0x4000) NOT set in DllCharacteristics\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : Indirect call targets are not validated. An attacker with\n"
                f"               write primitive can redirect virtual calls or function\n"
                f"               pointer calls to arbitrary locations.\n"
                f"Fix          : Recompile with /guard:cf compiler/linker flags."
            ),
            module = MODULE_NAME,
        ))

    # ── HighEntropyVA ─────────────────────────────────────────────────────────
    if mitigations.get("HighEntropyVA") == "FAIL":
        results.append(finding(
            severity = "P4",
            message  = f"High Entropy ASLR not enabled (64-bit binary): {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Flag         : HIGH_ENTROPY_VA (0x0020) NOT set\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : ASLR uses only 8-bit entropy instead of 19-bit.\n"
                f"               Brute-force of base address is significantly easier.\n"
                f"Fix          : Recompile with /HIGHENTROPYVA linker flag."
            ),
            module = MODULE_NAME,
        ))

    # ── Authenticode ─────────────────────────────────────────────────────────
    if authenticode == "FAIL":
        results.append(finding(
            severity = "P4",
            message  = f"Binary not Authenticode signed: {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Status       : WinVerifyTrust returned non-zero (no valid signature chain)\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : No cryptographic proof of binary integrity or origin.\n"
                f"               SmartScreen and AV heuristics are weakened.\n"
                f"               Particularly significant for auto-elevating executables.\n"
                f"Fix          : Sign the binary with a code-signing certificate."
            ),
            module = MODULE_NAME,
        ))

    # ── StrongNaming (.NET only) ───────────────────────────────────────────────
    if mitigations.get("DotNET") == "YES" and strong_naming == "FAIL":
        results.append(finding(
            severity = "P4",
            message  = f".NET assembly missing strong name signature: {fname}",
            detail   = (
                f"Binary       : {path}\n"
                f"Status       : GetPublicKeyToken() returned empty (no strong name)\n"
                f"Process IL   : {il_label}\n"
                f"Risk         : Without strong naming, the assembly can be replaced with a\n"
                f"               tampered version that has the same identity. The CLR will\n"
                f"               load it without complaint.\n"
                f"Fix          : Sign the assembly with a strong name key (sn.exe -k)."
            ),
            module = MODULE_NAME,
        ))

    return results





# ---------------------------------------------------------------------------
# Terminal summary table — Rich-based (Issue 4)
# ---------------------------------------------------------------------------


def _cell(val: str) -> str:
    """Return a Rich markup string for a mitigation status value."""
    v = (val or "?").upper()
    if v == "PASS":          return "[green]✓[/green]"
    if v == "FAIL":          return "[red]✗[/red]"
    if v == "WARN":          return "[yellow]⚠[/yellow]"
    if v in ("N/A", "NA"):   return "[dim]-[/dim]"
    if v == "YES":           return "[green]Y[/green]"
    if v == "NO":            return "[dim]N[/dim]"
    return val


def _print_pe_table(pe_results: list) -> None:
    """
    Print a compact per-binary mitigation summary.  Uses Rich when available,
    falls back to ANSI otherwise.

    Column structure (Issue 4):
      Binary | Arch | .NET | ASLR | HighEntVA | DEP | SafeSEH | CFG |
      Authenticode | StrongName
    """
    if _RICH:
        _print_pe_table_rich(pe_results)
    else:
        _print_pe_table_ansi(pe_results)


def _print_pe_table_rich(pe_results: list) -> None:
    global _last_pe_table
    tbl = _Table(
        show_header=True,
        header_style="bold cyan",
        box=_box.SQUARE,
        expand=False,
        show_lines=True,
        border_style="cyan",
        pad_edge=True,
    )
    tbl.add_column("Binary",       style="cyan",  max_width=28, no_wrap=True)
    tbl.add_column("Arch",         style="white", max_width=7,  justify="center")
    tbl.add_column(".NET",                         max_width=5,  justify="center")
    tbl.add_column("ASLR",                         max_width=6,  justify="center")
    tbl.add_column("HighEntVA",                    max_width=9,  justify="center")
    tbl.add_column("DEP",                          max_width=5,  justify="center")
    tbl.add_column("SafeSEH",                      max_width=7,  justify="center")
    tbl.add_column("CFG",                          max_width=5,  justify="center")
    tbl.add_column("Authenticode",                 max_width=12, justify="center")
    tbl.add_column("StrongName",                   max_width=10, justify="center")

    for r in pe_results:
        name = r.get("name", "?")
        if len(name) > 27:
            name = name[:26] + "…"
        tbl.add_row(
            name,
            r.get("arch", "?"),
            _cell(r.get("dotnet",       "?")),
            _cell(r.get("aslr",         "?")),
            _cell(r.get("high_entropy", "?")),
            _cell(r.get("dep",          "?")),
            _cell(r.get("safeseh",      "?")),
            _cell(r.get("cfg",          "?")),
            _cell(r.get("authenticode", "?")),
            _cell(r.get("strongname",   "?")),
        )

    # Store for deferred rendering in the Findings section.
    # The caller (anvil.py) reads _last_pe_table after analysis completes.
    _last_pe_table = tbl
    # Actual print is handled by anvil.py after the Live context exits.
    _console.print()
    _console.print(tbl)
    _console.print()


def _print_pe_table_ansi(pe_results: list) -> None:
    """Fallback ANSI renderer (used when Rich is not installed)."""
    import sys
    use_color = sys.stdout.isatty()
    GRN  = "\033[92m" if use_color else ""
    _RED = "\033[91m" if use_color else ""
    YEL  = "\033[93m" if use_color else ""
    DIM  = "\033[2m"  if use_color else ""
    BOLD = "\033[1m"  if use_color else ""
    RST  = "\033[0m"  if use_color else ""

    COLS = [
        ("Binary",       18, "name"),
        ("Arch",          7, "arch"),
        (".NET",          5, "dotnet"),
        ("ASLR",          6, "aslr"),
        ("DEP",           5, "dep"),
        ("HiEntVA",       8, "high_entropy"),
        ("Authentic",     9, "authenticode"),
        ("StrongName",   10, "strongname"),
        ("SafeSEH",       7, "safeseh"),
        ("CFG",           5, "cfg"),
    ]

    def fmt(val: str, _w: int) -> str:
        v = (val or "?").upper()
        if v == "PASS":           return f"{GRN}✓{RST}"
        if v == "FAIL":           return f"{_RED}✗{RST}"
        if v == "WARN":           return f"{YEL}⚠{RST}"
        if v in ("N/A", "NA"):    return f"{DIM}-{RST}"
        if v == "YES":            return f"{GRN}Y{RST}"
        if v == "NO":             return f"{DIM}N{RST}"
        return v

    def trunc(s: str, w: int) -> str:
        return s.ljust(w) if len(s) <= w else s[:w - 1] + "…"

    header = "  "
    sep    = "  "
    for (label, width, _) in COLS:
        header += f"{BOLD}{label:<{width}}{RST}  "
        sep    += "-" * width + "  "
    print(header)
    print(f"  {DIM}{sep.strip()}{RST}")
    for r in pe_results:
        row = "  "
        for (_, width, key) in COLS:
            if key in ("name", "arch"):
                row += trunc(r.get(key, "?"), width) + "  "
            else:
                row += f"{fmt(r.get(key, '?'), width):<{width + 10}}  "
        print(row)
    print()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def run(ctx: dict) -> List[dict]:
    """
    Scan PE binaries for security mitigations.

    Issue 3: 'Process integrity' line removed — il_rid/il_label are now
             read from ctx["il_rid"] / ctx["il_label"] (set in Phase 1 of
             Anvil.py) rather than re-querying and re-printing here.
    Issue 4: Terminal output is the Rich table only.  Per-finding verbose
             output is suppressed — findings go to HTML report.
    Issue 6: Directory walk only runs when ctx["pesec_scan_dir"] is True
             (controlled by --scan-install-dir CLI flag).
    """
    all_findings: List[dict]    = []
    pe_results:   List[Dict]    = []

    exe_path    = ctx.get("exe_path")
    install_dir = ctx.get("install_dir")

    if not exe_path and not install_dir:
        print_warning("No executable or install directory — PE security check skipped.")
        return all_findings

    # Use pre-computed IL from ctx (Issue 3 — avoids re-query + re-print)
    il_rid   = ctx.get("il_rid")
    il_label = ctx.get("il_label") or "Unknown"

    # Collect binaries to scan
    targets: List[str] = []
    if exe_path and os.path.isfile(exe_path):
        targets.append(exe_path)

    # Issue 6: Only scan install dir if --scan-install-dir was passed
    if ctx.get("pesec_scan_dir") and install_dir and os.path.isdir(install_dir):
        dll_count = 0
        try:
            for entry in sorted(os.scandir(install_dir), key=lambda e: e.name.lower()):
                if dll_count >= MAX_DLL_SCAN:
                    print_info(f"DLL scan limit reached ({MAX_DLL_SCAN}). Remaining skipped.")
                    break
                if entry.is_file() and entry.name.lower().endswith((".dll", ".exe")):
                    if entry.path != exe_path:
                        targets.append(entry.path)
                        dll_count += 1
        except Exception as exc:
            print_warning(f"Could not scan install directory: {exc}")

    skip_authenticode = ctx.get("skip_authenticode", False)
    if skip_authenticode:
        print_info("Authenticode signing check skipped (--skip-authenticode).")
    print_info(f"Scanned {len(targets)} binary/binaries for security mitigations…")

    for path in targets:
        fname = os.path.basename(path)
        pe = PEInfo(path)

        if not pe.valid:
            print_warning(f"  Skipping {fname}: {pe.error or 'parse error'}")
            continue

        mitigations  = _eval_mitigations(pe)
        authenticode = "N/A" if skip_authenticode else _check_authenticode(path)
        strong_name  = _check_strong_naming(path) if pe.is_dotnet else "N/A"

        arch_str = _MACHINE_NAMES.get(pe.machine, f"0x{pe.machine:04X}")
        pe_results.append({
            "path":         path,
            "name":         fname,
            "arch":         arch_str,
            "dotnet":       mitigations.get("DotNET", "NO"),
            "aslr":         mitigations.get("ASLR",          "?"),
            "high_entropy": mitigations.get("HighEntropyVA",  "?"),
            "dep":          mitigations.get("DEP",            "?"),
            "safeseh":      mitigations.get("SafeSEH",        "?"),
            "cfg":          mitigations.get("CFG",            "?"),
            "authenticode": authenticode,
            "strongname":   strong_name,
        })

        binary_findings = _findings_for_binary(
            path, mitigations, authenticode, strong_name, il_rid
        )
        all_findings.extend(binary_findings)

    # Store results in ctx for HTML report
    ctx["pe_security_results"] = pe_results

    # Issue 4: Table IS the output; per-finding terminal output suppressed
    if pe_results:
        _print_pe_table(pe_results)

    if all_findings:
        print_info(
            f"PE security: {len(all_findings)} missing mitigation(s) across "
            f"{len(pe_results)} binaries. (Details in HTML report)"
        )
    else:
        print_info(f"All {len(pe_results)} binaries passed mitigation checks.")

    return all_findings
