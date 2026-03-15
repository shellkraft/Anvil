import re
import ctypes
import ctypes.wintypes
import os
from typing import List, Dict, Tuple, Optional

from .utils import finding, print_info, print_warning, print_error, is_windows, is_admin

MODULE_NAME = "Sensitive Strings in Memory"

# ── Built-in sensitive keyword patterns ───────────────────────────────────────
BUILTIN_PATTERNS: Dict[str, re.Pattern] = {
    "PASSWORD":          re.compile(rb"(?i)password\s*[=:\"']\s*\S+"),
    "PASSWD":            re.compile(rb"(?i)passwd\s*[=:\"']\s*\S+"),
    "API_KEY":           re.compile(rb"(?i)api[_\-]?key\s*[=:\"']\s*\S+"),
    "SECRET":            re.compile(rb"(?i)(?:secret|client_secret|app_secret)\s*[=:\"']\s*\S+"),
    "AUTH_TOKEN":        re.compile(rb"(?i)auth[_\-]?token\s*[=:\"']\s*\S+"),
    "ACCESS_TOKEN":      re.compile(rb"(?i)access[_\-]?token\s*[=:\"']\s*\S+"),
    "SESSION_ID":        re.compile(rb"(?i)session[_\-]?id\s*[=:\"']\s*\S+"),
    "COOKIE":            re.compile(rb"(?i)cookie\s*[=:\"']\s*\S+"),
    "BEARER":            re.compile(rb"(?i)bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"),
    "PRIVATE_KEY":       re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "CONNECTION_STRING": re.compile(rb"(?i)(?:connectionstring|connection_string|Data Source)\s*[=:\"']\s*\S+"),
    "JDBC_URL":          re.compile(rb"(?i)jdbc:[a-z]+://\S+"),
    "DATABASE_URL":      re.compile(rb"(?i)(?:db_url|database_url|postgres|mysql|mongodb)://\S+"),
    "AWS_SECRET":        re.compile(rb"(?i)aws.{0,20}(?:secret|key)\s*[=:\"']\s*\S+"),
    "OAUTH_TOKEN":       re.compile(rb"(?i)oauth[_\-]?token\s*[=:\"']\s*\S+"),
    "JWT":               re.compile(rb"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"),
    "SMTP_PASS":         re.compile(rb"(?i)smtp.{0,10}pass\s*[=:\"']\s*\S+"),
    "CREDIT_CARD":       re.compile(rb"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "PRIVATE_KEY_PEM":   re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]{10,500}-----END"),
    "ENCRYPTION_KEY":    re.compile(rb"(?i)encrypt(?:ion)?[_\-]?key\s*[=:\"']\s*\S+"),
    "SAML_TOKEN":        re.compile(rb"(?i)saml[_\-]?token\s*[=:\"']\s*\S+"),
    "HASH_CREDENTIAL":   re.compile(rb"(?i)(?:\$2[aby]\$|\$6\$|\$5\$)[^\s\"']{20,}"),
    "NTLM_HASH":         re.compile(rb"(?i)ntlm[_\-]?hash\s*[=:\"']\s*[A-Fa-f0-9]{32}"),
}

# ── Per-pattern severity ──────────────────────────────────────────────────────
# Severity reflects the number of steps between the finding and a usable attack.
#
# P2 — Immediately actionable: the raw material can be used directly without
#       cracking, context-switching, or obtaining additional access.
#
# P3 — One step away: value must be cracked, replayed in a specific authenticated
#       context, or combined with service access before it is useful.
#
# P4 — PCI-DSS / PII concern: not an authentication vector.
#
# Custom patterns (user-supplied via --memory-strings) default to P3.
PATTERN_SEVERITY: Dict[str, str] = {
    # P2 — immediately actionable
    "PRIVATE_KEY":       "P2",   # raw asymmetric key material, immediately usable
    "PRIVATE_KEY_PEM":   "P2",   # same — full PEM block including the key body
    "NTLM_HASH":         "P2",   # pass-the-hash requires no cracking
    "AWS_SECRET":        "P2",   # cloud credential with account-wide blast radius
    "BEARER":            "P2",   # live signed token, replayable immediately
    "JWT":               "P2",   # live signed token, replayable immediately

    # P3 — credential disclosure, one step to exploit
    "PASSWORD":          "P3",
    "PASSWD":            "P3",
    "API_KEY":           "P3",
    "SECRET":            "P3",
    "AUTH_TOKEN":        "P3",
    "ACCESS_TOKEN":      "P3",
    "SESSION_ID":        "P3",
    "COOKIE":            "P3",
    "CONNECTION_STRING": "P3",
    "JDBC_URL":          "P3",
    "DATABASE_URL":      "P3",
    "OAUTH_TOKEN":       "P3",
    "SMTP_PASS":         "P3",
    "ENCRYPTION_KEY":    "P3",
    "SAML_TOKEN":        "P3",
    "HASH_CREDENTIAL":   "P3",   # bcrypt/sha512 — requires cracking

    # P4 — PII / compliance concern, not a direct auth vector
    "CREDIT_CARD":       "P4",
}

# Short rationale shown in each finding's detail block.
_SEVERITY_RATIONALE: Dict[str, str] = {
    "PRIVATE_KEY":       "raw private key material — immediately usable for impersonation",
    "PRIVATE_KEY_PEM":   "raw private key material — immediately usable for impersonation",
    "NTLM_HASH":         "pass-the-hash — grants access without cracking",
    "AWS_SECRET":        "cloud credential — account-wide blast radius",
    "BEARER":            "live bearer token — replayable immediately",
    "JWT":               "live signed JWT — replayable immediately",
    "PASSWORD":          "credential disclosure — requires service access to exploit",
    "PASSWD":            "credential disclosure — requires service access to exploit",
    "API_KEY":           "credential disclosure — requires service access to exploit",
    "SECRET":            "credential disclosure — requires service access to exploit",
    "AUTH_TOKEN":        "credential disclosure — requires service access to exploit",
    "ACCESS_TOKEN":      "credential disclosure — requires service access to exploit",
    "SESSION_ID":        "credential disclosure — requires service access to exploit",
    "COOKIE":            "credential disclosure — requires service access to exploit",
    "CONNECTION_STRING": "credential disclosure — requires database access to exploit",
    "JDBC_URL":          "credential disclosure — requires database access to exploit",
    "DATABASE_URL":      "credential disclosure — requires database access to exploit",
    "OAUTH_TOKEN":       "credential disclosure — requires service access to exploit",
    "SMTP_PASS":         "credential disclosure — requires mail server access to exploit",
    "ENCRYPTION_KEY":    "key material disclosure — requires cryptographic context",
    "SAML_TOKEN":        "credential disclosure — requires IdP/SP access to exploit",
    "HASH_CREDENTIAL":   "hashed credential — requires cracking before use",
    "CREDIT_CARD":       "PCI-DSS / PII concern — not a direct authentication vector",
}

# ── Windows memory reading ────────────────────────────────────────────────────
PROCESS_VM_READ         = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT              = 0x00001000
PAGE_NOACCESS           = 0x01
PAGE_GUARD              = 0x100

# Memory region structure (MEMORY_BASIC_INFORMATION)
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             ctypes.wintypes.DWORD),
        ("Protect",           ctypes.wintypes.DWORD),
        ("Type",              ctypes.wintypes.DWORD),
    ]


def _open_process(pid: int):
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    return handle if handle else None


def _read_memory(handle, address: int, size: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    success = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read)
    )
    if success and bytes_read.value > 0:
        return buf.raw[:bytes_read.value]
    return None


def _enumerate_readable_regions(handle) -> List[Tuple[int, int]]:
    """Return list of (base_address, size) for all readable committed regions."""
    regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while True:
        result = ctypes.windll.kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not result:
            break

        if (
            mbi.State == MEM_COMMIT
            and not (mbi.Protect & PAGE_NOACCESS)
            and not (mbi.Protect & PAGE_GUARD)
        ):
            regions.append((mbi.BaseAddress, mbi.RegionSize))

        # Advance past this region
        address = (mbi.BaseAddress or 0) + (mbi.RegionSize or 1)
        # Correct 64-bit user-mode address space ceiling:
        # Windows uses canonical 48-bit addresses; user-mode top is 0x00007FFFFFFFFFFF.
        # LargeAddressAware 32-bit processes can reach up to 0xFFFFFFFF (covered).
        if address >= 0x00007FFFFFFFFFFF:
            break

    return regions


def _redact(raw: bytes, max_value_len: int = 6) -> str:
    """Return a redacted display string: show key name, hide most of value."""
    try:
        s = raw.decode("utf-8", errors="replace")
    except Exception:
        s = repr(raw)
    # Redact after the separator (=, :)
    s = re.sub(r'(=\s*|:\s*)(\S{0,4})\S+', r'\1\2[REDACTED]', s)
    return s[:120]


def _luhn_valid(digits: str) -> bool:
    """Return True if the digit string passes the Luhn checksum algorithm."""
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _build_custom_patterns(extra_strings: List[str]) -> Dict[str, re.Pattern]:
    custom = {}
    for raw in extra_strings:
        key = raw.upper().replace(" ", "_")
        try:
            custom[key] = re.compile(re.escape(raw).encode(), re.IGNORECASE)
        except re.error:
            pass
    return custom


# ── Main scan ─────────────────────────────────────────────────────────────────
def run(ctx: dict) -> List[dict]:
    findings = []

    if not is_windows():
        print_warning("Memory scanning requires Windows.")
        return findings

    # Use the PID of the process launched by this session (set by Anvil.py
    # after spawning the exe), then fall back to an explicit --pid argument.
    pid = ctx.get("launched_pid") or ctx.get("pid")
    if not pid:
        print_warning(
            "No process PID available for memory scanning.  "
            "Use --pid to attach to an already-running process."
        )
        return findings

    if not is_admin():
        print_warning(
            "Not running as Administrator. Memory access may be denied for elevated processes."
        )

    print_info(f"Opening process PID {pid} for memory scanning…")
    handle = _open_process(pid)
    if not handle:
        err = ctypes.windll.kernel32.GetLastError()
        print_error(f"Failed to open process {pid} (error code {err}). Try running as Administrator.")
        return findings

    try:
        patterns = {**BUILTIN_PATTERNS}
        extra = ctx.get("extra_strings", [])
        if extra:
            custom_patterns = _build_custom_patterns(extra)
            patterns.update(custom_patterns)
            print_info(f"Loaded {len(custom_patterns)} custom pattern(s): {', '.join(custom_patterns)}")

        print_info(f"Scanning process memory with {len(patterns)} pattern(s)…")

        regions = _enumerate_readable_regions(handle)
        print_info(f"Found {len(regions)} readable memory region(s).")

        CHUNK   = 4 * 1024 * 1024   # 4 MB primary chunk size
        # Overlap between consecutive chunks so patterns straddling a boundary
        # are not missed.  512 bytes is larger than any pattern in BUILTIN_PATTERNS.
        OVERLAP = 512
        matched_patterns: Dict[str, int] = {}
        finding_details:  Dict[str, List[str]] = {}

        for (base, size) in regions:
            offset = 0
            while offset < size:
                read_size = min(CHUNK, size - offset)
                chunk = _read_memory(handle, base + offset, read_size)
                if not chunk:
                    offset += read_size
                    continue

                for name, pattern in patterns.items():
                    for match in pattern.finditer(chunk):
                        if matched_patterns.get(name, 0) >= 5:
                            continue
                        # Luhn validation for credit card matches — eliminates
                        # false positives from counters, timestamps, and addresses
                        if name == "CREDIT_CARD":
                            digits = re.sub(rb"[^0-9]", b"", match.group(0)).decode()
                            if not _luhn_valid(digits):
                                continue
                        matched_patterns[name] = matched_patterns.get(name, 0) + 1
                        snippet = _redact(match.group(0))
                        finding_details.setdefault(name, []).append(
                            f"  Region 0x{base + offset:016x}+0x{match.start():x}: {snippet}"
                        )

                # Advance by (chunk_size - overlap) so the next read re-covers
                # the tail of this chunk — catches patterns split at the boundary.
                if read_size == CHUNK:
                    offset += CHUNK - OVERLAP
                else:
                    offset += read_size

        # Convert hits to findings
        for name, count in matched_patterns.items():
            details = "\n".join(finding_details.get(name, []))
            # Custom patterns (not in PATTERN_SEVERITY) default to P3.
            sev = PATTERN_SEVERITY.get(name, "P3")
            findings.append(finding(
                severity=sev,
                message=f"Sensitive pattern '{name}' found {count}x in process memory",
                detail=(
                    f"Pattern      : {name}\n"
                    f"Severity     : {sev} — {_SEVERITY_RATIONALE.get(name, 'credential disclosure')}\n"
                    f"Hit count    : {count}\n"
                    f"Sample locations (value redacted):\n{details}"
                ),
                module=MODULE_NAME,
            ))

        if not findings:
            print_info("No sensitive strings found in process memory.")

    finally:
        ctypes.windll.kernel32.CloseHandle(handle)

    return findings
