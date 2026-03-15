import os
from typing import List, Optional

from .utils import (
    finding, print_info, print_warning,
    path_writable_by_non_admin, is_windows,
    _is_auto_triggered,
)

MODULE_NAME = "Insecure Installation Directory"

SAFE_INSTALL_ROOTS = (
    os.path.normcase(r"C:\Program Files"),
    os.path.normcase(r"C:\Program Files (x86)"),
    os.path.normcase(r"C:\Windows"),
)


def _is_in_safe_root(path: str) -> bool:
    norm = os.path.normcase(os.path.abspath(path))
    return any(norm.startswith(r) for r in SAFE_INSTALL_ROOTS)


def _has_elevation_manifest(exe_path: str) -> bool:
    """Heuristic: scan the binary for elevation-requesting manifest keywords."""
    try:
        with open(exe_path, "rb") as f:
            data = f.read()
        return b"requireAdministrator" in data or b"highestAvailable" in data
    except Exception:
        return False


def _check_root_acl(install_dir: str) -> List[dict]:
    """
    Check whether the install directory root is writable by standard users.
    C:\\Program Files will correctly return False.
    """
    results = []
    if not path_writable_by_non_admin(install_dir):
        print_info(f"Install directory is NOT writable by standard users: {install_dir}")
        return results

    results.append(finding(
        severity="P2",
        message=f"Install directory writable by standard users: {install_dir}",
        detail=(
            f"Directory    : {install_dir}\n"
            f"Writable     : Yes (AccessCheck confirmed)\n"
            f"Risk         : Standard users can plant or replace DLLs and executables.\n"
            f"               Any EXE here that runs as High/SYSTEM is a direct priv esc vector."
        ),
        module=MODULE_NAME,
    ))
    return results


def _check_elevated_exes(install_dir: str, exe_path: Optional[str]) -> List[dict]:
    """
    Find EXEs with elevation manifests in the install directory.

    Severity model — matches the logic used by every other Anvil module:

      P1  The target is auto-triggered (service, run key, scheduled task,
          shell extension). An attacker replaces the binary and waits — the
          system invokes it without any user interaction required.

      P2  No auto-trigger found. A user must manually launch the EXE before
          the UAC elevation fires. Requires user interaction → not P1.

      P5  Directory is NOT writable. Informational context only.

    The previous code assigned P1 unconditionally for any writable-dir +
    manifest combination, which is wrong: it never verified that anything
    actually invokes the EXE without user interaction.
    """
    results = []
    if not os.path.isdir(install_dir):
        return results

    dir_writable = path_writable_by_non_admin(install_dir)

    # _is_auto_triggered checks service registration, run keys, scheduled
    # tasks, and shell extensions for the target exe. If the install dir is
    # auto-triggered, replacing any elevation-manifest EXE inside it is P1.
    auto_trigger, auto_trigger_desc = _is_auto_triggered(exe_path)

    try:
        for fname in os.listdir(install_dir):
            if not fname.lower().endswith(".exe"):
                continue
            fpath = os.path.join(install_dir, fname)
            if not os.path.isfile(fpath):
                continue
            if not _has_elevation_manifest(fpath):
                continue

            if dir_writable:
                if auto_trigger:
                    sev = "P1"
                    trigger_line = f"Trigger      : {auto_trigger_desc}"
                    attack_note  = (
                        f"Attack       : Replace this EXE with a malicious binary.\n"
                        f"               The auto-trigger will invoke it without user\n"
                        f"               interaction, causing elevation to Administrator."
                    )
                else:
                    sev = "P2"
                    trigger_line = "Trigger      : User-launched (no auto-trigger detected)"
                    attack_note  = (
                        f"Attack       : Replace this EXE with a malicious binary.\n"
                        f"               When a user manually launches it, UAC will elevate\n"
                        f"               it to Administrator. Requires user interaction —\n"
                        f"               this is why it is P2, not P1."
                    )

                results.append(finding(
                    severity=sev,
                    message=f"Elevation-manifest EXE in writable dir: {fpath}",
                    detail=(
                        f"Binary       : {fpath}\n"
                        f"Manifest     : requireAdministrator / highestAvailable detected\n"
                        f"Directory    : {install_dir}  ← WRITABLE by standard users\n"
                        f"{trigger_line}\n"
                        f"{attack_note}"
                    ),
                    module=MODULE_NAME,
                ))
            else:
                results.append(finding(
                    severity="P5",
                    message=f"Elevation-manifest EXE (dir not writable): {fpath}",
                    detail=(
                        f"Binary       : {fpath}\n"
                        f"Manifest     : requireAdministrator / highestAvailable\n"
                        f"Directory    : {install_dir}  (not writable by standard users)\n"
                        f"Note         : If another vulnerability makes this dir writable,\n"
                        f"               this EXE becomes a priv esc target."
                    ),
                    module=MODULE_NAME,
                ))
    except PermissionError:
        pass
    except Exception:
        pass

    return results



def _check_subdirectories(install_dir: str, max_depth: int = 4) -> List[dict]:
    """
    Recursively check subdirectories (up to max_depth levels deep) for
    weaker ACLs than the parent install directory.  Only reports subdirs
    that are confirmed writable by a standard user via AccessCheck.

    Previously only checked immediate children — writable subdirs more
    than one level deep were silently missed.
    """
    results  = []
    seen     = set()   # guard against symlink loops

    def _walk(directory: str, depth: int) -> None:
        if depth > max_depth:
            return
        if not os.path.isdir(directory):
            return
        try:
            real = os.path.realpath(directory)
        except Exception:
            real = directory
        if real in seen:
            return
        seen.add(real)

        try:
            for entry in os.scandir(directory):
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if path_writable_by_non_admin(entry.path):
                    results.append(finding(
                        severity="P2",
                        message=f"Writable subdirectory inside install dir: {entry.path}",
                        detail=(
                            f"Subdirectory : {entry.path}\n"
                            f"Depth        : {depth}\n"
                            f"Writable     : Yes (AccessCheck confirmed)\n"
                            f"Risk         : If any DLLs or plugins load from this subdir,\n"
                            f"               a standard user can plant a malicious replacement.\n"
                            f"               Check DLL hijacking results for files in this path."
                        ),
                        module=MODULE_NAME,
                    ))
                # Recurse regardless of writability — deeper subdirs may be writable
                _walk(entry.path, depth + 1)
        except PermissionError:
            pass   # Some subdirs may be inaccessible; skip silently
        except Exception:
            pass

    _walk(install_dir, 1)
    return results


def _print_install_dir_tree(
    install_dir: str,
    root_writable: bool,
    elevated_exes: List[dict],
    writable_subdirs: List[dict],
) -> None:

    try:
        from rich.console import Console as _Console
        _console_tree = _Console(highlight=False)
        _rich = True
    except ImportError:
        _rich = False

    sev = "P2" if (root_writable or elevated_exes or writable_subdirs) else "P5"

    if _rich:
        sev_style = {"P1": "bold red", "P2": "red", "P3": "yellow"}.get(sev, "white")
        prefix = "[ - ]" if sev in ("P1", "P2", "P3") else "[ * ]"
        _console_tree.print(
            f"  [bold {sev_style}]{prefix}[/bold {sev_style}] "
            f"[{sev_style}][{sev}][/{sev_style}] "
            f"[yellow]{install_dir}[/yellow]"
        )
        if root_writable:
            _console_tree.print(f"        [dim]├─[/dim] Root writable  : Yes (AccessCheck confirmed)")
        if elevated_exes:
            names = ", ".join(os.path.basename(f["message"].split(": ", 1)[-1]) for f in elevated_exes)
            _console_tree.print(f"        [dim]├─[/dim] Elevated EXEs  : {names}")
        if writable_subdirs:
            count = len(writable_subdirs)
            _console_tree.print(f"        [dim]└─[/dim] Writable subdirs ({count}):")
            for i, sd in enumerate(writable_subdirs):
                path = sd["message"].split(": ", 1)[-1]
                rel = os.path.relpath(path, install_dir)
                connector = "└─" if i == count - 1 else "├─"
                _console_tree.print(f"             [dim]{connector}[/dim] {rel}")
    else:
        prefix = "[ - ]" if sev in ("P1", "P2", "P3") else "[ * ]"
        print(f"  {prefix} [{sev}] {install_dir}")
        if root_writable:
            print(f"        ├─ Root writable  : Yes (AccessCheck confirmed)")
        if elevated_exes:
            names = ", ".join(os.path.basename(f["message"].split(": ", 1)[-1]) for f in elevated_exes)
            print(f"        ├─ Elevated EXEs  : {names}")
        if writable_subdirs:
            count = len(writable_subdirs)
            print(f"        └─ Writable subdirs ({count}):")
            for i, sd in enumerate(writable_subdirs):
                path = sd["message"].split(": ", 1)[-1]
                rel = os.path.relpath(path, install_dir)
                connector = "└─" if i == count - 1 else "├─"
                print(f"             {connector} {rel}")
    print()


def run(ctx: dict) -> List[dict]:
    findings = []
    install_dir = ctx.get("install_dir")
    exe_path    = ctx.get("exe_path")

    if not install_dir:
        print_warning("No install directory – skipping insecure install dir check.")
        return findings

    print_info(f"Target install directory: {install_dir}")

    # Informational note only — being outside Program Files is not a vulnerability
    if not _is_in_safe_root(install_dir):
        findings.append(finding(
            severity="P5",
            message=f"Application installed outside standard paths: {install_dir}",
            detail=(
                f"Install path : {install_dir}\n"
                f"Note         : Being outside 'Program Files' or 'Windows' means the directory\n"
                f"               may not inherit the standard protected ACLs. The actual ACL\n"
                f"               is checked below — this is informational, not a vulnerability."
            ),
            module=MODULE_NAME,
        ))

    root_findings = _check_root_acl(install_dir)
    root_writable = bool(root_findings)
    for f in root_findings:
        f["_tree_printed"] = True
    findings.extend(root_findings)

    elevated_findings = _check_elevated_exes(install_dir, exe_path)
    for f in elevated_findings:
        f["_tree_printed"] = True
    findings.extend(elevated_findings)

    subdir_findings = _check_subdirectories(install_dir)
    for f in subdir_findings:
        f["_tree_printed"] = True
    findings.extend(subdir_findings)

    # ── Tree-format summary (mirrors named pipe ACL output) ───────────────────
    has_vulns = root_writable or elevated_findings or subdir_findings
    if has_vulns:
        _print_install_dir_tree(
            install_dir    = install_dir,
            root_writable  = root_writable,
            elevated_exes  = [f for f in elevated_findings if f.get("severity") in ("P1", "P2")],
            writable_subdirs = subdir_findings,
        )
    else:
        print_info("No insecure install directory issues found (ACLs are correctly configured).")

    return findings
