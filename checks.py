"""Safe, read-only endpoint checks. No command in this module changes system state."""
import platform
import shutil
import subprocess
from typing import Sequence

from .models import CheckResult


def _run(command: Sequence[str], timeout: int = 12) -> tuple[bool, str]:
    """Run a known status/query command; never invoke a shell."""
    try:
        completed = subprocess.run(
            list(command), capture_output=True, text=True, timeout=timeout,
            check=False, shell=False,
        )
        output = (completed.stdout + "\n" + completed.stderr).strip()
        return completed.returncode == 0, output[:5000]
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError) as exc:
        return False, f"Unable to run query: {exc.__class__.__name__}"


def _which(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def check_firewall() -> CheckResult:
    system = platform.system()
    if system == "Windows":
        cmd = _which("powershell", "pwsh")
        if not cmd:
            return CheckResult("FW-01", "Host firewall", "UNKNOWN", "PowerShell was not found.", "Verify Windows Defender Firewall is enabled for Domain, Private, and Public profiles.")
        ok, out = _run([cmd, "-NoProfile", "-NonInteractive", "-Command", "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -HideTableHeaders"])
        enabled = [line for line in out.splitlines() if "True" in line]
        disabled = [line for line in out.splitlines() if "False" in line]
        status = "PASS" if ok and enabled and not disabled else ("WARN" if ok and disabled else "UNKNOWN")
    elif system == "Darwin":
        cmd = _which("/usr/libexec/ApplicationFirewall/socketfilterfw")
        if not cmd:
            return CheckResult("FW-01", "Host firewall", "UNKNOWN", "macOS firewall utility was not found.", "Review System Settings > Network > Firewall.")
        ok, out = _run([cmd, "--getglobalstate"])
        status = "PASS" if ok and "enabled" in out.lower() else ("WARN" if ok and "disabled" in out.lower() else "UNKNOWN")
    elif system == "Linux":
        ufw = _which("ufw")
        if ufw:
            ok, out = _run([ufw, "status"])
            status = "PASS" if ok and "status: active" in out.lower() else ("WARN" if ok and "inactive" in out.lower() else "UNKNOWN")
        else:
            fw = _which("firewall-cmd")
            if fw:
                ok, out = _run([fw, "--state"])
                status = "PASS" if ok and out.strip().lower() == "running" else ("WARN" if ok else "UNKNOWN")
            else:
                return CheckResult("FW-01", "Host firewall", "UNKNOWN", "No supported UFW or firewalld query tool was found.", "Check the active nftables/iptables or distribution firewall configuration with the system administrator.")
    else:
        return CheckResult("FW-01", "Host firewall", "UNKNOWN", f"Unsupported platform: {system}", "Verify the host firewall using the operating system's documented settings.")
    return CheckResult("FW-01", "Host firewall", status, out or "No status output.", "Enable the host firewall and verify all applicable network profiles. Review required inbound exceptions.", out)


def check_disk_encryption() -> CheckResult:
    system = platform.system()
    if system == "Windows":
        cmd = _which("manage-bde")
        if not cmd:
            return CheckResult("ENC-01", "Disk encryption", "UNKNOWN", "manage-bde was not found.", "Verify BitLocker status in Windows Settings or with an authorized administrator.")
        ok, out = _run([cmd, "-status", "C:"])
        low = out.lower()
        status = "PASS" if ok and "conversion status: fully encrypted" in low and "protection status: protection on" in low else ("WARN" if ok and ("fully decrypted" in low or "protection status: protection off" in low) else "UNKNOWN")
    elif system == "Darwin":
        cmd = _which("fdesetup")
        if not cmd:
            return CheckResult("ENC-01", "Disk encryption", "UNKNOWN", "fdesetup was not found.", "Verify FileVault in System Settings > Privacy & Security.")
        ok, out = _run([cmd, "status"])
        status = "PASS" if ok and "filevault is on" in out.lower() else ("WARN" if ok and "filevault is off" in out.lower() else "UNKNOWN")
    elif system == "Linux":
        cmd = _which("lsblk")
        if not cmd:
            return CheckResult("ENC-01", "Disk encryption", "UNKNOWN", "lsblk was not found.", "Ask the administrator to verify LUKS/dm-crypt coverage for all relevant volumes.")
        ok, out = _run([cmd, "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])
        encrypted = ok and ("crypt" in out.lower() or " luks" in out.lower())
        status = "INFO" if encrypted else "UNKNOWN"
        return CheckResult("ENC-01", "Disk encryption", status, "Encrypted block-device indicators found; full coverage is not established." if encrypted else "The query did not establish encryption coverage.", "Verify that every relevant data volume and swap area is encrypted and that recovery keys are safely escrowed.", out)
    else:
        return CheckResult("ENC-01", "Disk encryption", "UNKNOWN", f"Unsupported platform: {system}", "Verify full-disk encryption using vendor documentation.")
    return CheckResult("ENC-01", "Disk encryption", status, out or "No status output.", "Enable full-disk encryption (BitLocker/FileVault/LUKS) and confirm protection is active.", out)


def check_admin_accounts() -> CheckResult:
    system = platform.system()
    if system == "Windows":
        cmd = _which("net.exe", "net")
        args = [cmd, "localgroup", "Administrators"] if cmd else None
    elif system == "Darwin":
        cmd = _which("dscl")
        args = [cmd, ".", "-read", "/Groups/admin", "GroupMembership"] if cmd else None
    elif system == "Linux":
        cmd = _which("getent")
        args = [cmd, "group", "sudo"] if cmd else None
        if not cmd:
            cmd = _which("getent")
            args = [cmd, "group", "wheel"] if cmd else None
    else:
        args = None
    if not args:
        return CheckResult("IAM-01", "Administrator membership", "UNKNOWN", "No supported group query is available.", "Review local and directory-managed administrator groups.")
    ok, out = _run(args)
    status = "INFO" if ok and out else "UNKNOWN"
    return CheckResult("IAM-01", "Administrator membership", status, "Group membership query completed. Review whether each listed account requires elevated access." if ok else out, "Apply least privilege; remove stale or unnecessary administrator membership only with owner approval.", out)


def check_updates() -> CheckResult:
    system = platform.system()
    if system == "Windows":
        cmd = _which("powershell", "pwsh")
        args = [cmd, "-NoProfile", "-NonInteractive", "-Command", "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,InstalledOn | Format-Table -HideTableHeaders"] if cmd else None
        note = "Recent installed hotfixes are shown; this does not prove no updates are pending. Check Windows Update for pending updates."
    elif system == "Darwin":
        cmd = _which("softwareupdate")
        args = [cmd, "-l"] if cmd else None
        note = "Review the listed available updates and install approved security updates."
    elif system == "Linux":
        if _which("apt"):
            cmd = _which("apt")
            args = [cmd, "list", "--upgradable"]
        elif _which("dnf"):
            cmd = _which("dnf")
            args = [cmd, "check-update"]
        else:
            args = None
        note = "Review pending package updates and apply approved security updates."
    else:
        args = None
        note = "Use the operating system's supported update mechanism."
    if not args:
        return CheckResult("PATCH-01", "Operating-system updates", "UNKNOWN", "No supported update query is available.", note)
    ok, out = _run(args, timeout=25)
    if not ok and not out:
        status = "UNKNOWN"
    elif system == "Darwin" and ok and "no new software available" in out.lower():
        status = "PASS"
    elif system == "Linux" and "apt" in (cmd or ""):
        lines = [line for line in out.splitlines() if "/" in line and "upgradable" in line.lower()]
        status = "WARN" if lines else ("INFO" if ok else "UNKNOWN")
    else:
        status = "INFO" if out else "UNKNOWN"
    return CheckResult("PATCH-01", "Operating-system updates", status, note, "Install supported security updates promptly; enable automatic updates where appropriate.", out)


def manual_checklist() -> list[CheckResult]:
    items = [
        ("IAM-02", "Password and passphrase practices", "Use long, unique passphrases and a reputable password manager. Never share or record passwords in the audit report."),
        ("IAM-03", "Phishing-resistant MFA", "Enable passkeys or FIDO2/WebAuthn security keys for important accounts where supported; review recovery methods."),
        ("IAM-04", "Guest and stale accounts", "Disable unused guest accounts and remove stale accounts after approval."),
        ("HUM-01", "Physical and screen-lock hygiene", "Verify automatic screen locking, secure device storage, and safe handling of removable media."),
        ("APP-01", "Unapproved applications / browser extensions", "Review installed applications and extensions against policy; document suspected shadow IT without removing software yourself."),
        ("NET-01", "Backups and endpoint protection", "Verify endpoint protection is active and backups are recent, protected, and restorable."),
    ]
    return [CheckResult(cid, title, "MANUAL", "Not automatically inspected. Complete this check yourself and record evidence in the report template.", recommendation) for cid, title, recommendation in items]


def run_audit(include_manual: bool = True) -> list[CheckResult]:
    results = [check_firewall(), check_disk_encryption(), check_admin_accounts(), check_updates()]
    if include_manual:
        results.extend(manual_checklist())
    return results
