"""Read-only discovery of optional LogSentry integrations."""
import shutil
import subprocess
import platform
from pathlib import Path


def _service_states(names):
    if platform.system().lower() == "windows":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            return {name: "unknown" for name in names}
        mapped = {"suricata": "Suricata", "wazuh-agent": "WazuhSvc", "clamav-daemon": "ClamAV", "smbd": "LanmanServer", "nmbd": "LanmanWorkstation", "windows-firewall": "MpsSvc"}
        result = {}
        for name in names:
            service = mapped.get(name)
            if not service:
                result[name] = "not_applicable"
                continue
            try:
                proc = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", f"$s=Get-Service -Name '{service}' -ErrorAction SilentlyContinue; if ($s) {{ $s.Status.ToString() }} else {{ 'not_found' }}"], capture_output=True, text=True, timeout=4, check=False)
                result[name] = proc.stdout.strip().lower() if proc.returncode == 0 and proc.stdout.strip() else "unknown"
            except (OSError, subprocess.TimeoutExpired): result[name] = "unknown"
        return result
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return {name: ("not_applicable" if platform.system().lower() != "linux" else "unknown") for name in names}
    try:
        result = subprocess.run([systemctl, "is-active", *names], capture_output=True,
                                text=True, timeout=3, check=False)
        values = (result.stdout or "").strip().splitlines()
        return {name: (values[index] if index < len(values) else "unknown")
                for index, name in enumerate(names)}
    except (OSError, subprocess.TimeoutExpired):
        return {name: "unknown" for name in names}


def discover_integrations():
    """Detect binaries, likely event files and service state without changing the system."""
    commands = {
        "nmap": "nmap", "clamav_scanner": "clamscan", "clamav_updater": "freshclam",
        "suricata": "suricata", "wazuh_agent": "wazuh-agentd",
        "ss": "ss", "iproute2": "ip", "ufw": "ufw", "nftables": "nft",
        "samba_server": "smbd", "samba_netbios": "nmbd", "powershell": "powershell",
    }
    if platform.system().lower() == "windows":
        commands.update({"windows_firewall": "netsh", "ss": "netstat", "iproute2": "ipconfig", "ufw": "__not_applicable__", "nftables": "__not_applicable__", "samba_server": "__not_applicable__", "samba_netbios": "__not_applicable__"})
    binaries = {name: (None if command == "__not_applicable__" else shutil.which(command)) for name, command in commands.items()}
    eve_candidates = [Path("/var/log/suricata/eve.json"), Path("/var/log/suricata/eve.json.1")]
    eve_file = next((str(path) for path in eve_candidates if path.is_file()), None)
    service_names = ("suricata", "wazuh-agent", "clamav-daemon", "smbd", "nmbd", "ufw", "windows-firewall")
    services = _service_states(service_names)
    return {
        "binaries": binaries,
        "services": services,
        "suricata_eve_file": eve_file,
        "available_count": sum(value is not None for value in binaries.values()),
        "note": "A deteção de um executável ou serviço não confirma que a ferramenta esteja configurada ou a monitorizar corretamente.",
    }
