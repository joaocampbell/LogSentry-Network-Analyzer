"""Read-only local endpoint triage and explicitly scoped private-network discovery."""
import ipaddress
import json
import shutil
import re
import subprocess
from pathlib import Path


def _run(args, timeout=8):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "error": None}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": None, "stdout": "", "stderr": "", "error": str(exc)}


_SENSITIVE_PORTS = {
    21: ("FTP", "cleartext or legacy file transfer service"),
    22: ("SSH", "remote administration service"),
    23: ("Telnet", "insecure remote administration service"),
    139: ("NetBIOS-SSN", "legacy Windows file-sharing service"),
    445: ("SMB", "Windows file-sharing service"),
    3306: ("MySQL", "database service"),
    5432: ("PostgreSQL", "database service"),
    6379: ("Redis", "database/cache service"),
    9200: ("Elasticsearch", "search/database API"),
}


def _address_port(endpoint):
    """Extract a port from common ss endpoint forms, including bracketed IPv6."""
    if not isinstance(endpoint, str):
        return None, None
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint[1:].rsplit("]:", 1)
    elif ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
    else:
        return endpoint, None
    try:
        return host, int(port)
    except ValueError:
        return host, None


def _bind_scope(host):
    """Classify a socket bind address without claiming real firewall reachability."""
    if not isinstance(host, str):
        return "unknown"
    host = host.strip().strip("[]")
    if "%" in host:  # IPv6 zone identifier, e.g. fe80::1%wlp1s0
        host = host.split("%", 1)[0]
    if host in {"", "*", "0.0.0.0", "::", ":::"}:
        return "all_interfaces"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback_only"
    if address.is_unspecified:
        return "all_interfaces"
    return "specific_non_loopback"


def _process_from_ss(line):
    """Extract process metadata from ss output when the OS grants visibility."""
    match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
    if not match:
        return None
    return {"name": match.group(1), "pid": match.group(2)}


def _parse_ss_line(line, kind):
    """Parse one `ss -H` row for listening or established sockets.

    Listening rows normally have: Netid State Recv-Q Send-Q Local Peer [Process].
    Both TCP listening and established rows have six mandatory whitespace-separated
    fields; process metadata is optional and appears after the peer endpoint.
    """
    fields = line.split()
    minimum = 6
    if len(fields) < minimum:
        return None
    if kind == "listening" and fields[1].upper() not in {"LISTEN", "UNCONN"}:
        return None
    return {
        "protocol": fields[0],
        "state": fields[1],
        "local": fields[4],
        "peer": fields[5],
        "process": _process_from_ss(line),
    }


def _read_ss_lines(ss_path, args):
    """Read socket metadata; prefer a non-interactive elevated snapshot only if richer.

    `sudo -n` never prompts. It succeeds only when credentials are already cached or
    policy permits it, so this helper never asks for or stores a password.
    """
    proc = _run([ss_path, *args], timeout=5)
    if proc["returncode"] != 0:
        return [], False, proc.get("error") or proc.get("stderr") or "comando ss falhou"
    lines = proc["stdout"].splitlines()
    if not any("p" in arg for arg in args):
        return lines, False, None
    normal_count = sum(1 for line in lines if _process_from_ss(line))
    # Always compare with a non-interactive privileged read: normal `ss` can expose
    # some PIDs but hide others, so checking only whether *any* PID exists is unsafe.
    sudo = shutil.which("sudo")
    if sudo:
        privileged = _run([sudo, "-n", ss_path, *args], timeout=5)
        if privileged["returncode"] == 0:
            privileged_lines = privileged["stdout"].splitlines()
            privileged_count = sum(1 for line in privileged_lines if _process_from_ss(line))
            if privileged_count > normal_count:
                return privileged_lines, True, None
    return lines, False, None


def _socket_match_key(row):
    """Build a normalized protocol/address/port key for safer ss-to-psutil joins."""
    host, port = _address_port(row.get("local", ""))
    if port is None:
        return None
    host = (host or "").strip().strip("[]")
    if "%" in host:
        host = host.split("%", 1)[0]
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.lower()
    protocol = str(row.get("protocol", "")).lower()
    return protocol, host, port


def _assess_exposure(listening):
    """Flag candidates for review; severity is heuristic and not proof of reachability."""
    findings = []
    for socket in listening:
        host, port = _address_port(socket.get("local", ""))
        if port is None:
            continue
        scope = _bind_scope(host)
        if scope not in {"all_interfaces", "specific_non_loopback"}:
            continue
        service, reason = _SENSITIVE_PORTS.get(port, ("Serviço não identificado", "socket ligado a endereço não loopback"))
        # Port number alone is not enough to call SMB/NetBIOS a high-severity issue.
        if port in {6379, 9200}:
            severity = "high"
        elif port in {21, 23, 139, 445, 3306, 5432}:
            severity = "medium"
        else:
            severity = "low"
        scope_text = {
            "all_interfaces": "escuta em todas as interfaces; acessibilidade depende da firewall e do encaminhamento",
            "specific_non_loopback": "escuta num endereço não loopback; acessibilidade depende da firewall e do encaminhamento",
        }[scope]
        findings.append({
            "severity": severity, "port": port, "protocol": socket.get("protocol"),
            "local": socket.get("local"), "service": service, "reason": reason,
            "bind_scope": scope, "evidence": scope_text, "status": "potential_exposure",
            "process": socket.get("process"),
            "process_name": (socket.get("process") or {}).get("name"),
            "process_pid": (socket.get("process") or {}).get("pid"),
            "confidence": "heuristic",
            "severity_basis": "A gravidade é uma prioridade de revisão baseada no tipo de serviço e no endereço de escuta; não confirma vulnerabilidade nem acesso externo.",
            "recommendation": "Confirmar se o serviço é necessário, validar o processo/PID e rever firewall, encaminhamento e controlos de acesso antes de alterar a configuração.",
        })
    return findings


def _psutil_snapshot(result):
    """Cross-platform process and socket collection using psutil when available."""
    try:
        import psutil
    except ImportError:
        return False

    for proc in psutil.process_iter(attrs=["pid", "username", "name", "cmdline"], ad_value=None):
        try:
            info = proc.info
            cmdline = " ".join(info.get("cmdline") or [])[:240]
            result["processes"].append({"pid": info.get("pid"), "user": info.get("username"),
                "name": (info.get("name") or "")[:120], "command": cmdline})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if len(result["processes"]) >= 500:
            result["warnings"].append("A lista de processos foi limitada a 500 entradas.")
            break

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        result["warnings"].append("Não foi possível recolher todas as ligações; execute com permissões adequadas se necessário.")
        result["socket_collection_status"] = "partial_or_denied"
        connections = []
    process_cache = {}
    for conn in connections[:2000]:
        if not conn.laddr:
            continue
        proto = "tcp" if conn.type == __import__("socket").SOCK_STREAM else "udp"
        local = f"[{conn.laddr.ip}]:{conn.laddr.port}" if ":" in conn.laddr.ip else f"{conn.laddr.ip}:{conn.laddr.port}"
        peer = "*"
        if conn.raddr:
            peer = f"[{conn.raddr.ip}]:{conn.raddr.port}" if ":" in conn.raddr.ip else f"{conn.raddr.ip}:{conn.raddr.port}"
        proc_info = None
        if conn.pid:
            if conn.pid not in process_cache:
                try:
                    process_cache[conn.pid] = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    process_cache[conn.pid] = None
            proc_name = process_cache[conn.pid]
            if proc_name:
                proc_info = {"name": proc_name, "pid": str(conn.pid)}
        row = {"protocol": proto, "state": conn.status or "UNKNOWN", "local": local, "peer": peer, "process": proc_info}
        if proto == "tcp" and conn.status == psutil.CONN_LISTEN:
            result["listening"].append(row)
        elif proto == "udp" and not conn.raddr:
            # UDP has no TCP-style LISTEN state; report bound sockets as listening endpoints.
            result["listening"].append(row)
        elif proto == "tcp" and conn.status == psutil.CONN_ESTABLISHED:
            result["established"].append(row)
    if result.get("socket_collection_status") == "not_collected":
        result["socket_collection_status"] = "collected"
    result["process_attribution_method"] = "psutil (multiplataforma; permissões do sistema podem limitar os dados)"
    return True


def _enrich_processes_from_ss(result):
    """On Linux, supplement psutil socket rows with exact ss PID metadata where possible."""
    if __import__("platform").system().lower() != "linux":
        return False
    ss = shutil.which("ss")
    if not ss or not result.get("listening"):
        return False
    lines, privileged, error = _read_ss_lines(ss, ["-H", "-lntup"])
    if error:
        result.setdefault("warnings", []).append(f"Não foi possível enriquecer processos via ss: {error}")
        return False
    parsed_rows = [_parse_ss_line(line, "listening") for line in lines]
    parsed_rows = [row for row in parsed_rows if row and row.get("process")]
    if not parsed_rows:
        result["process_attribution_method"] = "psutil + ss sem metadados de processo visíveis"
        result.setdefault("warnings", []).append(
            "O ss não expôs processos. No Linux, execute `sudo -v` e volte a executar a análise; "
            "o LogSentry tentará `sudo -n ss` sem pedir a palavra-passe nem elevar a interface gráfica."
        )
        return False

    exact = {}
    by_protocol_port = {}
    for row in parsed_rows:
        key = _socket_match_key(row)
        if key is None:
            continue
        exact.setdefault(key, []).append(row)
        by_protocol_port.setdefault((key[0], key[2]), []).append(row)

    changed = False
    for row in result["listening"]:
        if row.get("process"):
            continue
        key = _socket_match_key(row)
        if key is None:
            continue
        matches = exact.get(key, [])
        # Wildcard and concrete local binds can represent the same socket. Only use
        # the weaker port fallback if every candidate resolves to the same process.
        if not matches:
            candidates = by_protocol_port.get((key[0], key[2]), [])
            identities = {(item["process"].get("pid"), item["process"].get("name")) for item in candidates}
            if len(identities) == 1:
                matches = candidates
        identities = {(item["process"].get("pid"), item["process"].get("name")) for item in matches}
        if len(identities) == 1 and matches:
            row["process"] = matches[0]["process"]
            changed = True

    if changed:
        result["process_attribution_method"] = "psutil + ss (associação por protocolo/endereço/porta)"
        if privileged:
            result["process_attribution_method"] += "; ss com sudo -n"
    return changed


def endpoint_audit(clamav_path=None, clamav_timeout=120):
    """Collect a read-only process/socket snapshot on Linux and Windows; optionally scan a chosen path with ClamAV."""
    result = {"available": True, "processes": [], "listening": [], "established": [], "exposure_findings": [],
              "clamav": {"installed": False, "scan_performed": False}, "warnings": [],
              "socket_collection_status": "not_collected", "established_collection_status": "not_collected"}
    used_psutil = _psutil_snapshot(result)
    if used_psutil:
        _enrich_processes_from_ss(result)
    if not used_psutil:
        if __import__("platform").system().lower() == "linux":
            ps = shutil.which("ps")
            if ps:
                proc = _run([ps, "-eo", "pid=,user=,comm=,args=", "--sort=-%cpu"], timeout=5)
                if proc["returncode"] == 0:
                    for line in proc["stdout"].splitlines()[:500]:
                        parts = line.strip().split(None, 3)
                        if len(parts) >= 3:
                            result["processes"].append({"pid": parts[0], "user": parts[1], "name": parts[2][:120], "command": (parts[3] if len(parts) > 3 else "")[:240]})
            ss = shutil.which("ss")
            if ss:
                for key, args in (("listening", ["-H", "-lntup"]), ("established", ["-H", "-tun", "state", "established"])):
                    lines, _, error = _read_ss_lines(ss, args)
                    if error:
                        result["warnings"].append(f"Não foi possível recolher sockets {key}: {error}")
                    for line in lines[:2000]:
                        parsed = _parse_ss_line(line, key)
                        if parsed: result[key].append(parsed)
                result["socket_collection_status"] = "collected" if result["listening"] else "empty_or_unavailable"
                result["process_attribution_method"] = "ss; metadados sujeitos a permissões"
            else:
                result["warnings"].append("psutil e ss não estão disponíveis; sockets não foram recolhidos.")
        else:
            result["warnings"].append("psutil não está instalado; recolha multiplataforma de processos/sockets indisponível.")

    clamscan = shutil.which("clamscan")
    freshclam = shutil.which("freshclam")
    result["clamav"] = {"installed": bool(clamscan), "clamscan_path": clamscan, "freshclam_path": freshclam,
                         "scan_performed": False, "status": "not_requested",
                         "message": "Nenhuma análise antivírus foi executada automaticamente." if clamscan else "ClamAV não detetado; análise de ficheiros indisponível."}
    if clamav_path is not None:
        scan_target = Path(clamav_path).expanduser()
        if not scan_target.exists():
            raise ValueError(f"O caminho indicado para análise ClamAV não existe: {scan_target}")
        if not clamscan:
            result["clamav"].update({"status": "unavailable", "message": "ClamAV não instalado; não foi realizada análise."})
        else:
            proc = _run([clamscan, "--infected", "--no-summary", "--", str(scan_target)], timeout=clamav_timeout)
            output = proc["stdout"]
            detections = []
            for line in output.splitlines():
                if line.rstrip().endswith(" FOUND"):
                    file_path, _, signature = line.rpartition(": ")
                    detections.append({"path": file_path[:500], "signature": signature[:-6][:200]})
            status = "clean" if proc["returncode"] == 0 else ("detections" if proc["returncode"] == 1 else "error")
            result["clamav"].update({"scan_performed": proc["returncode"] in (0, 1), "status": status,
                "target": str(scan_target), "detections": detections, "detection_count": len(detections),
                "returncode": proc["returncode"], "error": proc["error"],
                "message": {"clean": "ClamAV não reportou deteções no alvo analisado.",
                            "detections": "ClamAV reportou uma ou mais deteções; validar e investigar antes de agir.",
                            "error": "A análise ClamAV não terminou com sucesso."}[status]})
    result["exposure_findings"] = _assess_exposure(result["listening"])
    result["exposure_finding_count"] = len(result["exposure_findings"])
    result["process_count"] = len(result["processes"])
    result["listening_count"] = len(result["listening"])
    result["established_count"] = len(result["established"])
    if result["socket_collection_status"] == "not_collected":
        result["established_collection_status"] = "unavailable"
    elif result["established"]:
        result["established_collection_status"] = "collected_nonzero"
    elif result["socket_collection_status"] == "collected":
        result["established_collection_status"] = "collected_zero_at_snapshot"
    else:
        result["established_collection_status"] = "partial_or_unavailable"
    result["process_attributed_socket_count"] = sum(1 for item in result["listening"] if item.get("process"))
    result["process_attribution_coverage_percent"] = round(100 * result["process_attributed_socket_count"] / len(result["listening"])) if result["listening"] else 0
    if not result["listening"]:
        result["process_attribution_status"] = "no_listening_sockets_or_unavailable"
    elif result["process_attributed_socket_count"] == len(result["listening"]):
        result["process_attribution_status"] = "complete"
    elif result["process_attributed_socket_count"]:
        result["process_attribution_status"] = "partial"
    else:
        result["process_attribution_status"] = "unavailable_or_permission_limited"
    if result["listening"] and not result["process_attributed_socket_count"] and not any("Nenhum processo foi associado" in warning for warning in result["warnings"]):
        result["warnings"].append("Nenhum processo foi associado aos sockets; a visibilidade pode estar limitada por permissões do sistema.")
    if not result["listening"] and result["socket_collection_status"] != "collected":
        result["warnings"].append("A recolha de sockets está incompleta; não interpretar a lista vazia como ausência de serviços.")
    result["limitations"] = ["Uma lista de processos ou sockets não confirma nem exclui malware.",
                              "A gravidade é heurística: o número da porta não confirma vulnerabilidade nem acessibilidade externa.",
                              "Os nomes de processos e destinos devem ser validados; software legítimo pode gerar padrões incomuns.",
                              "A análise de ficheiros só é executada quando um caminho é indicado explicitamente; ClamAV não garante deteção de todas as ameaças.",
                              "A classificação de exposição é heurística; firewall, encaminhamento e permissões podem alterar a acessibilidade real."]
    return result


def discover_private_network(cidr, timeout=20, max_hosts=256):
    """Run an explicit Nmap ping scan only for a bounded private IPv4/IPv6 network."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"CIDR inválido: {exc}") from exc
    if not network.is_private or network.num_addresses > max_hosts:
        raise ValueError(f"A rede tem de ser privada e conter no máximo {max_hosts} endereços.")
    nmap = shutil.which("nmap")
    if not nmap:
        return {"available": False, "target": str(network), "hosts": [], "message": "Nmap não está instalado."}
    proc = _run([nmap, "-sn", "-n", "--max-retries", "1", "--host-timeout", "5s", str(network)], timeout=timeout)
    hosts = []
    for line in proc["stdout"].splitlines():
        if line.startswith("Nmap scan report for "):
            value = line.split(" for ", 1)[1].strip()
            if " (" in value and value.endswith(")"):
                name, ip = value.rsplit(" (", 1); ip = ip[:-1]
            else:
                name, ip = None, value
            try: ipaddress.ip_address(ip)
            except ValueError: continue
            hosts.append({"ip": ip, "name": name})
    return {"available": True, "target": str(network), "hosts": hosts, "host_count": len(hosts),
            "returncode": proc["returncode"], "error": proc["error"],
            "message": "Descoberta Nmap -sn concluída; hosts sem resposta podem continuar ligados." if proc["returncode"] == 0 else (proc["stderr"] or proc["error"] or "A descoberta Nmap falhou."),
            "scope": "Apenas descoberta de hosts; não foram testadas portas."}
