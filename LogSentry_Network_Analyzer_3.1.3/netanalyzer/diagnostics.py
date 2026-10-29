"""Read-only local network diagnostics for Linux; all external probes have timeouts."""
import http.client
import json
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from . import __version__

COMMAND_TIMEOUT = 5
CONNECT_TIMEOUT = 4
HTTP_TIMEOUT = 5
DEFAULT_HOST = "example.com"


def command(args, timeout=COMMAND_TIMEOUT):
    """Run a fixed-argument system command without a shell and bound its runtime."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {"returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip(), "timed_out": False}
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "command not found", "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "timeout", "timed_out": True}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": False}


def collect_linux():
    result = {"interfaces": [], "routes": [], "neighbors": [], "dns": {}}
    ip = shutil.which("ip")
    if ip:
        addr = command([ip, "-j", "addr", "show"])
        r4 = command([ip, "-j", "-4", "route", "show", "table", "main"])
        r6 = command([ip, "-j", "-6", "route", "show", "table", "main"])
        nei = command([ip, "-j", "neigh", "show"])
        warnings = []
        if addr["timed_out"] or addr["returncode"] not in (0, None): warnings.append("Falha ao recolher interfaces com o comando ip.")
        try:
            for interface in json.loads(addr["stdout"] or "[]"):
                result["interfaces"].append({"name": interface.get("ifname"), "state": interface.get("operstate"), "mtu": interface.get("mtu"),
                    "addresses": [{"family": a.get("family"), "address": a.get("local"), "prefixlen": a.get("prefixlen"), "scope": a.get("scope")} for a in interface.get("addr_info", [])]})
        except (json.JSONDecodeError, TypeError): warnings.append("Não foi possível interpretar os dados das interfaces.")
        for raw, family in ((r4, "IPv4"), (r6, "IPv6")):
            try:
                for route in json.loads(raw["stdout"] or "[]"):
                    result["routes"].append({"family": family, "destination": route.get("dst", "default"), "gateway": route.get("gateway"), "device": route.get("dev"), "table": route.get("table", "main")})
            except (json.JSONDecodeError, TypeError): warnings.append(f"Não foi possível interpretar as rotas {family}.")
        try:
            for neighbor in json.loads(nei["stdout"] or "[]"):
                result["neighbors"].append({"ip": neighbor.get("dst"), "device": neighbor.get("dev"), "mac": neighbor.get("lladdr"), "state": neighbor.get("state")})
        except (json.JSONDecodeError, TypeError): warnings.append("Não foi possível interpretar a cache de vizinhos.")
        if warnings: result["collection_warnings"] = warnings
    else:
        result["collection_warnings"] = ["Comando 'ip' não encontrado; dados de interfaces e rotas podem estar incompletos."]
    try:
        lines = Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines()
        result["dns"]["nameservers"] = [line.split()[1] for line in lines if line.strip().startswith("nameserver ") and len(line.split()) > 1]
    except OSError as exc: result["dns"]["error"] = str(exc)
    return result


def collect_windows():
    """Collect Windows interface details through psutil and read-only PowerShell cmdlets."""
    result = {"interfaces": [], "routes": [], "neighbors": [], "dns": {}, "collection_warnings": []}
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, addresses in psutil.net_if_addrs().items():
            entry = {"name": name, "state": "UP" if stats.get(name) and stats[name].isup else "DOWN",
                     "mtu": stats[name].mtu if name in stats else None, "addresses": []}
            for addr in addresses:
                family_name = "inet" if addr.family == socket.AF_INET else ("inet6" if addr.family == socket.AF_INET6 else None)
                if family_name:
                    entry["addresses"].append({"family": family_name, "address": addr.address.split("%", 1)[0],
                                                "prefixlen": None, "scope": "unknown"})
            result["interfaces"].append(entry)
    except (ImportError, OSError) as exc:
        result["collection_warnings"].append(f"Não foi possível recolher interfaces via psutil: {exc}")

    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        result["collection_warnings"].append("PowerShell não encontrado; rotas, vizinhos e DNS podem estar incompletos.")
        return result
    queries = {
        "routes": "Get-NetRoute -ErrorAction SilentlyContinue | Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json -Compress",
        "neighbors": "Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Json -Compress",
        "dns": "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress"
    }
    for key, script in queries.items():
        try:
            proc = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=8, check=False)
            if proc.returncode != 0:
                result["collection_warnings"].append(f"PowerShell não conseguiu recolher {key}.")
                continue
            raw = json.loads(proc.stdout.strip().lstrip("\ufeff") or "null")
            rows = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
            if key == "routes":
                for row in rows:
                    family = "IPv4" if str(row.get("AddressFamily")) in ("2", "IPv4") else "IPv6"
                    dest = row.get("DestinationPrefix") or "default"
                    result["routes"].append({"family": family, "destination": dest, "gateway": row.get("NextHop"),
                                              "device": row.get("InterfaceAlias"), "table": "main"})
            elif key == "neighbors":
                for row in rows:
                    result["neighbors"].append({"ip": row.get("IPAddress"), "mac": row.get("LinkLayerAddress"),
                                                 "state": row.get("State"), "device": row.get("InterfaceAlias")})
            else:
                servers = []
                for row in rows:
                    values = row.get("ServerAddresses") or []
                    if isinstance(values, str): values = [values]
                    servers.extend(values)
                result["dns"]["nameservers"] = sorted(set(servers))
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, TypeError) as exc:
            result["collection_warnings"].append(f"Recolha Windows de {key} indisponível: {exc}")
    return result


def dns_test(host=DEFAULT_HOST, timeout=CONNECT_TIMEOUT):
    """Resolve a host. getaddrinfo uses the system resolver; a worker thread is intentionally avoided.

    The OS resolver can have platform-specific blocking behavior; the configured socket timeout does
    not impose a hard timeout on getaddrinfo. This limitation is surfaced in documentation.
    """
    start = time.perf_counter()
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        finally:
            socket.setdefaulttimeout(old_timeout)
        return {"target": host, "ok": bool(addresses), "addresses": addresses,
                "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": None if addresses else "No addresses returned"}
    except OSError as exc:
        return {"target": host, "ok": False, "addresses": [], "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": str(exc)}


def tcp_test(host=DEFAULT_HOST, port=443, family=socket.AF_UNSPEC, timeout=CONNECT_TIMEOUT):
    start = time.perf_counter()
    try: infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except OSError as exc:
        return {"target": host, "port": port, "ok": False, "connection": None, "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": str(exc)}
    success, errors = None, []
    for af, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            success = {"address": sockaddr[0], "family": "IPv6" if af == socket.AF_INET6 else "IPv4"}
            break
        except OSError as exc: errors.append(str(exc))
        finally: sock.close()
    return {"target": host, "port": port, "ok": success is not None, "connection": success,
            "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": None if success else (errors[-1] if errors else "No address returned")}


def tls_test(host=DEFAULT_HOST, family=socket.AF_INET, timeout=CONNECT_TIMEOUT):
    """Validate TLS certificate and hostname using the system trust store."""
    start = time.perf_counter()
    context = ssl.create_default_context()
    try:
        infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
        errors = []
        for af, socktype, proto, _, sockaddr in infos:
            raw = socket.socket(af, socktype, proto); raw.settimeout(timeout)
            try:
                raw.connect(sockaddr)
                with context.wrap_socket(raw, server_hostname=host) as secure:
                    cert = secure.getpeercert()
                    return {"target": host, "ok": True, "verified": True, "tls_version": secure.version(),
                            "cipher": secure.cipher()[0] if secure.cipher() else None,
                            "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": None}
            except (OSError, ssl.SSLError) as exc:
                errors.append(str(exc)); raw.close()
        return {"target": host, "ok": False, "verified": False, "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": errors[-1] if errors else "No address returned"}
    except (OSError, ssl.SSLError) as exc:
        return {"target": host, "ok": False, "verified": False, "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": str(exc)}


def https_test(host=DEFAULT_HOST, timeout=HTTP_TIMEOUT):
    """Perform an HTTPS HEAD request; report TLS verification separately from HTTP status."""
    start = time.perf_counter()
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ssl.create_default_context())
    try:
        conn.request("HEAD", "/", headers={"User-Agent": "LogSentry-Network-Analyzer/2.3"})
        response = conn.getresponse()
        return {"target": host, "ok": 200 <= response.status < 500, "http_status": response.status,
                "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": None}
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"target": host, "ok": False, "http_status": None, "elapsed_ms": round((time.perf_counter()-start)*1000, 2), "error": str(exc)}
    finally: conn.close()


def has_ipv6_default_route(network):
    return any(r.get("family") == "IPv6" and r.get("destination") in (None, "default", "::/0") for r in network.get("routes", []))


def effective_route(destination, family=socket.AF_INET6, timeout=COMMAND_TIMEOUT):
    """Ask Linux kernel for the selected route to a specific destination using `ip route get`."""
    exe = shutil.which("ip")
    if not exe: return {"ok": False, "destination": destination, "error": "ip command not found"}
    flag = "-6" if family == socket.AF_INET6 else "-4"
    result = command([exe, flag, "route", "get", destination], timeout=timeout)
    if result["returncode"] != 0 or not result["stdout"]:
        return {"ok": False, "destination": destination, "error": result["stderr"] or "No route returned", "timed_out": result["timed_out"]}
    # Do not parse the whole grammar: preserve the kernel's first route line for diagnostic context.
    return {"ok": True, "destination": destination, "route": result["stdout"].splitlines()[0]}


def classify_ipv6_check(check, network):
    result = dict(check)
    destination = None
    try:
        infos = socket.getaddrinfo(result.get("target", DEFAULT_HOST), 443, socket.AF_INET6, socket.SOCK_STREAM)
        if infos: destination = infos[0][4][0]
    except OSError: pass
    if destination and platform.system().lower() == "linux":
        route = effective_route(destination, socket.AF_INET6)
        result["effective_route"] = route
        if route.get("ok"):
            result["diagnosis"] = "route_selected"
            result["message"] = "O kernel selecionou uma rota IPv6 para o destino; a conectividade ainda depende do resultado da ligação."
        else:
            result["diagnosis"] = "no_effective_ipv6_route"
            result["message"] = "O kernel não devolveu uma rota IPv6 utilizável para o destino testado."
    elif destination and platform.system().lower() == "windows":
        result["diagnosis"] = "route_present" if has_ipv6_default_route(network) else "route_unknown"
        result["message"] = "Foi detetada uma rota IPv6 predefinida no Windows; a ligação TCP é a evidência principal de conectividade." if has_ipv6_default_route(network) else "A rota IPv6 efetiva não foi confirmada; consultar a tabela de rotas do Windows."
    elif not has_ipv6_default_route(network):
        result["diagnosis"] = "no_ipv6_default_route"
        result["message"] = "Não foi encontrada rota IPv6 predefinida na tabela principal; podem existir rotas específicas ou encaminhamento por políticas."
    if result.get("ok"):
        result["diagnosis"] = "connected"; result["message"] = "Ligação TCP IPv6 estabelecida."
    elif result.get("diagnosis") not in ("no_effective_ipv6_route", "no_ipv6_default_route"):
        result["diagnosis"] = "connection_failed"
        result["message"] = "A ligação IPv6 falhou; verificar encaminhamento, firewall, DNS e destino remoto."
    return result


def ping_test(target):
    exe = shutil.which("ping")
    if not exe: return {"target": target, "ok": None, "supported": False, "message": "Comando ping não encontrado"}
    if platform.system().lower() == "windows":
        args = [exe, "-n", "4", "-w", "2000", target]
    else:
        args = [exe, "-n", "-c", "4", "-W", "2", target]
    p = command(args, timeout=12)
    output = p["stdout"] + "\n" + p["stderr"]
    loss = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet loss|loss)", output, re.I)
    avg = re.search(r"(?:rtt|round-trip)[^=]+=\s*[\d.]+/([\d.]+)(?:/|\s)", output, re.I)
    if not avg and platform.system().lower() == "windows":
        avg = re.search(r"Average\s*=\s*(\d+)ms", output, re.I)
    return {"target": target, "ok": p["returncode"] == 0, "supported": True,
            "packet_loss_percent": float(loss.group(1)) if loss else None,
            "average_latency_ms": float(avg.group(1)) if avg else None, "output": output.strip(), "timed_out": p["timed_out"]}


def build_summary(network, checks):
    findings=[]
    dns=checks["dns"]
    findings.append({"status":"ok" if dns.get("ok") else "warning","title":"DNS","detail":"Resolução de nomes concluída." if dns.get("ok") else f"Falha na resolução DNS: {dns.get('error') or 'erro desconhecido'}"})
    tcp=checks["tcp_ipv4"]
    findings.append({"status":"ok" if tcp.get("ok") else "warning","title":"TCP IPv4","detail":f"Ligação TCP a {tcp.get('target')}:{tcp.get('port')} estabelecida." if tcp.get("ok") else f"Falha TCP: {tcp.get('error') or 'erro desconhecido'}"})
    tls=checks["tls_ipv4"]
    findings.append({"status":"ok" if tls.get("ok") else "warning","title":"TLS IPv4","detail":f"TLS validado ({tls.get('tls_version') or 'versão não identificada'})." if tls.get("ok") else f"Validação TLS falhou: {tls.get('error') or 'erro desconhecido'}"})
    http=checks["https_http"]
    findings.append({"status":"ok" if http.get("ok") else "warning","title":"HTTPS/HTTP","detail":f"Pedido HTTPS concluído com estado HTTP {http.get('http_status')}." if http.get("ok") else f"Pedido HTTPS falhou: {http.get('error') or 'erro desconhecido'}"})
    ipv6=checks["tcp_ipv6"]
    findings.append({"status":"ok" if ipv6.get("ok") else "warning","title":"IPv6","detail":ipv6.get("message") or ipv6.get("error") or "Sem resultado."})
    ping=checks["icmp_public_ipv4"]
    findings.append({"status":"info" if ping.get("packet_loss_percent")==100 or ping.get("ok") is not True else "ok","title":"ICMP público","detail":"Sem respostas ICMP; isto não prova falha de Internet. Algumas redes filtram ICMP." if ping.get("packet_loss_percent")==100 else ("O destino ICMP respondeu." if ping.get("ok") else "Estado ICMP não confirmado; considerar os testes TCP/TLS/HTTP separadamente.")})
    findings.append({"status":"info","title":"Cache de vizinhos","detail":f"{len(network.get('neighbors', []))} entradas em cache; não é um inventário completo de dispositivos."})
    for warning in network.get("collection_warnings",[]): findings.append({"status":"warning","title":"Recolha de dados","detail":warning})
    return findings


def collect():
    system = platform.system().lower()
    if system == "linux": network = collect_linux()
    elif system == "windows": network = collect_windows()
    else: network = {"interfaces": [], "routes": [], "neighbors": [], "dns": {}, "note": f"Recolha detalhada não implementada para {platform.system()}.", "collection_warnings": []}
    checks={"dns":dns_test(),"tcp_ipv4":tcp_test(family=socket.AF_INET),"tcp_ipv6":tcp_test(family=socket.AF_INET6),
            "tls_ipv4":tls_test(family=socket.AF_INET),"https_http":https_test(),"icmp_public_ipv4":ping_test("1.1.1.1")}
    checks["tcp_ipv6"]=classify_ipv6_check(checks["tcp_ipv6"],network)
    gateway=next((r["gateway"] for r in network.get("routes",[]) if r.get("family")=="IPv4" and r.get("destination")=="default" and r.get("gateway")),None)
    checks["icmp_gateway"]=ping_test(gateway) if gateway else {"target":None,"ok":None,"supported":False,"message":"Não foi encontrado gateway IPv4"}
    return {"product":"LogSentry Network Analyzer","version":__version__,"generated_at":datetime.now(timezone.utc).isoformat(),
            "hostname":socket.gethostname(),"platform":platform.platform(),"network":network,"checks":checks,"summary":build_summary(network,checks)}
