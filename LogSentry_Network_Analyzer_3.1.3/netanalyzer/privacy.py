"""Privacy helpers for diagnostic reports."""
import copy
import ipaddress
import re

_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
_IP_CANDIDATE_RE = re.compile(r"(?<![0-9a-f:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f:.]{0,39}(?![0-9a-f:.])|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", re.I)



def _redact_ip_value(value):
    """Redact an IP address, optionally preserving its CIDR prefix length."""
    raw = value.strip()
    if not raw or raw.startswith("[") and "REDACTED" in raw:
        return value
    try:
        if "/" in raw:
            address, prefix = raw.rsplit("/", 1)
            ipaddress.ip_address(address)
            return f"[IP REDACTED]/{prefix}"
        ipaddress.ip_address(raw)
        return "[IP REDACTED]"
    except ValueError:
        return _redact_text(value)

def _redact_text(value):
    value = _MAC_RE.sub("[MAC REDACTED]", value)
    def replace_ip(match):
        raw = match.group(0); candidate = raw.strip(" .,:;()[]{}")
        try: ipaddress.ip_address(candidate)
        except ValueError: return raw
        left = len(raw) - len(raw.lstrip(" .,:;()[]{}")); right = len(raw) - len(raw.rstrip(" .,:;()[]{}"))
        end = len(raw) - right if right else len(raw)
        return raw[:left] + "[IP REDACTED]" + raw[end:]
    return _IP_CANDIDATE_RE.sub(replace_ip, value)


def anonymize_report(data, public_profile=False):
    """Return a copy with identifiers redacted; public_profile also minimizes host metadata."""
    result = copy.deepcopy(data)
    def walk(value, key=""):
        if isinstance(value, dict):
            for item_key, item in list(value.items()):
                low = item_key.lower()
                if low in {"mac", "lladdr"} and item:
                    value[item_key] = "[MAC REDACTED]"
                elif low in {"hostname", "host_name"} and item:
                    value[item_key] = "[HOSTNAME REDACTED]"
                elif (low in {"address", "ip", "gateway", "nameserver", "nameservers", "target_ip", "destination", "src_ip", "dest_ip"} or low.endswith("_ip")) and isinstance(item, str):
                    value[item_key] = _redact_ip_value(item)
                else:
                    value[item_key] = walk(item, low)
            return value
        if isinstance(value, list): return [walk(item, key) for item in value]
        if isinstance(value, str):
            if key in {"address", "ip", "gateway", "nameserver", "nameservers", "target_ip", "destination", "src_ip", "dest_ip"} or key.endswith("_ip"):
                return _redact_ip_value(value)
            return _redact_text(value)
        return value
    result = walk(result)
    # Endpoint command lines and user names can expose private paths, accounts, and arguments.
    endpoint = result.get("endpoint_audit")
    if public_profile and isinstance(endpoint, dict):
        for process in endpoint.get("processes", []):
            if isinstance(process, dict):
                process["user"] = "[USER REDACTED]" if process.get("user") else process.get("user")
                process.pop("command", None)
        endpoint["privacy_note"] = "Linhas de comando e nomes de utilizador omitidos no perfil público."
    result["hostname"] = "[HOSTNAME REDACTED]"
    if public_profile:
        result["platform"] = "[PLATFORM REDACTED]"
        result["generated_at"] = result.get("generated_at", "")[:10] + " [TIME REDACTED]"
        network = result.get("network", {})
        for interface in network.get("interfaces", []): interface["name"] = "[INTERFACE]"
        for route in network.get("routes", []): route["device"] = "[INTERFACE]" if route.get("device") else None
        for neighbor in network.get("neighbors", []): neighbor["device"] = "[INTERFACE]" if neighbor.get("device") else None
        # Keep useful check results, but remove detailed command output that can reveal local topology.
        checks = result.get("checks", {})
        for check in checks.values():
            if isinstance(check, dict):
                check.pop("output", None)
                check.pop("effective_route", None)
        result["privacy_profile"] = "public"
    else:
        result["privacy_profile"] = "standard-anonymized"
    return result
