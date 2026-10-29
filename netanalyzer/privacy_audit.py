"""Best-effort scanner for residual IP/MAC identifiers in public JSON/HTML reports."""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
IP_RE = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", re.I)
PLACEHOLDERS = ("[IP REDACTED]", "[MAC REDACTED]", "[HOSTNAME REDACTED]", "[PLATFORM REDACTED]", "[INTERFACE]")


def scan_text(text):
    findings = []
    for match in MAC_RE.finditer(text):
        findings.append({"type": "mac_address", "value": match.group(0)})
    for match in IP_RE.finditer(text):
        raw = match.group(0).strip(" .;,()[]{}")
        if any(marker in raw for marker in PLACEHOLDERS):
            continue
        candidate = raw.split("/", 1)[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        # Loopback/link-local values are still identifiers/configuration and are reported too.
        findings.append({"type": "ip_address", "value": raw})
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Procura possíveis IPs/MAC residuais em relatórios públicos.")
    parser.add_argument("files", nargs="+", help="Ficheiros HTML/JSON a analisar")
    args = parser.parse_args(argv)
    found = False
    for name in args.files:
        path = Path(name)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERRO {path}: {exc}", file=sys.stderr); found = True; continue
        if path.suffix.lower() == ".json":
            try:
                data = json.loads(text)
                if isinstance(data, dict) and data.get("privacy_profile") != "public":
                    print(f"AVISO {path}: campo privacy_profile não é 'public'.")
            except json.JSONDecodeError as exc:
                print(f"ERRO {path}: JSON inválido: {exc}"); found = True; continue
        findings = scan_text(text)
        if findings:
            found = True
            print(f"POSSÍVEIS IDENTIFICADORES em {path}:")
            for item in findings[:50]:
                print(f"  {item['type']}: {item['value']}")
            if len(findings) > 50: print(f"  ... e mais {len(findings)-50} ocorrência(s)")
        else:
            print(f"OK {path}: não foram encontrados IPs/MAC em texto simples.")
    if found:
        print("\nRever os resultados manualmente. Este scanner é heurístico e não garante anonimato.")
        return 1
    print("\nVerificação heurística concluída; isto não garante anonimato absoluto.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
