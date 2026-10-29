"""Command-line interface for LogSentry Network Analyzer."""
import argparse
import sys
from pathlib import Path
from . import __version__
from .diagnostics import collect
from .privacy import anonymize_report
from .report import write_html, write_json
from .threats import build_threat_assessment
from .security import endpoint_audit, discover_private_network
from .integrations import discover_integrations


def main(argv=None):
    parser = argparse.ArgumentParser(prog="logsentry-net", description="Diagnóstico local de conectividade e relatórios HTML/JSON.")
    parser.add_argument("--version", action="version", version=f"LogSentry Network Analyzer {__version__}")
    parser.add_argument("--out", default="output/network-report", help="Prefixo dos ficheiros de saída")
    parser.add_argument("--json-only", action="store_true", help="Gerar apenas JSON")
    parser.add_argument("--anonymize", action="store_true", help="Ocultar hostname, IP e MAC no relatório")
    parser.add_argument("--privacy-profile", choices=("standard", "public"), default="standard", help="Perfil de privacidade; public minimiza metadados")
    parser.add_argument("--suricata-eve", help="Caminho opcional para um registo Suricata EVE JSON existente")
    parser.add_argument("--baseline-file", help="Ficheiro JSON local para comparar a cache ARP/NDP com uma baseline")
    parser.add_argument("--save-baseline", action="store_true", help="Criar a baseline se ainda não existir (requer --baseline-file)")
    parser.add_argument("--endpoint-audit", action="store_true", help="Recolher snapshot local de processos e sockets (somente leitura)")
    parser.add_argument("--clamav-scan", metavar="PATH", help="Executar análise ClamAV explícita no ficheiro/pasta indicada; não remove ficheiros")
    parser.add_argument("--discover-network", metavar="CIDR", help="Descobrir hosts numa rede privada explicitamente indicada (máximo 256 endereços; requer Nmap)")
    args = parser.parse_args(argv)
    if args.save_baseline and not args.baseline_file:
        parser.error("--save-baseline requer --baseline-file")
    try:
        data = collect()
        data["integrations"] = discover_integrations()
        data["threat_assessment"] = build_threat_assessment(data.get("network", {}), args.suricata_eve, args.baseline_file, args.save_baseline)
        if args.endpoint_audit or args.clamav_scan:
            data["endpoint_audit"] = endpoint_audit(clamav_path=args.clamav_scan)
        if args.discover_network:
            data["network_discovery"] = discover_private_network(args.discover_network)
        if args.anonymize or args.privacy_profile == "public":
            data = anonymize_report(data, public_profile=args.privacy_profile == "public")
        prefix = Path(args.out); prefix.parent.mkdir(parents=True, exist_ok=True)
        json_path = prefix.with_suffix(".json"); write_json(data, json_path)
        if not args.json_only:
            html_path = prefix.with_suffix(".html"); write_html(data, html_path)
        print(f"Diagnóstico concluído para {data['hostname']}.")
        print(f"JSON: {json_path.resolve()}")
        if not args.json_only: print(f"HTML: {prefix.with_suffix('.html').resolve()}")
        if args.anonymize or args.privacy_profile == "public": print(f"Perfil de privacidade aplicado: {data.get('privacy_profile')}.")
        print("Análise de ameaças: triagem local e leitura opcional de alertas existentes; sem captura de pacotes.")
        if args.endpoint_audit or args.clamav_scan: print("Auditoria local: snapshot de processos/sockets e avaliação heurística de exposição recolhidos.")
        if args.clamav_scan: print(f"Análise ClamAV solicitada para: {args.clamav_scan} (sem quarentena ou remoção automática).")
        if args.discover_network: print(f"Descoberta de hosts executada para a rede privada indicada: {args.discover_network}.")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"erro: {exc}", file=sys.stderr); return 1

if __name__ == "__main__": raise SystemExit(main())
