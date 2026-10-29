"""JSON and self-contained HTML report generation for LogSentry."""
import html
import json
from collections import Counter


def write_json(data, path):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _value(value, fallback="—"):
    return fallback if value is None or value == "" else str(value)


def write_html(data, path):
    """Create a detailed, responsive, self-contained HTML network report."""
    esc = html.escape
    network = data.get("network") or {}
    checks = data.get("checks") or {}
    interfaces = network.get("interfaces") or []
    routes = network.get("routes") or []
    neighbors = network.get("neighbors") or []
    dns_config = network.get("dns") or {}
    threat = data.get("threat_assessment") or {}

    check_ok = sum(1 for item in checks.values() if item.get("ok") is True)
    check_fail = sum(1 for item in checks.values() if item.get("ok") is False)
    check_na = sum(1 for item in checks.values() if item.get("ok") is None)
    ipv4 = sum(1 for iface in interfaces for addr in iface.get("addresses", []) if addr.get("family") == "inet")
    ipv6 = sum(1 for iface in interfaces for addr in iface.get("addresses", []) if addr.get("family") == "inet6")
    gateways = [r for r in routes if r.get("destination") in ("default", "::/0", "0.0.0.0/0") and r.get("gateway")]
    neighbor_states = Counter(str(n.get("state") or "desconhecido") for n in neighbors)

    cards = [
        ("Verificações OK", f"{check_ok}/{len(checks)}", "ok"),
        ("Verificações falhadas", str(check_fail), "warning" if check_fail else "ok"),
        ("Interfaces detetadas", str(len(interfaces)), "info"),
        ("Endereços IPv4", str(ipv4), "info"),
        ("Endereços IPv6", str(ipv6), "info"),
        ("Rotas", str(len(routes)), "info"),
        ("Gateways predefinidos", str(len(gateways)), "info"),
        ("Vizinhos em cache", str(len(neighbors)), "info"),
    ]
    card_html = "".join(f'<article class="metric {kind}"><span>{esc(label)}</span><strong>{esc(value)}</strong></article>' for label, value, kind in cards)

    findings_html = "".join(
        f'<article class="finding {esc(item.get("status", "info"))}"><div class="finding-title">{esc(_value(item.get("title")))}</div><p>{esc(_value(item.get("detail")))}</p></article>'
        for item in data.get("summary", [])
    ) or '<p class="empty">Não foram produzidas conclusões automáticas.</p>'

    interface_rows = []
    for iface in interfaces:
        addresses = iface.get("addresses", [])
        if addresses:
            addr_text = "<br>".join(
                f'{esc(_value(a.get("family")))} · {esc(_value(a.get("address")))}/{esc(_value(a.get("prefixlen")))} · âmbito {esc(_value(a.get("scope")))}'
                for a in addresses
            )
        else:
            addr_text = "Sem endereços reportados"
        interface_rows.append(f'<tr><td>{esc(_value(iface.get("name")))}</td><td>{esc(_value(iface.get("state")))}</td><td>{esc(_value(iface.get("mtu")))}</td><td>{addr_text}</td></tr>')

    route_rows = [
        f'<tr><td>{esc(_value(r.get("family")))}</td><td>{esc(_value(r.get("destination"), "default"))}</td><td>{esc(_value(r.get("gateway")))}</td><td>{esc(_value(r.get("device")))}</td><td>{esc(_value(r.get("table"), "main"))}</td></tr>'
        for r in routes
    ]
    neighbor_rows = [
        f'<tr><td>{esc(_value(n.get("ip")))}</td><td>{esc(_value(n.get("mac")))}</td><td>{esc(_value(n.get("state")))}</td><td>{esc(_value(n.get("device")))}</td></tr>'
        for n in neighbors
    ]

    check_rows = []
    for key, item in checks.items():
        ok = item.get("ok")
        state = "OK" if ok is True else ("FALHOU" if ok is False else "N/D")
        state_class = "ok" if ok is True else ("warning" if ok is False else "info")
        detail_parts = []
        for field, label in (("target", "Destino"), ("port", "Porta"), ("http_status", "HTTP"), ("tls_version", "TLS"), ("cipher", "Cifra"), ("verified", "Certificado validado"), ("diagnosis", "Diagnóstico"), ("message", "Mensagem"), ("error", "Erro")):
            if item.get(field) is not None:
                detail_parts.append(f'<span class="detail-label">{esc(label)}:</span> {esc(str(item[field]))}')
        if item.get("connection"):
            conn = item["connection"]
            detail_parts.append(f'<span class="detail-label">Ligação:</span> {esc(_value(conn.get("family")))} · {esc(_value(conn.get("address")))}')
        if item.get("addresses"):
            detail_parts.append(f'<span class="detail-label">Endereços resolvidos:</span> {esc(", ".join(map(str, item["addresses"]))) }')
        elapsed = _value(item.get("elapsed_ms"))
        check_rows.append(f'<tr><td><code>{esc(key)}</code></td><td><span class="pill {state_class}">{state}</span></td><td>{"<br>".join(detail_parts) or "—"}</td><td class="numeric">{esc(elapsed)}</td></tr>')

    dns_rows = []
    for server in dns_config.get("nameservers", []):
        dns_rows.append(f'<tr><td>Servidor DNS configurado</td><td>{esc(str(server))}</td></tr>')
    if dns_config.get("error"):
        dns_rows.append(f'<tr><td>Erro de configuração DNS</td><td>{esc(str(dns_config["error"]))}</td></tr>')
    if not dns_rows:
        dns_rows.append('<tr><td colspan="2">Não foram encontrados servidores DNS na fonte consultada.</td></tr>')

    warnings = list(network.get("collection_warnings", []))
    if network.get("note"):
        warnings.append(network["note"])
    warnings_html = "".join(f'<li>{esc(str(w))}</li>' for w in warnings) or '<li>Sem avisos de recolha reportados.</li>'
    neighbor_summary = ", ".join(f'{state}: {count}' for state, count in sorted(neighbor_states.items())) or "Sem entradas"

    def table(title, headers, rows, empty_message="Não foram recolhidos dados."):
        rows = rows or [f'<tr><td colspan="{len(headers)}">{esc(empty_message)}</td></tr>']
        return f'<section class="section"><h2>{esc(title)}</h2><div class="panel"><table><thead><tr>{"".join(f"<th>{esc(h)}</th>" for h in headers)}</tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>'

    # Threat-triage section summarizes existing telemetry; it is not an antivirus verdict.
    components = threat.get("components") or {}
    component_rows = [
        f'<tr><td>Suricata</td><td>{"Detetado no sistema" if components.get("suricata_binary") else "Não detetado no PATH"}</td></tr>',
        f'<tr><td>Agente Wazuh</td><td>{"Detetado no sistema" if components.get("wazuh_agent_binary") else "Não detetado no PATH"}</td></tr>',
    ]
    suricata = threat.get("suricata") or {}
    alert_rows = []
    for alert in suricata.get("alerts", []):
        alert_rows.append(
            f'<tr><td>{esc(_value(alert.get("timestamp")))}</td>'
            f'<td>{esc(_value(alert.get("severity")))}</td>'
            f'<td>{esc(_value(alert.get("signature")))}</td>'
            f'<td>{esc(_value(alert.get("category")))}</td>'
            f'<td>{esc(_value(alert.get("src_ip")))}:{esc(_value(alert.get("src_port")))}</td>'
            f'<td>{esc(_value(alert.get("dest_ip")))}:{esc(_value(alert.get("dest_port")))}</td></tr>'
        )
    baseline = threat.get("neighbor_baseline") or {}
    baseline_rows = []
    for change_type in ("new", "missing"):
        for entry in baseline.get(change_type, []):
            baseline_rows.append(f'<tr><td>{"Novo na cache face à baseline" if change_type == "new" else "Ausente da cache face à baseline"}</td><td>{esc(_value(entry.get("ip")))}</td><td>{esc(_value(entry.get("mac")))}</td><td>{esc(_value(entry.get("device")))}</td></tr>')
    threat_headline = esc(_value(threat.get("headline"), "Análise de ameaças não executada."))
    threat_section = (
        f'<section class="section"><h2>Triagem de ameaças</h2>'
        f'<div class="finding {"warning" if threat.get("status") == "review" else "info"}"><div class="finding-title">{threat_headline}</div>'
        f'<p>{esc(_value(suricata.get("message")))}</p>'
        f'<p class="muted">Eventos lidos: {esc(_value(suricata.get("events_read"), "0"))} · Alertas: {esc(_value(suricata.get("alert_count"), "0"))}</p></div>'
        f'{table("Componentes de monitorização detetados", ["Componente", "Estado"], component_rows)}'
        f'{table("Alertas Suricata", ["Data/hora", "Severidade", "Assinatura", "Categoria", "Origem", "Destino"], alert_rows, "Sem alertas encontrados no registo analisado ou registo indisponível.")}'
        f'{table("Diferenças da baseline ARP/NDP", ["Alteração", "IP", "MAC", "Interface"], baseline_rows, "Sem diferenças reportadas ou baseline não configurada.")}'
        f'<div class="note"><strong>Limitações:</strong><ul>{"".join(f"<li>{esc(str(item))}</li>" for item in threat.get("limitations", []))}</ul>'
        f'<p>Os alertas devem ser validados com contexto adicional. A presença ou ausência de um dispositivo na cache não prova comprometimento.</p></div></section>'
    )

    endpoint = data.get("endpoint_audit") or {}
    endpoint_rows = []
    for item in endpoint.get("listening", []):
        proc = item.get("process") or {}
        endpoint_rows.append(f'<tr><td>{esc(_value(item.get("protocol")))}</td><td>{esc(_value(item.get("local")))}</td><td>{esc(_value(item.get("peer")))}</td><td>{esc(_value(proc.get("name")))}</td><td>{esc(_value(proc.get("pid")))}</td></tr>')
    exposure_rows = []
    for item in endpoint.get("exposure_findings", []):
        process_label = " / ".join(str(v) for v in (item.get("process_name"), item.get("process_pid")) if v) or "não identificado"
        context = _value(item.get("severity_basis"), item.get("evidence"))
        recommendation = _value(item.get("recommendation"))
        exposure_rows.append(f'<tr><td><strong>{esc(_value(item.get("severity")))}</strong><br>{esc(_value(item.get("protocol")))}</td><td><code>{esc(_value(item.get("local")))}</code><br><span class="muted">{esc(_value(item.get("bind_scope")))}</span></td><td>{esc(_value(item.get("service")))}<br><span class="muted">{esc(process_label)}</span></td><td>{esc(context)}</td><td>{esc(recommendation)}</td></tr>')
    process_rows = []
    for item in endpoint.get("processes", [])[:30]:
        process_rows.append(f'<tr><td>{esc(_value(item.get("pid")))}</td><td>{esc(_value(item.get("user")))}</td><td>{esc(_value(item.get("name")))}</td><td>{esc(_value(item.get("command")))}</td></tr>')
    endpoint_section = ""
    if endpoint:
        clam = endpoint.get("clamav", {})
        endpoint_section = (f'<section class="section"><h2>Triagem local do computador</h2>'
            f'<div class="findings"><article class="finding info"><div class="finding-title">Processos recolhidos</div><p>{esc(_value(endpoint.get("process_count"), "0"))}</p></article>'
            f'<article class="finding info"><div class="finding-title">Sockets em escuta</div><p>{esc(_value(endpoint.get("listening_count"), "0"))}</p></article>'
            f'<article class="finding info"><div class="finding-title">Ligações estabelecidas (instantâneo)</div><p>{esc(_value(endpoint.get("established_count"), "0"))}</p><p>Estado da recolha: {esc(_value(endpoint.get("established_collection_status"), "não indicado"))}. Zero só representa ausência no instante observado quando a recolha foi concluída.</p></article>'
            f'<article class="finding {"ok" if clam.get("status") == "clean" else ("warning" if clam.get("status") in {"detections", "error", "unavailable"} or not clam.get("installed") else "info")}><div class="finding-title">ClamAV</div><p>{esc(_value(clam.get("message"), "Análise não executada."))}</p><p>Estado: {esc(_value(clam.get("status"), "não solicitado"))} · Deteções: {esc(_value(clam.get("detection_count"), "0"))}</p></article></div>'
            f'{table("Avaliação heurística de exposição", ["Prioridade / protocolo", "Endereço / âmbito", "Serviço / processo", "Contexto", "Recomendação"], exposure_rows, "Não foram identificados sockets candidatos pelas regras atuais; isto não garante ausência de exposição.")}'
            f'{table("Sockets em escuta", ["Protocolo", "Endereço local", "Peer", "Processo", "PID"], endpoint_rows)}' 
            f'{table(f"Processos (até 30 apresentados de {endpoint.get('process_count', len(endpoint.get('processes', [])))} recolhidos)", ["PID", "Utilizador", "Nome", "Comando"], process_rows)}'
            f'<p class="muted">Atribuição de processo: {esc(_value(endpoint.get("process_attributed_socket_count"), "0"))}/{esc(_value(endpoint.get("listening_count"), "0"))} sockets ({esc(_value(endpoint.get("process_attribution_coverage_percent"), "0"))}%). Estado da atribuição: {esc(_value(endpoint.get("process_attribution_status"), "não indicado"))}. Método: {esc(_value(endpoint.get("process_attribution_method"), "não indicado"))}. Estado da recolha: {esc(_value(endpoint.get("socket_collection_status"), "não indicado"))}.</p>'
            f'<div class="note"><strong>Limitações:</strong><ul>{"".join(f"<li>{esc(str(item))}</li>" for item in endpoint.get("limitations", []))}</ul></div></section>')

    discovery = data.get("network_discovery") or {}
    discovery_rows = [f'<tr><td>{esc(_value(host.get("ip")))}</td><td>{esc(_value(host.get("name")))}</td></tr>' for host in discovery.get("hosts", [])]
    discovery_section = ""
    if discovery:
        discovery_section = (f'<section class="section"><h2>Descoberta de rede solicitada</h2>'
            f'<div class="finding info"><div class="finding-title">Alvo: {esc(_value(discovery.get("target")))}</div>'
            f'<p>{esc(_value(discovery.get("message")))}</p><p>Hosts encontrados: {esc(_value(discovery.get("host_count"), "0"))}</p>'
            f'<p>{esc(_value(discovery.get("scope")))}</p></div>'
            f'{table("Hosts que responderam", ["Endereço IP", "Nome (se disponível)"], discovery_rows)}</section>')

    integration_data = data.get("integrations") or {}
    integration_labels = {
        "nmap": "Nmap", "clamav_scanner": "ClamAV (clamscan)", "clamav_updater": "FreshClam",
        "suricata": "Suricata", "wazuh_agent": "Agente Wazuh", "ss": "ss",
        "iproute2": "iproute2", "ufw": "UFW", "nftables": "nftables",
        "samba_server": "Samba (smbd)", "samba_netbios": "Samba (nmbd)",
    }
    integration_rows = [
        f'<tr><td>{esc(integration_labels.get(name, name))}</td><td>{"Disponível" if path else "Não encontrado"}</td><td>{esc(str(path or "—"))}</td></tr>'
        for name, path in (integration_data.get("binaries") or {}).items()
    ]
    service_rows = [
        f'<tr><td>{esc(name)}</td><td>{esc(state)}</td></tr>'
        for name, state in (integration_data.get("services") or {}).items()
    ]
    integrations_section = (
        f'<section class="section"><h2>Componentes e integrações</h2>'
        f'<p class="muted">{esc(str(integration_data.get("note") or "A presença não confirma configuração funcional."))}</p>'
        f'{table("Ferramentas detetadas", ["Componente", "Disponibilidade", "Executável"], integration_rows)}'
        f'{table("Estado dos serviços (systemd)", ["Serviço", "Estado observado"], service_rows)}'
        f'<p class="muted">Ficheiro Suricata EVE: {esc(str(integration_data.get("suricata_eve_file") or "não encontrado nos caminhos padrão"))}</p></section>'
    ) if integration_data else ""

    sections = [
        table("Interfaces de rede", ["Interface", "Estado", "MTU", "Endereços / prefixos"], interface_rows),
        table("Rotas de encaminhamento", ["Família", "Destino", "Gateway", "Interface", "Tabela"], route_rows),
        table("Configuração DNS", ["Campo", "Valor"], dns_rows),
        table("Testes de conectividade", ["Teste", "Estado", "Detalhes recolhidos", "Tempo (ms)"], check_rows),
        table("Vizinhos de rede em cache", ["Endereço IP", "Endereço MAC", "Estado", "Interface"], neighbor_rows, "A cache ARP/NDP está vazia ou não foi recolhida."),
    ]

    page = f'''<!doctype html>
<html lang="pt-PT"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogSentry — Relatório de rede</title><style>
:root{{--bg:#0a1020;--panel:#121d32;--panel2:#17243b;--text:#edf3ff;--muted:#aab9d2;--line:#2a3a56;--accent:#6ee7bd;--blue:#80b7ff;--warn:#f6c66a;--bad:#ff8585}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at top,#14213a 0,#0a1020 55%);color:var(--text);font:14px/1.55 system-ui,-apple-system,sans-serif}}main{{max-width:1440px;margin:auto;padding:28px 22px 44px}}header{{border-bottom:1px solid var(--line);padding:6px 0 20px}}h1{{font-size:clamp(25px,3vw,36px);margin:0;letter-spacing:-.6px}}h2{{font-size:20px;margin:0 0 13px}}h3{{font-size:15px}}p{{margin:8px 0}}.muted,.sub{{color:var(--muted)}}.sub{{font-size:13px}}.topline{{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}}.tag{{border:1px solid var(--line);border-radius:999px;padding:5px 10px;color:var(--accent);font-size:12px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0 30px}}.metric{{background:linear-gradient(140deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:14px;padding:16px;min-height:94px}}.metric span{{display:block;color:var(--muted);font-size:12px}}.metric strong{{display:block;font-size:26px;margin-top:7px;overflow-wrap:anywhere}}.section{{margin-top:30px}}.findings{{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:11px}}.finding{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:10px;padding:13px 15px}}.finding.ok{{border-left-color:var(--accent)}}.finding.warning{{border-left-color:var(--warn)}}.finding.info{{border-left-color:var(--blue)}}.finding-title{{font-weight:700}}.finding p{{color:var(--muted);font-size:13px;overflow-wrap:anywhere}}.panel{{overflow:auto;border:1px solid var(--line);border-radius:12px;background:rgba(18,29,50,.92)}}table{{border-collapse:collapse;width:100%;min-width:680px}}td,th{{padding:12px 13px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{background:#17243b;color:var(--muted);font-size:11px;letter-spacing:.5px;text-transform:uppercase;position:sticky;top:0}}tr:last-child td{{border-bottom:0}}tbody tr:hover{{background:rgba(128,183,255,.045)}}td{{overflow-wrap:anywhere}}.numeric{{font-variant-numeric:tabular-nums;white-space:nowrap}}.detail-label{{color:var(--muted);font-size:12px}}code{{color:#b8d6ff}}.pill{{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:700}}.pill.ok{{color:var(--accent);background:#143a34}}.pill.warning{{color:var(--warn);background:#3b3020}}.pill.info{{color:var(--blue);background:#1b2e4a}}.twocol{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}}.info-box{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px}}.info-box strong{{display:block;margin-bottom:6px}}.info-box p{{color:var(--muted);font-size:13px}}.note{{margin-top:30px;border:1px solid var(--line);border-left:4px solid var(--accent);background:var(--panel);border-radius:10px;padding:15px;color:var(--muted);font-size:12px}}.empty{{color:var(--muted)}}footer{{margin-top:22px;color:var(--muted);font-size:12px}}@media print{{@page{{size:A4 landscape;margin:9mm}}:root{{--bg:#fff;--panel:#fff;--panel2:#f3f5f8;--text:#111827;--muted:#4b5563;--line:#d1d5db}}body{{background:white;color:#111;font-size:9pt}}main{{max-width:none;padding:0}}header{{break-after:avoid}}.metrics{{grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin:10px 0 16px}}.metric{{min-height:0;padding:8px;border-radius:4px}}.metric strong{{font-size:16pt;margin-top:3px}}.section{{margin-top:16px}}h2{{font-size:14pt;margin-bottom:7px}}.findings{{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}}.finding,.info-box,.note{{padding:8px;border-radius:4px}}.panel{{overflow:visible;border-radius:4px}}table{{min-width:0;width:100%;table-layout:fixed;font-size:7pt}}td,th{{padding:4px 5px;overflow-wrap:anywhere;word-break:normal}}th{{position:static;white-space:normal}}tr{{break-inside:avoid}}.metric,.finding,.info-box,.note{{break-inside:avoid}}.section h2{{break-after:avoid}}footer{{font-size:8pt}}}}
</style></head><body><main>
<header><div class="topline"><h1>LogSentry Network Analyzer</h1><span class="tag">RELATÓRIO DE DIAGNÓSTICO</span></div>
<p class="sub">Versão {_value(data.get('version'))} · Gerado em {_value(data.get('generated_at'))}</p>
<div class="twocol"><div><p><span class="muted">Computador:</span> <strong>{esc(_value(data.get('hostname')))}</strong></p><p><span class="muted">Sistema operativo / plataforma:</span> {esc(_value(data.get('platform')))}</p></div><div><p><span class="muted">Estado dos testes:</span> {check_ok} OK · {check_fail} falhados · {check_na} não determinados</p><p><span class="muted">Estados da cache de vizinhos:</span> {esc(neighbor_summary)}</p></div></div></header>
<section class="metrics">{card_html}</section>
<section class="section"><h2>Resumo executivo</h2><div class="findings">{findings_html}</div></section>
{''.join(sections)}
{integrations_section}
{threat_section}
{endpoint_section}
{discovery_section}
<section class="section"><h2>Avisos e limitações da recolha</h2><div class="panel" style="padding:14px 18px"><ul>{warnings_html}</ul></div></section>
<section class="section"><h2>Como interpretar</h2><div class="twocol"><article class="info-box"><strong>Latência</strong><p>Os tempos são medições pontuais. Podem variar com Wi-Fi, congestionamento, distância ao destino, DNS e carga do sistema; não representam uma garantia de desempenho.</p></article><article class="info-box"><strong>ICMP e perda de pacotes</strong><p>Um destino pode bloquear ICMP e continuar acessível por TCP/HTTPS. Interprete ICMP em conjunto com os restantes testes.</p></article><article class="info-box"><strong>Rotas e interfaces</strong><p>As rotas refletem a tabela principal recolhida no momento do teste. VPNs, políticas de encaminhamento, contentores e permissões podem alterar a visão.</p></article><article class="info-box"><strong>Vizinhos em cache</strong><p>ARP/NDP mostra vizinhos recentemente conhecidos pelo sistema, não todos os dispositivos ligados à rede.</p></article></div></section>
<div class="note"><strong>Âmbito de segurança:</strong> o relatório usa diagnósticos locais e testes de conectividade limitados. Não captura pacotes nem executa testes de intrusão. A descoberta de hosts só é executada quando solicitada para uma rede privada dentro do limite definido; a auditoria local recolhe processos e sockets sem os classificar automaticamente como malware. O perfil de privacidade público pode ocultar identificadores, mas deve ser auditado antes de partilhar o ficheiro.</div>
<footer>Gerado localmente pelo LogSentry Network Analyzer. Os dados representam o momento da recolha.</footer>
</main></body></html>'''
    path.write_text(page, encoding="utf-8")
