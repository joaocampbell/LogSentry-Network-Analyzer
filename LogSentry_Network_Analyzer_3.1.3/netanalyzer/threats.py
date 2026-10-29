"""Read-only threat triage helpers for LogSentry 2.6.0.

This module does not claim to detect malware by itself. It summarizes existing
Suricata alerts and compares locally observed ARP/NDP neighbors to an optional
user-created baseline.
"""
import json
import shutil
from pathlib import Path

DEFAULT_SURICATA_PATHS = (Path('/var/log/suricata/eve.json'), Path('/var/log/suricata/eve.json.1'))


def component_presence():
    """Report whether common monitoring components appear installed; no services are changed."""
    return {
        'suricata_binary': shutil.which('suricata') is not None,
        'wazuh_agent_binary': any(shutil.which(name) for name in ('wazuh-agentd', 'ossec-control')),
    }


def read_suricata_alerts(path=None, max_bytes=5_000_000, max_events=5000):
    """Read existing Suricata EVE JSON alerts, bounded to avoid unbounded file reads."""
    candidates = [Path(path)] if path else list(DEFAULT_SURICATA_PATHS)
    chosen = next((p for p in candidates if p.is_file()), None)
    result = {'available': chosen is not None, 'source': str(chosen) if chosen else None,
              'events_read': 0, 'alerts': [], 'error': None}
    if chosen is None:
        result['message'] = 'Não foi encontrado um ficheiro EVE do Suricata nos caminhos consultados.'
        return result
    try:
        if chosen.stat().st_size > max_bytes:
            result['error'] = f'Ficheiro excede o limite de leitura de {max_bytes} bytes.'
            return result
        with chosen.open('r', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                if result['events_read'] >= max_events:
                    result['message'] = f'Limite de {max_events} eventos atingido.'
                    break
                if not line.strip():
                    continue
                result['events_read'] += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get('event_type') != 'alert' or not isinstance(event.get('alert'), dict):
                    continue
                alert = event['alert']
                result['alerts'].append({
                    'timestamp': event.get('timestamp'),
                    'signature': str(alert.get('signature') or 'Assinatura não indicada')[:300],
                    'category': str(alert.get('category') or 'Não categorizado')[:200],
                    'severity': alert.get('severity') if isinstance(alert.get('severity'), int) else None,
                    'src_ip': event.get('src_ip'), 'src_port': event.get('src_port'),
                    'dest_ip': event.get('dest_ip'), 'dest_port': event.get('dest_port'),
                    'proto': event.get('proto'), 'app_proto': event.get('app_proto'),
                })
        result['alert_count'] = len(result['alerts'])
        result['message'] = 'Alertas lidos do registo existente; não foi iniciada captura de tráfego.'
    except OSError as exc:
        result['error'] = str(exc)
    return result


def neighbor_inventory(network):
    """Create stable, deduplicated neighbor keys for baseline comparison."""
    entries = set()
    for item in (network or {}).get('neighbors', []):
        ip = item.get('ip')
        mac = item.get('mac')
        device = item.get('device')
        if ip or mac:
            entries.add((str(ip or ''), str(mac or '').lower(), str(device or '')))
    return sorted(entries)


def compare_neighbor_baseline(network, baseline_path=None, save_baseline=False):
    """Compare neighbor cache to a local JSON baseline; never scan the network."""
    current = neighbor_inventory(network)
    result = {'enabled': bool(baseline_path), 'baseline_path': str(baseline_path) if baseline_path else None,
              'current_count': len(current), 'new': [], 'missing': [], 'status': 'not_configured',
              'message': 'Baseline não configurada; a cache de vizinhos não é um inventário completo.'}
    if not baseline_path:
        return result
    path = Path(baseline_path)
    if not path.exists():
        if save_baseline:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'neighbors': current}, indent=2), encoding='utf-8')
            result.update(status='baseline_created', message='Baseline criada com a cache de vizinhos atual. Reveja o ficheiro antes de confiar nele.')
        else:
            result.update(status='baseline_missing', message='Baseline não existe. Use --save-baseline para criar uma baseline inicial.')
        return result
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        old = {tuple(str(v) for v in row) for row in data.get('neighbors', []) if isinstance(row, list) and len(row) == 3}
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        result.update(status='baseline_error', message=f'Não foi possível ler a baseline: {exc}')
        return result
    current_set = {tuple(row) for row in current}
    result['new'] = [{'ip': ip or None, 'mac': mac or None, 'device': dev or None} for ip, mac, dev in sorted(current_set-old)]
    result['missing'] = [{'ip': ip or None, 'mac': mac or None, 'device': dev or None} for ip, mac, dev in sorted(old-current_set)]
    result.update(status='compared', message='Diferenças na cache ARP/NDP face à baseline; podem resultar de alterações normais da rede e não provam atividade maliciosa.')
    return result


def build_threat_assessment(network, suricata_path=None, baseline_path=None, save_baseline=False):
    components = component_presence()
    suricata = read_suricata_alerts(suricata_path)
    baseline = compare_neighbor_baseline(network, baseline_path, save_baseline)
    if suricata.get('error'):
        status = 'review'
        headline = 'Não foi possível analisar completamente o registo Suricata.'
    elif suricata.get('alert_count', 0):
        status = 'review'
        headline = f"Foram encontrados {suricata['alert_count']} alertas Suricata para revisão."
    else:
        status = 'no_alerts' if suricata.get('available') else 'limited'
        headline = ('Não foram encontrados alertas nos eventos lidos; isto não prova ausência de ameaças.'
                    if suricata.get('available') else 'Visibilidade IDS indisponível: não foi encontrado um registo EVE do Suricata.')
    return {'status': status, 'headline': headline, 'components': components,
            'suricata': suricata, 'neighbor_baseline': baseline,
            'limitations': [
                'Esta análise é triagem baseada em registos e cache local; não é um antivírus nem garante deteção de malware.',
                'A cache ARP/NDP pode estar incompleta e muda normalmente; vizinhos novos ou ausentes não são prova de comprometimento.',
                'A análise de alertas depende de o Suricata estar instalado, configurado, a observar tráfego relevante e com regras atualizadas.',
            ]}
