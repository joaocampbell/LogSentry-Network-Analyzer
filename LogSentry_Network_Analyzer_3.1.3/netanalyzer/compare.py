"""Offline comparison of LogSentry reports, with metric assessment and HTML export."""
import argparse
import html
import json
import math
import sys
from pathlib import Path

METRICS = ("elapsed_ms", "average_latency_ms", "packet_loss_percent", "http_status")
LATENCY_METRICS = {"elapsed_ms", "average_latency_ms"}


def load_report(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Não foi possível ler {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("checks"), dict):
        raise ValueError(f"{path}: formato de relatório inválido (campo 'checks' ausente).")
    for name, check in data["checks"].items():
        if not isinstance(name, str) or not isinstance(check, dict):
            raise ValueError(f"{path}: verificação inválida em 'checks'.")
    return data


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _assess_metrics(metrics, threshold_percent):
    assessments = []
    for key, item in metrics.items():
        before, after = item["before"], item["after"]
        if key in LATENCY_METRICS and item["percent_change"] is not None:
            pct = item["percent_change"]
            if pct >= threshold_percent:
                assessments.append("regression")
            elif pct <= -threshold_percent:
                assessments.append("improvement")
        elif key == "packet_loss_percent":
            if after > before:
                assessments.append("regression")
            elif after < before:
                assessments.append("improvement")
    if "regression" in assessments:
        return "regression"
    if "improvement" in assessments:
        return "improvement"
    return "within_threshold"


def compare_reports(before, after, latency_threshold_percent=25.0):
    """Compare check states and numeric metrics. Higher latency/loss is worse."""
    if not _number(latency_threshold_percent) or latency_threshold_percent < 0:
        raise ValueError("O limiar de latência deve ser um número finito não negativo.")
    left, right = before["checks"], after["checks"]
    rows = []
    for name in sorted(set(left) | set(right)):
        a, b = left.get(name), right.get(name)
        if not isinstance(a, dict) or not isinstance(b, dict):
            rows.append({"check": name, "change": "added" if a is None else "removed" if b is None else "invalid", "before_ok": a.get("ok") if isinstance(a, dict) else None, "after_ok": b.get("ok") if isinstance(b, dict) else None, "metrics": {}, "metric_assessment": "not_comparable"})
            continue
        metrics = {}
        for key in METRICS:
            av, bv = a.get(key), b.get(key)
            if _number(av) and _number(bv):
                delta = round(bv - av, 3)
                percent = round((delta / av) * 100, 2) if av != 0 else None
                metrics[key] = {"before": av, "after": bv, "delta": delta, "percent_change": percent}
        old_ok, new_ok = a.get("ok"), b.get("ok")
        if old_ok is False and new_ok is True:
            change = "recovered"
        elif old_ok is True and new_ok is False:
            change = "regressed"
        elif old_ok != new_ok:
            change = "status_changed"
        else:
            change = "unchanged"
        rows.append({"check": name, "change": change, "before_ok": old_ok, "after_ok": new_ok, "metrics": metrics, "metric_assessment": _assess_metrics(metrics, latency_threshold_percent)})
    counts = {key: sum(1 for row in rows if row["metric_assessment"] == key) for key in ("regression", "improvement", "within_threshold", "not_comparable")}
    return {"product": "LogSentry Report Comparison", "version": "2.5.0", "before_version": before.get("version"), "after_version": after.get("version"), "checks_compared": len(rows), "latency_threshold_percent": latency_threshold_percent, "metric_summary": counts, "results": rows}


def write_html_comparison(result, path):
    esc = html.escape
    labels = {"regression": "POTENCIAL REGRESSÃO", "improvement": "MELHORIA", "within_threshold": "DENTRO DO LIMIAR", "not_comparable": "NÃO COMPARÁVEL"}
    rows = []
    for item in result["results"]:
        metrics = []
        for key, metric in item["metrics"].items():
            pct = "N/D" if metric["percent_change"] is None else f"{metric['percent_change']:+.2f}%"
            metrics.append(f"{esc(key)}: {metric['before']} → {metric['after']} (Δ {metric['delta']:+.3f}; {pct})")
        rows.append("<tr><td>" + esc(item["check"]) + "</td><td>" + esc(item["change"]) + "</td><td>" + esc(labels.get(item["metric_assessment"], item["metric_assessment"])) + "</td><td>" + "<br>".join(metrics or ["—"]) + "</td></tr>")
    counts = result["metric_summary"]
    summary = " · ".join(f"{labels[k]}: {v}" for k, v in counts.items())
    document = """<!doctype html><html lang="pt-PT"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Comparação LogSentry</title><style>
body{margin:0;background:#0b1020;color:#edf2ff;font:15px/1.5 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:28px 18px}h1{font-size:26px}.muted{color:#aab7d0}.panel{overflow:auto;border:1px solid #2a3854;border-radius:12px;background:#141d31}table{border-collapse:collapse;width:100%;min-width:700px}td,th{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid #2a3854}th{color:#aab7d0;font-size:12px;text-transform:uppercase}.note{margin-top:18px;padding:14px;border-left:3px solid #65d6ad;background:#141d31;color:#aab7d0}
</style></head><body><main><h1>LogSentry — Comparação de relatórios</h1><p class="muted">Versão do comparador: """ + esc(result["version"]) + """ · Relatório anterior: """ + esc(str(result.get("before_version") or "N/D")) + """ · Relatório atual: """ + esc(str(result.get("after_version") or "N/D")) + """</p><p>""" + esc(summary) + """</p><div class="panel"><table><thead><tr><th>Verificação</th><th>Estado funcional</th><th>Avaliação das métricas</th><th>Diferenças</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table></div><div class="note">Uma variação de latência é um indicador, não prova isolada de falha. O limiar aplicado é de """ + esc(str(result["latency_threshold_percent"])) + """%. As medições dependem da rede, destino e momento da execução.</div></main></body></html>"""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compara dois relatórios JSON do LogSentry, incluindo alterações nas métricas.")
    parser.add_argument("before", help="Relatório anterior (JSON)")
    parser.add_argument("after", help="Relatório mais recente (JSON)")
    parser.add_argument("--json-out", help="Guardar comparação num ficheiro JSON")
    parser.add_argument("--html-out", help="Gerar relatório HTML da comparação")
    parser.add_argument("--latency-threshold-percent", type=float, default=25.0, help="Variação percentual de latência considerada relevante (predefinição: 25%%)")
    args = parser.parse_args(argv)
    try:
        result = compare_reports(load_report(args.before), load_report(args.after), args.latency_threshold_percent)
        print(f"Comparação LogSentry: {result['checks_compared']} verificações")
        print(f"Versões: {result.get('before_version') or 'N/D'} -> {result.get('after_version') or 'N/D'}")
        print("Resumo das métricas: " + ", ".join(f"{key}={value}" for key, value in result["metric_summary"].items()))
        labels = {"recovered": "RECUPERADO", "regressed": "DEGRADADO", "unchanged": "SEM ALTERAÇÃO", "added": "ADICIONADO", "removed": "REMOVIDO", "status_changed": "ESTADO ALTERADO", "invalid": "INVÁLIDO"}
        assessments = {"regression": "POTENCIAL REGRESSÃO", "improvement": "MELHORIA", "within_threshold": "DENTRO DO LIMIAR", "not_comparable": "NÃO COMPARÁVEL"}
        for row in result["results"]:
            print(f"- {row['check']}: {labels.get(row['change'], row['change'])} | {assessments.get(row['metric_assessment'], row['metric_assessment'])}")
            for key, metric in row["metrics"].items():
                pct = f", {metric['percent_change']}%" if metric["percent_change"] is not None else ""
                print(f"    {key}: {metric['before']} -> {metric['after']} (Δ {metric['delta']}{pct})")
        if args.json_out:
            out = Path(args.json_out); out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"JSON: {out}")
        if args.html_out:
            write_html_comparison(result, args.html_out)
            print(f"HTML: {Path(args.html_out)}")
        return 0
    except (ValueError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
