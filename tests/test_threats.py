import json
import tempfile
import unittest
from pathlib import Path
from netanalyzer.threats import compare_neighbor_baseline, read_suricata_alerts, neighbor_inventory, build_threat_assessment
from netanalyzer.report import write_html


class ThreatTriageTests(unittest.TestCase):
    def test_reads_suricata_alerts_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'eve.json'
            path.write_text('\n'.join([
                json.dumps({'event_type': 'flow', 'src_ip': '10.0.0.2'}),
                json.dumps({'event_type': 'alert', 'src_ip': '10.0.0.2', 'dest_ip': '10.0.0.1', 'alert': {'signature': 'Test signature', 'severity': 2}}),
            ]), encoding='utf-8')
            result = read_suricata_alerts(path)
            self.assertTrue(result['available'])
            self.assertEqual(result['alert_count'], 1)
            self.assertEqual(result['alerts'][0]['signature'], 'Test signature')

    def test_invalid_eve_json_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'eve.json'
            path.write_text('{bad json}\n', encoding='utf-8')
            result = read_suricata_alerts(path)
            self.assertEqual(result['alert_count'], 0)

    def test_baseline_creation_and_change_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'baseline.json'
            network = {'neighbors': [{'ip': '192.168.1.2', 'mac': 'aa:bb:cc:dd:ee:ff', 'device': 'wlan0'}]}
            created = compare_neighbor_baseline(network, path, True)
            self.assertEqual(created['status'], 'baseline_created')
            changed = {'neighbors': [{'ip': '192.168.1.3', 'mac': 'aa:bb:cc:dd:ee:11', 'device': 'wlan0'}]}
            result = compare_neighbor_baseline(changed, path)
            self.assertEqual(result['status'], 'compared')
            self.assertEqual(len(result['new']), 1)
            self.assertEqual(len(result['missing']), 1)

    def test_no_baseline_does_not_claim_threat(self):
        result = compare_neighbor_baseline({'neighbors': []})
        self.assertEqual(result['status'], 'not_configured')
        self.assertEqual(result['new'], [])

    def test_html_contains_threat_triage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.html'
            data = {'version': '2.6.0', 'hostname': 'host', 'platform': 'Linux', 'generated_at': 'now',
                    'network': {'interfaces': [], 'routes': [], 'neighbors': [], 'dns': {}}, 'checks': {}, 'summary': [],
                    'threat_assessment': build_threat_assessment({'neighbors': []})}
            write_html(data, path)
            html = path.read_text(encoding='utf-8')
            self.assertIn('Triagem de ameaças', html)
            self.assertIn('Alertas Suricata', html)
            self.assertIn('não é um antivírus', html)


if __name__ == '__main__':
    unittest.main()
