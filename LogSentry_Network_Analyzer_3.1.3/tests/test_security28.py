import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from netanalyzer.security import _address_port, _assess_exposure, _bind_scope, _process_from_ss, _parse_ss_line, endpoint_audit

class ExposureTests(unittest.TestCase):
    def test_ipv4_and_ipv6_endpoint_parsing(self):
        self.assertEqual(_address_port('0.0.0.0:445'), ('0.0.0.0', 445))
        self.assertEqual(_address_port('[::]:3306'), ('::', 3306))
        self.assertEqual(_address_port('127.0.0.1:631'), ('127.0.0.1', 631))

    def test_loopback_not_reported_as_network_exposure(self):
        findings = _assess_exposure([{'local':'127.0.0.1:3306','protocol':'tcp'}])
        self.assertEqual(findings, [])

    def test_wildcard_smb_is_medium_heuristic_not_confirmed_attack(self):
        findings = _assess_exposure([{'local':'0.0.0.0:445','protocol':'tcp'}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'potential_exposure')
        self.assertEqual(findings[0]['severity'], 'medium')
        self.assertEqual(findings[0]['bind_scope'], 'all_interfaces')
        self.assertIn('firewall', findings[0]['evidence'])

    def test_bind_scope_distinguishes_loopback_and_network(self):
        self.assertEqual(_bind_scope('127.0.0.1'), 'loopback_only')
        self.assertEqual(_bind_scope('::1'), 'loopback_only')
        self.assertEqual(_bind_scope('0.0.0.0'), 'all_interfaces')
        self.assertEqual(_bind_scope('192.168.1.80'), 'specific_non_loopback')

    def test_parse_established_socket_with_six_fields(self):
        row = _parse_ss_line('tcp ESTAB 0 0 192.168.1.80:443 93.184.216.34:51514', 'established')
        self.assertEqual(row['protocol'], 'tcp')
        self.assertEqual(row['state'], 'ESTAB')
        self.assertEqual(row['local'], '192.168.1.80:443')
        self.assertEqual(row['peer'], '93.184.216.34:51514')
        self.assertIsNone(row['process'])

    def test_parse_established_socket_with_process_metadata(self):
        row = _parse_ss_line('tcp ESTAB 0 0 127.0.0.1:3306 127.0.0.1:52144 users:(("mysqld",pid=1430,fd=19))', 'established')
        self.assertEqual(row['process'], {'name': 'mysqld', 'pid': '1430'})

    def test_parse_listening_socket_and_reject_short_rows(self):
        row = _parse_ss_line('tcp LISTEN 0 128 0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=1234,fd=7))', 'listening')
        self.assertEqual(row['local'], '0.0.0.0:445')
        self.assertIsNone(_parse_ss_line('tcp ESTAB 0 0 127.0.0.1:1 127.0.0.1:2', 'listening'))
        self.assertIsNone(_parse_ss_line('tcp ESTAB 0 0 127.0.0.1:1', 'established'))

    def test_process_metadata_parser(self):
        line = 'tcp LISTEN 0 128 0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=1234,fd=7))'
        self.assertEqual(_process_from_ss(line), {'name': 'smbd', 'pid': '1234'})
        self.assertIsNone(_process_from_ss('tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*'))

    def test_non_sensitive_wildcard_port_is_low_severity(self):
        findings = _assess_exposure([{'local':'[::]:51820','protocol':'udp'}])
        self.assertEqual(findings[0]['severity'], 'low')
        self.assertEqual(findings[0]['confidence'], 'heuristic')
        self.assertIn('não confirma vulnerabilidade', findings[0]['severity_basis'])

    def test_process_attribution_fields_are_present(self):
        findings = _assess_exposure([{'local':'0.0.0.0:445','protocol':'tcp',
                                      'process': {'name': 'smbd', 'pid': '1234'}}])
        self.assertEqual(findings[0]['process_name'], 'smbd')
        self.assertEqual(findings[0]['process_pid'], '1234')
        self.assertIn('antes de alterar', findings[0]['recommendation'])

    def test_clamav_path_must_exist(self):
        with self.assertRaises(ValueError):
            endpoint_audit(clamav_path='/definitely/not/a/real/path/logsentry')

    def test_clamav_not_installed_is_reported_without_scan(self):
        with patch('netanalyzer.security.shutil.which', side_effect=lambda x: '/usr/bin/ss' if x == 'ss' else None):
            with tempfile.TemporaryDirectory() as d:
                result = endpoint_audit(clamav_path=d)
        self.assertEqual(result['clamav']['status'], 'unavailable')
        self.assertFalse(result['clamav']['scan_performed'])

if __name__ == '__main__':
    unittest.main()
