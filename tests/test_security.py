import unittest
from unittest.mock import patch
from netanalyzer.security import discover_private_network, endpoint_audit

class SecurityTests(unittest.TestCase):
    def test_discovery_rejects_public_network(self):
        with self.assertRaises(ValueError):
            discover_private_network('8.8.8.0/24')

    def test_discovery_rejects_oversized_private_network(self):
        with self.assertRaises(ValueError):
            discover_private_network('192.168.0.0/16')

    def test_discovery_rejects_invalid_cidr(self):
        with self.assertRaises(ValueError):
            discover_private_network('not-a-network')

    def test_discovery_without_nmap_is_reported(self):
        with patch('netanalyzer.security.shutil.which', return_value=None):
            result = discover_private_network('192.168.1.0/24')
        self.assertFalse(result['available'])
        self.assertEqual(result['hosts'], [])

    def test_endpoint_audit_does_not_claim_scan(self):
        result = endpoint_audit()
        self.assertIn('clamav', result)
        self.assertFalse(result['clamav']['scan_performed'])
        self.assertIn('limitations', result)

if __name__ == '__main__':
    unittest.main()
