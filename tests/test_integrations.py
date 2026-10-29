import unittest
from unittest.mock import patch
from netanalyzer.integrations import discover_integrations

class IntegrationDiscoveryTests(unittest.TestCase):
    @patch('netanalyzer.integrations._service_states', return_value={'suricata':'inactive'})
    @patch('netanalyzer.integrations.shutil.which', side_effect=lambda name: '/usr/bin/' + name if name in {'ss','ip'} else None)
    def test_detects_available_and_missing_binaries(self, _which, _services):
        result = discover_integrations()
        self.assertEqual(result['binaries']['ss'], '/usr/bin/ss')
        self.assertIsNone(result['binaries']['suricata'])
        self.assertEqual(result['services']['suricata'], 'inactive')
        self.assertIn('não confirma', result['note'])

    @patch('netanalyzer.integrations._service_states', return_value={})
    @patch('netanalyzer.integrations.shutil.which', return_value=None)
    def test_missing_optional_tools_are_nonfatal(self, _which, _services):
        result = discover_integrations()
        self.assertEqual(result['available_count'], 0)
        self.assertIsNone(result['suricata_eve_file'])

if __name__ == '__main__': unittest.main()
