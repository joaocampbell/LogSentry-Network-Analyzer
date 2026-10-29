import unittest
from unittest.mock import patch
from types import SimpleNamespace
from netanalyzer.security import _psutil_snapshot, _enrich_processes_from_ss, endpoint_audit
from netanalyzer.diagnostics import collect_windows

class FakeProcess:
    def __init__(self, pid): self.pid = pid
    def name(self): return "demo-service"

class FakePsutil:
    CONN_LISTEN = "LISTEN"
    CONN_ESTABLISHED = "ESTABLISHED"
    NoSuchProcess = type("NoSuchProcess", (Exception,), {})
    AccessDenied = type("AccessDenied", (Exception,), {})
    ZombieProcess = type("ZombieProcess", (Exception,), {})
    def process_iter(self, attrs, ad_value=None):
        return [SimpleNamespace(info={"pid": 42, "username": "tester", "name": "demo-service", "cmdline": ["demo-service", "--safe"]})]
    def net_connections(self, kind="inet"):
        return [
            SimpleNamespace(type=1, laddr=SimpleNamespace(ip="0.0.0.0", port=8080), raddr=(), status="LISTEN", pid=42),
            SimpleNamespace(type=1, laddr=SimpleNamespace(ip="127.0.0.1", port=3306), raddr=SimpleNamespace(ip="127.0.0.1", port=50000), status="ESTABLISHED", pid=42),
        ]
    def Process(self, pid): return FakeProcess(pid)

class CrossPlatformSocketTests(unittest.TestCase):
    def test_psutil_snapshot_attributes_process_and_counts_established(self):
        import sys
        fake = FakePsutil()
        with patch.dict(sys.modules, {"psutil": fake}):
            result = {"processes": [], "listening": [], "established": [], "warnings": []}
            self.assertTrue(_psutil_snapshot(result))
        self.assertEqual(len(result["processes"]), 1)
        self.assertEqual(result["listening"][0]["process"], {"name": "demo-service", "pid": "42"})
        self.assertEqual(len(result["established"]), 1)

    def test_endpoint_audit_reports_explicit_collection_state(self):
        result = endpoint_audit()
        self.assertIn(result["established_collection_status"], {"collected_nonzero", "collected_zero_at_snapshot", "partial_or_unavailable", "unavailable"})
        self.assertIn("process_attribution_coverage_percent", result)
        if result["socket_collection_status"] == "collected":
            self.assertNotEqual(result["established_collection_status"], "unavailable")

    def test_ss_enrichment_adds_process_metadata_by_protocol_and_port(self):
        result = {"listening": [{"protocol": "tcp", "local": "0.0.0.0:445", "process": None}], "process_attribution_method": "psutil"}
        with patch('netanalyzer.security.shutil.which', return_value='/usr/bin/ss'), patch('netanalyzer.security._read_ss_lines', return_value=(['tcp LISTEN 0 128 0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=1234,fd=7))'], False, None)):
            with patch('platform.system', return_value='Linux'):
                changed = _enrich_processes_from_ss(result)
        self.assertTrue(changed)
        self.assertEqual(result['listening'][0]['process'], {'name':'smbd','pid':'1234'})


    def test_ss_enrichment_does_not_match_different_local_addresses_on_same_port(self):
        result = {"listening": [{"protocol": "tcp", "local": "192.168.1.80:445", "process": None}], "process_attribution_method": "psutil", "warnings": []}
        lines = [
            'tcp LISTEN 0 128 0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=1234,fd=7))',
            'tcp LISTEN 0 128 127.0.0.1:445 0.0.0.0:* users:(("test-service",pid=5678,fd=7))',
        ]
        with patch('netanalyzer.security.shutil.which', return_value='/usr/bin/ss'), patch('netanalyzer.security._read_ss_lines', return_value=(lines, False, None)):
            with patch('platform.system', return_value='Linux'):
                changed = _enrich_processes_from_ss(result)
        self.assertFalse(changed)
        self.assertIsNone(result['listening'][0]['process'])

    def test_read_ss_lines_prefers_privileged_output_when_it_has_more_processes(self):
        from netanalyzer.security import _read_ss_lines
        normal = SimpleNamespace(returncode=0, stdout='tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:*', stderr='')
        privileged = SimpleNamespace(returncode=0, stdout='tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:(("web",pid=123,fd=3))', stderr='')
        with patch('netanalyzer.security._run', side_effect=[{"returncode": 0, "stdout": normal.stdout, "stderr": "", "error": None}, {"returncode": 0, "stdout": privileged.stdout, "stderr": "", "error": None}]), patch('netanalyzer.security.shutil.which', return_value='/usr/bin/sudo'):
            lines, elevated, error = _read_ss_lines('/usr/bin/ss', ['-H', '-lntup'])
        self.assertIsNone(error)
        self.assertTrue(elevated)
        self.assertIn('pid=123', lines[0])

    def test_endpoint_attribution_status_is_explicit(self):
        result = endpoint_audit()
        self.assertIn(result['process_attribution_status'], {'complete', 'partial', 'unavailable_or_permission_limited', 'no_listening_sockets_or_unavailable'})

    def test_windows_collector_normalizes_single_dns_server(self):
        import netanalyzer.diagnostics as diagnostics
        fake_addr = {"Ethernet": [SimpleNamespace(family=diagnostics.socket.AF_INET, address="192.168.1.10")]}
        fake_stats = {"Ethernet": SimpleNamespace(isup=True, mtu=1500)}
        psutil_fake = SimpleNamespace(net_if_addrs=lambda: fake_addr, net_if_stats=lambda: fake_stats)
        responses = [
            SimpleNamespace(returncode=0, stdout='{"AddressFamily":2,"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","InterfaceAlias":"Ethernet"}', stderr=''),
            SimpleNamespace(returncode=0, stdout='{"IPAddress":"192.168.1.1","LinkLayerAddress":"00-11-22-33-44-55","State":"Reachable","InterfaceAlias":"Ethernet"}', stderr=''),
            SimpleNamespace(returncode=0, stdout='{"InterfaceAlias":"Ethernet","AddressFamily":2,"ServerAddresses":"192.168.1.1"}', stderr=''),
        ]
        with patch.dict('sys.modules', {'psutil': psutil_fake}), patch('netanalyzer.diagnostics.shutil.which', return_value='powershell'), patch('netanalyzer.diagnostics.subprocess.run', side_effect=responses):
            result = collect_windows()
        self.assertEqual(result['dns']['nameservers'], ['192.168.1.1'])
        self.assertEqual(result['routes'][0]['gateway'], '192.168.1.1')
        self.assertEqual(result['neighbors'][0]['ip'], '192.168.1.1')

if __name__ == "__main__": unittest.main()
