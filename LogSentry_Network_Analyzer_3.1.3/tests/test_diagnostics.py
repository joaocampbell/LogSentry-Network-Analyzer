import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from netanalyzer.diagnostics import (build_summary, classify_ipv6_check, dns_test, effective_route,
    has_ipv6_default_route, tcp_test, tls_test, https_test, command)
from netanalyzer.report import write_html, write_json
from netanalyzer.privacy import anonymize_report
from netanalyzer.compare import compare_reports, write_html_comparison
from netanalyzer.privacy_audit import scan_text

class IPv6Tests(unittest.TestCase):
    def test_missing_default_route(self):
        self.assertFalse(has_ipv6_default_route({"routes":[{"family":"IPv6","destination":"fe80::/64"}]}))
    def test_default_route_detected(self):
        self.assertTrue(has_ipv6_default_route({"routes":[{"family":"IPv6","destination":"::/0"}]}))
    def test_effective_route_failure_classified(self):
        with patch("netanalyzer.diagnostics.socket.getaddrinfo", return_value=[(socket.AF_INET6,socket.SOCK_STREAM,6,"",("2001:db8::1",443,0,0))]), \
             patch("netanalyzer.diagnostics.effective_route", return_value={"ok":False,"error":"Network is unreachable"}):
            result=classify_ipv6_check({"target":"test.invalid","ok":False,"error":"unreachable"},{"routes":[]})
        self.assertEqual(result["diagnosis"],"no_effective_ipv6_route")
    def test_ipv6_connected(self):
        result=classify_ipv6_check({"target":"test.invalid","ok":True},{"routes":[]})
        self.assertEqual(result["diagnosis"],"connected")

class ConnectivityTests(unittest.TestCase):
    def test_dns_success(self):
        fake=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("192.0.2.10",0))]
        with patch("netanalyzer.diagnostics.socket.getaddrinfo",return_value=fake): result=dns_test("test.invalid")
        self.assertTrue(result["ok"]); self.assertEqual(result["addresses"],["192.0.2.10"])
    def test_dns_failure(self):
        with patch("netanalyzer.diagnostics.socket.getaddrinfo",side_effect=socket.gaierror("lookup failed")): result=dns_test("test.invalid")
        self.assertFalse(result["ok"]); self.assertIn("lookup failed",result["error"])
    def test_tcp_failure(self):
        with patch("netanalyzer.diagnostics.socket.getaddrinfo",side_effect=OSError("unreachable")): result=tcp_test("test.invalid",family=socket.AF_INET6)
        self.assertFalse(result["ok"]); self.assertIn("unreachable",result["error"])
    def test_tls_success(self):
        secure=MagicMock(); secure.version.return_value="TLSv1.3"; secure.cipher.return_value=("TLS_AES_128_GCM_SHA256","TLSv1.3",128)
        context=MagicMock(); context.wrap_socket.return_value.__enter__.return_value=secure
        raw=MagicMock()
        with patch("netanalyzer.diagnostics.ssl.create_default_context",return_value=context), patch("netanalyzer.diagnostics.socket.getaddrinfo",return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("192.0.2.1",443))]), patch("netanalyzer.diagnostics.socket.socket",return_value=raw):
            result=tls_test("test.invalid")
        self.assertTrue(result["ok"]); self.assertTrue(result["verified"]); self.assertEqual(result["tls_version"],"TLSv1.3")
    def test_https_http_status(self):
        conn=MagicMock(); conn.getresponse.return_value.status=204
        with patch("netanalyzer.diagnostics.http.client.HTTPSConnection",return_value=conn): result=https_test("test.invalid")
        self.assertTrue(result["ok"]); self.assertEqual(result["http_status"],204); conn.close.assert_called_once()
    def test_https_http_failure(self):
        conn=MagicMock(); conn.request.side_effect=OSError("timeout")
        with patch("netanalyzer.diagnostics.http.client.HTTPSConnection",return_value=conn): result=https_test("test.invalid")
        self.assertFalse(result["ok"]); self.assertIn("timeout",result["error"])
    def test_command_timeout_reported(self):
        with patch("netanalyzer.diagnostics.subprocess.run",side_effect=__import__("subprocess").TimeoutExpired(["x"],1)):
            result=command(["x"],timeout=1)
        self.assertTrue(result["timed_out"]); self.assertEqual(result["stderr"],"timeout")
    def test_icmp_loss_not_internet_failure(self):
        network={"neighbors":[],"routes":[]}
        checks={"dns":{"ok":True},"tcp_ipv4":{"ok":True,"target":"example.com","port":443},"tls_ipv4":{"ok":True,"tls_version":"TLSv1.3"},"https_http":{"ok":True,"http_status":200},"tcp_ipv6":{"ok":False,"message":"no route"},"icmp_public_ipv4":{"ok":False,"packet_loss_percent":100}}
        result=build_summary(network,checks); finding=next(x for x in result if x["title"]=="ICMP público")
        self.assertEqual(finding["status"],"info"); self.assertIn("não prova",finding["detail"])

class PrivacyTests(unittest.TestCase):
    def test_anonymize_ip_mac_hostname_without_mutating_source(self):
        source={"hostname":"workstation","platform":"Linux private","network":{"interfaces":[{"name":"wlan0","addresses":[{"address":"192.168.1.22"}]}],"neighbors":[{"ip":"192.168.1.1","mac":"aa:bb:cc:dd:ee:ff"}]},"checks":{"test":{"target":"1.1.1.1","error":"connect 2001:db8::1 failed"}}}
        result=anonymize_report(source); raw=json.dumps(result)
        for secret in ("workstation","192.168.1.22","192.168.1.1","aa:bb:cc:dd:ee:ff","2001:db8::1"): self.assertNotIn(secret,raw)
        self.assertEqual(source["hostname"],"workstation")
    def test_public_profile_minimizes_metadata(self):
        source={"hostname":"host","platform":"Linux 7.0","generated_at":"2026-10-28T12:00:00+00:00","network":{"interfaces":[{"name":"wlp1s0"}],"routes":[{"device":"wlp1s0"}],"neighbors":[]},"checks":{"ping":{"output":"private command output"}}}
        result=anonymize_report(source,public_profile=True); raw=json.dumps(result)
        self.assertEqual(result["platform"],"[PLATFORM REDACTED]"); self.assertNotIn("wlp1s0",raw); self.assertNotIn("private command output",raw)
    def test_anonymize_keeps_normal_text(self):
        self.assertIn("example.com",anonymize_report({"message":"DNS succeeded for example.com"})["message"])
    def test_public_profile_redacts_loopback_address_field(self):
        result = anonymize_report({"network": {"interfaces": [{"addresses": [{"address": "::1"}]}]}}, public_profile=True)
        self.assertEqual(result["network"]["interfaces"][0]["addresses"][0]["address"], "[IP REDACTED]")
    def test_public_profile_redacts_ipv6_route_destination(self):
        result = anonymize_report({"network": {"routes": [{"family": "IPv6", "destination": "fe80::/64"}]}}, public_profile=True)
        self.assertEqual(result["network"]["routes"][0]["destination"], "[IP REDACTED]/64")
    def test_privacy_scanner_finds_ipv4_ipv6_and_mac(self):
        found = scan_text("ip=192.168.1.10 v6=2001:db8::1 mac=aa:bb:cc:dd:ee:ff")
        kinds = {x["type"] for x in found}
        self.assertIn("ip_address", kinds); self.assertIn("mac_address", kinds)
        self.assertTrue(any(item["value"] == "::1" for item in scan_text("loopback=::1")))

class ComparisonTests(unittest.TestCase):
    def test_report_comparison_detects_regression_and_metric_delta(self):
        before = {"version":"2.3.0", "checks":{"dns":{"ok":True,"elapsed_ms":5},"tcp":{"ok":True,"elapsed_ms":20}}}
        after = {"version":"2.4.0", "checks":{"dns":{"ok":True,"elapsed_ms":8},"tcp":{"ok":False,"elapsed_ms":25},"tls":{"ok":True}}}
        result = compare_reports(before, after)
        rows = {row["check"]: row for row in result["results"]}
        self.assertEqual(rows["tcp"]["change"], "regressed")
        self.assertEqual(rows["dns"]["metrics"]["elapsed_ms"]["delta"], 3)
        self.assertEqual(rows["tls"]["change"], "added")
    def test_report_comparison_detects_recovery(self):
        result = compare_reports({"checks":{"dns":{"ok":False}}}, {"checks":{"dns":{"ok":True}}})
        self.assertEqual(result["results"][0]["change"], "recovered")

    def test_latency_metric_assessment_uses_threshold(self):
        before = {"version":"2.4.0", "checks":{"dns":{"ok":True,"elapsed_ms":10}, "https":{"ok":True,"elapsed_ms":100}}}
        after = {"version":"2.5.0", "checks":{"dns":{"ok":True,"elapsed_ms":14}, "https":{"ok":True,"elapsed_ms":60}}}
        result = compare_reports(before, after, latency_threshold_percent=25)
        rows = {row["check"]: row for row in result["results"]}
        self.assertEqual(rows["dns"]["metric_assessment"], "regression")
        self.assertEqual(rows["https"]["metric_assessment"], "improvement")
        self.assertEqual(result["version"], "2.5.0")

    def test_comparison_ignores_boolean_and_nonfinite_metrics(self):
        result = compare_reports({"checks":{"x":{"ok":True,"elapsed_ms":True}}}, {"checks":{"x":{"ok":True,"elapsed_ms":float("inf")}}})
        self.assertNotIn("elapsed_ms", result["results"][0]["metrics"])
        self.assertEqual(result["results"][0]["metric_assessment"], "within_threshold")

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            compare_reports({"checks":{}}, {"checks":{}}, latency_threshold_percent=-1)

    def test_html_comparison_report(self):
        result = compare_reports({"checks":{"<script>":{"ok":True,"elapsed_ms":10}}}, {"checks":{"<script>":{"ok":True,"elapsed_ms":20}}})
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "comparison.html"
            write_html_comparison(result, path)
            content = path.read_text(encoding="utf-8")
            self.assertIn("lang=\"pt-PT\"", content)
            self.assertNotIn("<script>", content)
            self.assertIn("POTENCIAL REGRESSÃO", content)

class ReportTests(unittest.TestCase):
    def test_html_and_json_reports(self):
        data={"product":"LogSentry Network Analyzer","version":"2.3.0","generated_at":"now","hostname":"test-host","platform":"Linux","network":{"interfaces":[],"routes":[],"neighbors":[]},"checks":{"tls_ipv4":{"ok":True,"elapsed_ms":1}},"summary":[{"status":"ok","title":"TLS","detail":"passed"}]}
        with tempfile.TemporaryDirectory() as d:
            html=Path(d)/"report.html"; js=Path(d)/"report.json"; write_html(data,html); write_json(data,js)
            self.assertIn('lang="pt-PT"',html.read_text()); self.assertEqual(json.loads(js.read_text())["version"],"2.3.0")

if __name__ == "__main__": unittest.main(verbosity=2)
