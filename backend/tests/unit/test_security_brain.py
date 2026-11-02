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


if __name__ == "__main__":
    unittest.main()
