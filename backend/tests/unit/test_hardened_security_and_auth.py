"""
SentinelGrid - Hardened Security, PBKDF2 Auth, and Polyglot Engine Verification Suite
Verifies PBKDF2 Password Authentication, Session Tokens, Simulation API Dual Contract,
Sandbox GET Query Injection, and IPv6 Canonicalization.
"""

import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, "/run/media/anup/D/sentinelgrid/backend")

from app.main import app
from app.security_engine.rate_limiter import global_rate_limiter
from app.api.v1.auth import verify_password, hash_password


class TestHardenedSecurityAndAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        global_rate_limiter.clear_all_quarantine()

    def test_01_pbkdf2_admin_authentication(self):
        """Verifies master admin authenticates with salted PBKDF2-HMAC-SHA256."""
        res = self.client.post("/v1/auth/login", json={
            "email": "a@123",
            "password": "anup@5212"
        })
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "authenticated")
        self.assertTrue(body["token"].startswith("sg_session_"))
        self.assertEqual(body["user"]["role"], "manager")

    def test_02_pbkdf2_wrong_password_rejected(self):
        """Verifies invalid passwords are rejected with 401."""
        res = self.client.post("/v1/auth/login", json={
            "email": "a@123",
            "password": "wrong-password"
        })
        self.assertEqual(res.status_code, 401)

    def test_03_sandbox_get_query_inspection(self):
        """Verifies GET query parameter injection is inspected and blocked."""
        res = self.client.post("/v1/inspect", json={
            "method": "GET",
            "path": "/api/v1/products",
            "query": "id=1' UNION SELECT username, password FROM users--",
            "client_ip": "127.0.0.1",
            "headers": {"X-SentinelGrid-Sandbox": "true"}
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action"], "BLOCK")
        self.assertIn("SQL", data["rule_triggered"])

    def test_04_simulate_rule_dual_contract(self):
        """Verifies /simulate-rule accepts frontend payload format and returns unified schema."""
        res = self.client.post("/v1/simulate-rule", json={
            "rule_id": "block-test-scanners",
            "pattern": "Nmap",
            "target_field": "user_agent",
            "action": "BLOCK"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        # Verify both frontend-expected keys and simulation report keys exist
        self.assertIn("sample_size_evaluated", data)
        self.assertIn("candidate_rule_id", data)
        self.assertIn("predicted_blocks_count", data)
        self.assertIn("block_delta_percent", data)
        self.assertIn("collateral_risk_level", data)
        self.assertIn("total_evaluated_requests", data)
        self.assertIn("is_safe_to_deploy", data)

    def test_05_ipv6_port_and_bracket_canonicalization(self):
        """Verifies IPv6 addresses with ports and brackets are normalized to /64 network."""
        bracketed = global_rate_limiter._canonicalize_ip("[2001:db8:85a3::8a2e:370:7334]:8080")
        bare = global_rate_limiter._canonicalize_ip("2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(bracketed, bare)
        self.assertTrue(bracketed.startswith("2001:db8:85a3::"))

    def test_06_cve_canary_php_cgi_fallback(self):
        """Verifies CVE-2024-4577 canary catches argument injection with %ad."""
        from app.security_engine.brain import SecurityBrain
        result = SecurityBrain.evaluate(
            path="/index.php",
            method="POST",
            query="%ad+d+allow_url_include=1",
            body="",
            headers={},
            client_ip="192.0.2.1"
        )
        self.assertEqual(result["action"], "BLOCK")
        self.assertEqual(result["top_match"]["rule_id"], "CVE-2024-4577-PHP-CGI-RCE")


if __name__ == "__main__":
    unittest.main()
