"""
SentinelGrid - Verification Suite for Developer 1 Work Stream
Tests Ed25519 signing, simulation false-positive prediction, and 1-click rollback.
"""

import sys
import os
import unittest

# Add backend directory to sys.path
sys.path.insert(0, "/run/media/anup/D/sentinelgrid/backend")

from app.core.crypto import Ed25519KeyManager, AsymmetricPolicySigner
from app.services.simulation import (
    PolicySimulationEngine,
    PolicyPayload,
    HistoricalTrafficSample
)
from app.services.policy_manager import PolicyManagerService


class TestDeveloperOneStream(unittest.TestCase):

    def test_ed25519_key_management_and_signing(self):
        """Verifies asymmetric key generation, signing, and connector verification."""
        priv, pub = Ed25519KeyManager.generate_key_pair()

        priv_b64 = Ed25519KeyManager.export_private_key_b64(priv)
        pub_b64 = Ed25519KeyManager.export_public_key_b64(pub)

        # Reload keys
        loaded_priv = Ed25519KeyManager.load_private_key_b64(priv_b64)
        loaded_pub = Ed25519KeyManager.load_public_key_b64(pub_b64)

        payload = {
            "policy_id": "test-123",
            "version": 1,
            "thresholds": {"block": 75}
        }

        # Sign with private key
        sig = AsymmetricPolicySigner.sign_policy(payload, loaded_priv)
        self.assertTrue(len(sig) > 0)

        # Verify with public key
        is_valid = AsymmetricPolicySigner.verify_signature(payload, sig, loaded_pub)
        self.assertTrue(is_valid)

        # Tampered payload must fail
        tampered = dict(payload)
        tampered["thresholds"] = {"block": 10}
        self.assertFalse(AsymmetricPolicySigner.verify_signature(tampered, sig, loaded_pub))

    def test_policy_simulation_detects_false_positive(self):
        """Verifies simulation detects when a proposed rule would block legitimate crawlers."""
        corpus = [
            HistoricalTrafficSample(
                event_id="ev-1",
                path="/products/item-123",
                method="GET",
                headers={"user-agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
                client_ip="66.249.66.1",
                is_legitimate_crawler=True,
                original_action="allow"
            ),
            HistoricalTrafficSample(
                event_id="ev-2",
                path="/admin/config",
                method="POST",
                headers={"user-agent": "HeadlessChrome/120.0"},
                client_ip="198.51.100.23",
                is_legitimate_crawler=False,
                original_action="allow"
            )
        ]

        # Proposed rule: block anything containing "bot"
        overly_broad_policy = PolicyPayload(
            policy_id="pol-broad",
            version=2,
            website_id="site-1",
            rules=[{
                "rule_id": "block-bots",
                "action": "block",
                "criteria": {"user_agent_contains": "bot"}
            }],
            issued_at="2026-11-02T00:00:00Z"
        )

        report = PolicySimulationEngine.simulate_policy_diff(overly_broad_policy, corpus)
        self.assertEqual(report.projected_blocks, 1)
        self.assertEqual(report.potential_false_positive_count, 1)
        self.assertFalse(report.is_safe_to_deploy)

    def test_policy_manager_full_lifecycle_and_rollback(self):
        """Verifies full draft -> simulate -> sign -> rollback cycle."""
        service = PolicyManagerService()
        website_id = "site-production"

        # 1. Draft v1
        v1 = service.create_policy_version(website_id, rules=[])
        self.assertEqual(v1.version, 1)

        # 2. Sign and activate v1
        env1 = service.sign_and_activate_policy(v1)
        self.assertEqual(env1["policy"]["version"], 1)

        # 3. Draft v2 with rules
        v2 = service.create_policy_version(
            website_id,
            rules=[{"rule_id": "r1", "action": "block", "criteria": {"path_prefix": "/wp-login.php"}}]
        )
        self.assertEqual(v2.version, 2)
        env2 = service.sign_and_activate_policy(v2)
        self.assertEqual(env2["policy"]["version"], 2)

        # 4. Instant rollback to v1
        restored_env = service.rollback_to_version(website_id, target_version=1)
        self.assertIsNotNone(restored_env)
        # Rollback bumps version counter to notify connectors
        self.assertEqual(restored_env["policy"]["version"], 3)
        self.assertEqual(len(restored_env["policy"]["rules"]), 0)


if __name__ == "__main__":
    unittest.main()
