"""
SentinelGrid - Central Policy Management & Versioning Service
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from uuid import uuid4
from app.core.crypto import AsymmetricPolicySigner, Ed25519KeyManager
from app.services.simulation import PolicyPayload, SimulationReport, PolicySimulationEngine, HistoricalTrafficSample


class PolicyManagerService:
    """
    Manages active policy versions, dry-run simulations, signing, and rollbacks.
    """

    def __init__(self):
        # In-memory storage for initial developer baseline (to be backed by PostgreSQL models)
        self._private_key, self._public_key = Ed25519KeyManager.generate_key_pair()
        self._policy_history: Dict[str, List[Dict[str, Any]]] = {}  # website_id -> list of signed policies
        self._active_policy_version: Dict[str, int] = {}  # website_id -> active version number

    @property
    def public_key_b64(self) -> str:
        """Connector-facing public verification key."""
        return Ed25519KeyManager.export_public_key_b64(self._public_key)

    def create_policy_version(
        self,
        website_id: str,
        rules: List[Dict[str, Any]],
        thresholds: Optional[Dict[str, int]] = None
    ) -> PolicyPayload:
        """Creates a new staged policy version payload."""
        current_version = self._active_policy_version.get(website_id, 0)
        next_version = current_version + 1

        payload = PolicyPayload(
            policy_id=str(uuid4()),
            version=next_version,
            website_id=website_id,
            thresholds=thresholds or {"block": 75, "challenge": 50, "monitor": 25},
            rules=rules,
            issued_at=datetime.now(timezone.utc).isoformat()
        )
        return payload

    def simulate_policy(
        self,
        candidate_policy: PolicyPayload,
        traffic_corpus: List[HistoricalTrafficSample]
    ) -> SimulationReport:
        """Executes non-invasive simulation against historical traffic."""
        return PolicySimulationEngine.simulate_policy_diff(candidate_policy, traffic_corpus)

    def sign_and_activate_policy(self, candidate_policy: PolicyPayload) -> Dict[str, Any]:
        """
        Signs the validated policy payload using private key and commits it to active state.
        Returns full signed envelope ready for distribution to connectors.
        """
        dict_payload = candidate_policy.model_dump()
        signature_b64 = AsymmetricPolicySigner.sign_policy(dict_payload, self._private_key)

        signed_envelope = {
            "policy": dict_payload,
            "signature": signature_b64,
            "signature_algorithm": "Ed25519",
            "signer": "SentinelGrid Central Control Plane"
        }

        website_id = candidate_policy.website_id
        if website_id not in self._policy_history:
            self._policy_history[website_id] = []

        self._policy_history[website_id].append(signed_envelope)
        self._active_policy_version[website_id] = candidate_policy.version

        return signed_envelope

    def rollback_to_version(self, website_id: str, target_version: int) -> Optional[Dict[str, Any]]:
        """
        1-Click Instant Rollback: Restores a previous stable policy version.
        Re-signs and distributes immediately.
        """
        history = self._policy_history.get(website_id, [])
        target_policy = None

        for item in history:
            if item["policy"]["version"] == target_version:
                target_policy = item["policy"]
                break

        if not target_policy:
            return None

        # Re-issue with updated timestamp and incremented active version to force connector cache refresh
        rollback_payload = PolicyPayload(
            policy_id=str(uuid4()),
            version=self._active_policy_version[website_id] + 1,
            website_id=website_id,
            thresholds=target_policy["thresholds"],
            rules=target_policy["rules"],
            ip_blocklist_delta=target_policy.get("ip_blocklist_delta", {"add": [], "remove": []}),
            issued_at=datetime.now(timezone.utc).isoformat()
        )

        return self.sign_and_activate_policy(rollback_payload)
