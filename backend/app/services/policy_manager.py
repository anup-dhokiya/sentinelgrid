"""
SentinelGrid - Central Policy Management & Versioning Service
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

import os
import tempfile
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from app.core.crypto import AsymmetricPolicySigner, Ed25519KeyManager
from app.services.simulation import PolicyPayload, SimulationReport, PolicySimulationEngine, HistoricalTrafficSample

if os.getenv("DATA_DIR"):
    MASTER_KEY_DIR = Path(os.getenv("DATA_DIR")) / ".keys"
elif Path("/run/media/anup/D/sentinelgrid/backend").is_dir():
    MASTER_KEY_DIR = Path("/run/media/anup/D/sentinelgrid/backend/.keys")
else:
    _base = Path(__file__).resolve().parent.parent.parent
    MASTER_KEY_DIR = _base / ".keys" if os.access(_base, os.W_OK) else Path(tempfile.gettempdir()) / "sentinelgrid_keys"

MASTER_KEY_FILE = MASTER_KEY_DIR / "ed25519_master.key"
MASTER_PUB_FILE = MASTER_KEY_DIR / "ed25519_master.pub"


class PolicyManagerService:
    """
    Manages active policy versions, dry-run simulations, signing, and rollbacks.
    Persists cryptographic master signing key to disk to guarantee connector continuity.
    """

    def __init__(self):
        self._init_master_keypair()
        self._policy_history: Dict[str, List[Dict[str, Any]]] = {}  # website_id -> list of signed policies
        self._active_policy_version: Dict[str, int] = {}  # website_id -> active version number

    def _init_master_keypair(self):
        import os
        MASTER_KEY_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(MASTER_KEY_DIR, 0o700)
        except Exception:
            pass

        if MASTER_KEY_FILE.exists():
            try:
                try:
                    os.chmod(MASTER_KEY_FILE, 0o600)
                except Exception:
                    pass
                b64_key = MASTER_KEY_FILE.read_text().strip()
                self._private_key = Ed25519KeyManager.load_private_key_b64(b64_key)
                self._public_key = self._private_key.public_key()
                return
            except Exception:
                pass

        # Generate and safely persist master keypair with strict permissions (0600)
        self._private_key, self._public_key = Ed25519KeyManager.generate_key_pair()
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(str(MASTER_KEY_FILE), flags, 0o600), "w") as f:
            f.write(Ed25519KeyManager.export_private_key_b64(self._private_key))
        MASTER_PUB_FILE.write_text(Ed25519KeyManager.export_public_key_b64(self._public_key))

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
