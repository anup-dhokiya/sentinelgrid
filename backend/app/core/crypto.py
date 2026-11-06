"""
SentinelGrid - Cryptographic Engine & Ed25519 Policy Signing (RFC 8032)
Author: SentinelGrid Architecture Core Team
"""

import base64
import json
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class Ed25519KeyManager:
    """Manages asymmetric Ed25519 key generation, rotation, and serialization."""

    @staticmethod
    def generate_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generates a high-security RFC 8032 Ed25519 private/public keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def export_private_key_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
        """Serializes raw 32-byte private key into base64 string for KMS/Vault storage."""
        raw_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return base64.b64encode(raw_bytes).decode("utf-8")

    @staticmethod
    def load_private_key_b64(b64_str: str) -> ed25519.Ed25519PrivateKey:
        """Loads private key from base64 string."""
        raw_bytes = base64.b64decode(b64_str.encode("utf-8"))
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)

    @staticmethod
    def export_public_key_b64(public_key: ed25519.Ed25519PublicKey) -> str:
        """Serializes raw 32-byte public key into base64 string for distribution to connectors."""
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw_bytes).decode("utf-8")

    @staticmethod
    def load_public_key_b64(b64_str: str) -> ed25519.Ed25519PublicKey:
        """Loads public key from base64 string."""
        raw_bytes = base64.b64decode(b64_str.encode("utf-8"))
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


class AsymmetricPolicySigner:
    """
    Cryptographic signer for security policies.
    Guarantees integrity and non-repudiation across distributed connectors.
    """

    @staticmethod
    def canonicalize_payload(payload: Dict[str, Any]) -> bytes:
        """
        Creates a deterministic, byte-for-byte canonical JSON representation.
        Sorts keys and strips redundant whitespace to ensure signature stability.
        """
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def sign_policy(cls, policy_payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
        """
        Signs the deterministic canonical JSON representation of a policy payload.
        Returns standard base64 signature string (64 bytes).
        """
        canonical_bytes = cls.canonicalize_payload(policy_payload)
        signature = private_key.sign(canonical_bytes)
        return base64.b64encode(signature).decode("utf-8")

    @classmethod
    def verify_signature(cls, policy_payload: Dict[str, Any], signature_b64: str, public_key: ed25519.Ed25519PublicKey) -> bool:
        """
        Verifies policy signature at the connector runtime.
        Returns True if signature is valid; False otherwise.
        """
        canonical_bytes = cls.canonicalize_payload(policy_payload)
        try:
            signature = base64.b64decode(signature_b64.encode("utf-8"))
            public_key.verify(signature, canonical_bytes)
            return True
        except Exception:
            return False
