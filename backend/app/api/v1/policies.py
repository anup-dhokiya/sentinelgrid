"""
SentinelGrid - Central Policy & Management API Router
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.services.simulation import PolicyPayload, SimulationReport, HistoricalTrafficSample
from app.services.policy_manager import PolicyManagerService
from app.core.crypto import AsymmetricPolicySigner, Ed25519KeyManager

router = APIRouter(prefix="/v1/policies", tags=["Policies"])

# Singleton service instance
policy_service = PolicyManagerService()


class CreatePolicyRequest(BaseModel):
    website_id: str
    rules: List[Dict[str, Any]]
    thresholds: Optional[Dict[str, int]] = None


class SimulatePolicyRequest(BaseModel):
    candidate_policy: PolicyPayload
    traffic_samples: List[HistoricalTrafficSample] = Field(default_factory=list)


class RollbackRequest(BaseModel):
    website_id: str
    target_version: int


@router.get("/verification-key", summary="Get connector public verification key")
async def get_verification_key():
    """
    Returns the public Ed25519 key used by connectors to verify signed policies.
    """
    return {
        "algorithm": "Ed25519",
        "public_key_b64": policy_service.public_key_b64
    }


@router.post("/draft", response_model=PolicyPayload, summary="Create a new policy version draft")
async def draft_policy(request: CreatePolicyRequest):
    """
    Drafts an incremented policy payload for testing and simulation.
    """
    return policy_service.create_policy_version(
        website_id=request.website_id,
        rules=request.rules,
        thresholds=request.thresholds
    )


@router.post("/simulate", response_model=SimulationReport, summary="Simulate policy against historical traffic")
async def simulate_policy(request: SimulatePolicyRequest):
    """
    Dry-run simulation: Replays historical traffic through candidate policy rules.
    Detects false positives on search crawlers before live enforcement.
    """
    report = policy_service.simulate_policy(
        candidate_policy=request.candidate_policy,
        traffic_corpus=request.traffic_samples
    )
    return report


@router.post("/deploy", summary="Sign and deploy policy to connectors")
async def deploy_policy(candidate_policy: PolicyPayload, force: bool = False):
    """
    Signs the candidate policy using RFC 8032 Ed25519 and marks it as active.
    """
    signed_envelope = policy_service.sign_and_activate_policy(candidate_policy)
    return signed_envelope


from app.core.database import get_db_connection
from app.core.crypto import AsymmetricPolicySigner
import json
from uuid import uuid4
from datetime import datetime, timezone

@router.post("/rollback", summary="1-Click Instant Policy Rollback")
async def rollback_policy(request: RollbackRequest):
    """
    Instantly restores a previously known safe policy version.
    Queries persistent SQLite policy ledger with Ed25519 asymmetric cryptographic resigning.
    """
    restored = policy_service.rollback_to_version(
        website_id=request.website_id,
        target_version=request.target_version
    )
    if restored:
        return restored

    # Fallback to persistent SQLite policy history
    conn = get_db_connection()
    with conn:
        site = conn.execute(
            "SELECT id FROM websites WHERE id = ? OR domain = ?", 
            (request.website_id, request.website_id)
        ).fetchone()
        site_id = site[0] if site else request.website_id

        target_row = conn.execute(
            "SELECT * FROM policies WHERE website_id = ? AND version = ?",
            (site_id, request.target_version)
        ).fetchone()

        if not target_row:
            target_row = conn.execute(
                "SELECT * FROM policies WHERE website_id = ? ORDER BY version DESC LIMIT 1",
                (site_id,)
            ).fetchone()

        if not target_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target policy version {request.target_version} not found in history for {request.website_id}"
            )

        latest_ver = conn.execute(
            "SELECT MAX(version) FROM policies WHERE website_id = ?",
            (site_id,)
        ).fetchone()[0] or 1
        new_version = latest_ver + 1
        now_iso = datetime.now(timezone.utc).isoformat()
        new_policy_id = f"pol-{uuid4().hex[:8]}"

        policy_body = {
            "policy_id": new_policy_id,
            "version": new_version,
            "website_id": site_id,
            "threshold_block": target_row["threshold_block"],
            "threshold_challenge": target_row["threshold_challenge"],
            "issued_at": now_iso
        }
        sig = AsymmetricPolicySigner.sign_policy(policy_body, policy_service._private_key)

        conn.execute("UPDATE policies SET status = 'superseded' WHERE website_id = ?", (site_id,))
        conn.execute("""
            INSERT INTO policies (id, website_id, version, name, threshold_block, threshold_challenge, status, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
        """, (
            new_policy_id, site_id, new_version,
            f"Restored from v{target_row['version']} ({target_row['name']})",
            target_row["threshold_block"], target_row["threshold_challenge"],
            sig, now_iso
        ))

    return {
        "status": "restored",
        "policy": {
            "policy_id": new_policy_id,
            "version": new_version,
            "website_id": site_id,
            "thresholds": {
                "block": target_row["threshold_block"],
                "challenge": target_row["threshold_challenge"]
            },
            "signature": sig,
            "issued_at": now_iso
        }
    }
