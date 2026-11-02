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


@router.post("/rollback", summary="1-Click Instant Policy Rollback")
async def rollback_policy(request: RollbackRequest):
    """
    Instantly restores a previously known safe policy version.
    """
    restored = policy_service.rollback_to_version(
        website_id=request.website_id,
        target_version=request.target_version
    )
    if not restored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target policy version {request.target_version} not found in history"
        )
    return restored
