"""
SentinelGrid - Strict Anti-Slop Pydantic Data Contracts & Schemas
Author: SentinelGrid Architecture Core Team
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


def current_iso8601_utc() -> str:
    """Returns strict ISO-8601 UTC string with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ForensicDetails(BaseModel):
    """Structured Forensic details object eliminating unstructured prose."""
    latency_ms: float = Field(..., description="Inspection latency in milliseconds rounded to 2 decimal places")
    payload_snippet: str = Field(..., max_length=500, description="Truncated payload string under inspection")
    host: str = Field("api.protected-mesh.internal", description="Target domain FQDN")
    user_agent: str = Field("curl/8.0.0", description="Client User-Agent header")
    cve: str = Field("N/A", description="Associated CVE identifier or N/A")


class RuleMatch(BaseModel):
    rule_id: str
    name: str
    category: Optional[str] = None
    owasp_id: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    cve_ref: Optional[str] = None


class InspectRequest(BaseModel):
    client_ip: str
    method: str = "GET"
    path: str = "/"
    query: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    host: Optional[str] = None


class InspectResponse(BaseModel):
    event_id: str
    action: str = Field(..., regex="^(ALLOW|BLOCK|CHALLENGE)$")
    risk_score: float = Field(..., ge=0.0, le=100.0)
    rule_triggered: Optional[str] = None
    owasp_category: Optional[str] = None
    cve_reference: Optional[str] = None
    total_matches: int = 0
    all_matches: List[RuleMatch] = []
    timestamp: str = Field(default_factory=current_iso8601_utc)
    execution_latency_ms: float
    retry_after_seconds: Optional[int] = None
    cryptographic_seal: Optional[str] = None
    forensic_details: Optional[ForensicDetails] = None


class UserProfile(BaseModel):
    full_name: str
    email: str
    role: str = Field(..., regex="^(manager|team_leader|member)$")


class LoginResponse(BaseModel):
    token: str
    user: UserProfile
    message: str = "Clearance verified"
