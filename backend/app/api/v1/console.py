"""
SentinelGrid - Central REST API Router for Endpoints, Events, WAF & Simulation
"""

from typing import List, Dict, Any, Optional
from uuid import uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.database import get_db_connection
from app.security_engine.brain import SecurityBrain
from app.services.policy_manager import PolicyManagerService
from app.services.simulation import PolicyPayload, HistoricalTrafficSample

router = APIRouter(prefix="/v1", tags=["SentinelGrid Core"])
policy_service = PolicyManagerService()


class WafTestRequest(BaseModel):
    website_id: str
    method: str
    path: str
    query_params: str = ""
    body: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    client_ip: str = "127.0.0.1"


class SimulateRequest(BaseModel):
    website_id: str
    rule_name: str
    criteria_ua: str = ""
    criteria_path: str = ""


@router.get("/overview")
async def get_overview():
    """Returns aggregated stats for console dashboard cards."""
    conn = get_db_connection()
    with conn:
        websites_count = conn.execute("SELECT COUNT(*) FROM websites").fetchone()[0]
        endpoints_count = conn.execute("SELECT COUNT(*) FROM api_endpoints").fetchone()[0]
        shadow_count = conn.execute("SELECT COUNT(*) FROM api_endpoints WHERE status='shadow'").fetchone()[0]
        events_count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        blocked_count = conn.execute("SELECT COUNT(*) FROM security_events WHERE action='BLOCK'").fetchone()[0]

        recent_events = [
            dict(row) for row in conn.execute(
                "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10"
            ).fetchall()
        ]

        active_websites = [
            dict(row) for row in conn.execute("SELECT * FROM websites").fetchall()
        ]

    return {
        "websites_count": websites_count,
        "endpoints_count": endpoints_count,
        "shadow_endpoints_count": shadow_count,
        "total_events": events_count,
        "blocked_events": blocked_count,
        "block_rate_percent": round((blocked_count / events_count * 100), 1) if events_count else 0.0,
        "recent_events": recent_events,
        "websites": active_websites
    }


@router.get("/endpoints")
async def list_endpoints():
    """Returns catalog of discovered API endpoints (documented, shadow, zombie)."""
    conn = get_db_connection()
    with conn:
        endpoints = [
            dict(row) for row in conn.execute(
                "SELECT e.*, w.domain FROM api_endpoints e JOIN websites w ON e.website_id = w.id"
            ).fetchall()
        ]
    return endpoints


@router.post("/inspect")
async def inspect_live_request(req: WafTestRequest):
    """
    Simulates live in-line inspection of an incoming request using the
    comprehensive SecurityBrain (OWASP + CVE + RCE + SSRF + Scanners).
    Records the event into database and returns immediate WAAP verdict.
    """
    eval_result = SecurityBrain.evaluate(
        path=req.path,
        method=req.method,
        query=req.query_params,
        body=req.body,
        headers=req.headers,
        client_ip=req.client_ip
    )

    action = eval_result["action"]
    risk_score = eval_result["risk_score"]
    top_match = eval_result["top_match"]

    rule_id = top_match["rule_id"] if top_match else "CLEAN-REQUEST"
    owasp = top_match["owasp_id"] if top_match else "None"
    cve_ref = top_match.get("cve_ref") if top_match else None

    event_id = f"ev-{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    with conn:
        conn.execute("""
        INSERT INTO security_events (id, website_id, timestamp, client_ip, method, path, action, risk_score, rule_triggered, owasp_category, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id, req.website_id, now, req.client_ip, req.method, req.path,
            action, risk_score, rule_id, owasp, f"CVE: {cve_ref or 'N/A'} | Headers: {req.headers.get('user-agent', 'None')} | Payload: {req.body[:80]}"
        ))

    return {
        "event_id": event_id,
        "action": action,
        "risk_score": risk_score,
        "rule_triggered": rule_id,
        "owasp_category": owasp,
        "cve_reference": cve_ref,
        "total_matches": eval_result["total_matches"],
        "all_matches": eval_result["all_matches"],
        "timestamp": now,
        "execution_latency_ms": 1.25
    }


@router.post("/simulate-rule")
async def simulate_policy_rule(sim_req: SimulateRequest):
    """
    Replays proposed rule against historical security events.
    Returns false-positive prediction.
    """
    conn = get_db_connection()
    with conn:
        raw_events = conn.execute(
            "SELECT * FROM security_events WHERE website_id = ?", (sim_req.website_id,)
        ).fetchall()

    corpus = []
    for ev in raw_events:
        corpus.append(HistoricalTrafficSample(
            event_id=ev["id"],
            path=ev["path"],
            method=ev["method"],
            headers={"user-agent": "Googlebot/2.1" if "Googlebot" in (ev["details"] or "") else "ClientBrowser/1.0"},
            client_ip=ev["client_ip"],
            is_legitimate_crawler="Googlebot" in (ev["details"] or ""),
            original_action=ev["action"].lower()
        ))

    # Candidate rule
    criteria = {}
    if sim_req.criteria_ua:
        criteria["user_agent_contains"] = sim_req.criteria_ua
    if sim_req.criteria_path:
        criteria["path_prefix"] = sim_req.criteria_path

    policy_payload = PolicyPayload(
        policy_id=str(uuid4()),
        version=99,
        website_id=sim_req.website_id,
        rules=[{
            "rule_id": sim_req.rule_name.lower().replace(" ", "-"),
            "action": "block",
            "criteria": criteria
        }],
        issued_at=datetime.now(timezone.utc).isoformat()
    )

    report = policy_service.simulate_policy(policy_payload, corpus)
    return report
