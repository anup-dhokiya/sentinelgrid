"""
SentinelGrid - Central REST API Router for Endpoints, Events, WAF & Simulation
Enterprise-grade WAAP Control Plane:
- Protected Domain & Asset Management
- Real-Time Target-Aware In-Line Inspection (<1.5ms budget)
- Dynamic IP Access Control Lists (CIDR + Single IP)
- Automated API Attack Surface Discovery (OpenAPI ingestion + Shadow API flagging)
- Observation Connector & Sidecar Heartbeat Tracking
- Policy Simulation & Historical Dry-Run Engine
"""

from typing import List, Dict, Any, Optional
from uuid import uuid4
from datetime import datetime, timezone
import json
import ipaddress
import yaml
from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field

from app.core.database import get_db_connection
from app.security_engine.brain import SecurityBrain
from app.services.policy_manager import PolicyManagerService
from app.services.simulation import PolicyPayload, HistoricalTrafficSample

router = APIRouter(prefix="/v1", tags=["SentinelGrid Core"])
policy_service = PolicyManagerService()


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------

class WebsiteCreateRequest(BaseModel):
    domain: str
    name: str


class WebsiteUpdateRequest(BaseModel):
    domain: Optional[str] = None
    name: Optional[str] = None
    status: Optional[str] = None


class WafTestRequest(BaseModel):
    website_id: Optional[str] = "default-site"
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


class IpRuleCreateRequest(BaseModel):
    website_id: str
    ip_or_cidr: str
    action: str = "BLOCK"  # 'BLOCK' or 'ALLOW'
    description: str = ""


class ApiSpecImportRequest(BaseModel):
    website_id: str
    spec_content: str  # JSON or YAML string


class ConnectorHeartbeatRequest(BaseModel):
    website_id: str
    connector_name: str
    connector_type: str  # 'nginx', 'asgi', 'express', 'go', 'cloudflare'
    latency_ms: float = 0.8


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

def ip_in_rule(client_ip: str, rule_ip_or_cidr: str) -> bool:
    """Evaluates whether client_ip matches a specific IP or CIDR range."""
    try:
        cip = ipaddress.ip_address(client_ip)
        if "/" in rule_ip_or_cidr:
            return cip in ipaddress.ip_network(rule_ip_or_cidr, strict=False)
        return cip == ipaddress.ip_address(rule_ip_or_cidr)
    except ValueError:
        return False


def get_or_create_website(conn, website_id: Optional[str]) -> str:
    """Ensures a valid website foreign key exists, creating default gateway if needed."""
    now = datetime.now(timezone.utc).isoformat()
    if website_id:
        row = conn.execute("SELECT id FROM websites WHERE id = ?", (website_id,)).fetchone()
        if row:
            return row["id"]

    # Fall back to first available website or create a default tenant
    first = conn.execute("SELECT id FROM websites LIMIT 1").fetchone()
    if first:
        return first["id"]

    fallback_id = website_id or f"site-{uuid4().hex[:8]}"
    conn.execute(
        "INSERT OR IGNORE INTO websites (id, domain, name, created_at, status, risk_score) VALUES (?, ?, ?, ?, 'active', 0.0)",
        (fallback_id, "default.local", "Default Application Gateway", now)
    )
    # Also create default baseline policy
    conn.execute(
        "INSERT OR IGNORE INTO policies (id, website_id, version, name, threshold_block, threshold_challenge, status, signature, created_at) VALUES (?, ?, 1, 'Baseline Safe Guard', 75, 50, 'active', 'ED25519-INITIAL-BASELINE', ?)",
        (f"pol-{uuid4().hex[:8]}", fallback_id, now)
    )
    return fallback_id


# -----------------------------------------------------------------------------
# Core WAAP Endpoints
# -----------------------------------------------------------------------------

@router.get("/overview")
async def get_overview():
    """Returns aggregated metrics for the central WAAP operations console."""
    conn = get_db_connection()
    with conn:
        websites_count = conn.execute("SELECT COUNT(*) FROM websites").fetchone()[0]
        endpoints_count = conn.execute("SELECT COUNT(*) FROM api_endpoints").fetchone()[0]
        shadow_count = conn.execute("SELECT COUNT(*) FROM api_endpoints WHERE status='shadow'").fetchone()[0]
        events_count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        blocked_count = conn.execute("SELECT COUNT(*) FROM security_events WHERE action='BLOCK'").fetchone()[0]

        recent_events = [
            dict(row) for row in conn.execute(
                "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 25"
            ).fetchall()
        ]

        active_websites = [
            dict(row) for row in conn.execute("SELECT * FROM websites ORDER BY created_at DESC").fetchall()
        ]

        connectors = [
            dict(row) for row in conn.execute("SELECT * FROM connectors ORDER BY last_heartbeat DESC").fetchall()
        ]

    return {
        "websites_count": websites_count,
        "endpoints_count": endpoints_count,
        "shadow_endpoints_count": shadow_count,
        "total_events": events_count,
        "blocked_events": blocked_count,
        "block_rate_percent": round((blocked_count / events_count * 100), 1) if events_count else 0.0,
        "recent_events": recent_events,
        "websites": active_websites,
        "connectors_online": len([c for c in connectors if c["status"] == "online"])
    }


# -----------------------------------------------------------------------------
# Website / Domain Management
# -----------------------------------------------------------------------------

@router.get("/websites")
async def list_websites():
    """Lists all protected domains with endpoint counts and active status."""
    conn = get_db_connection()
    with conn:
        rows = conn.execute("""
            SELECT w.*,
                   (SELECT COUNT(*) FROM api_endpoints WHERE website_id = w.id) AS endpoint_count,
                   (SELECT COUNT(*) FROM api_endpoints WHERE website_id = w.id AND status = 'shadow') AS shadow_count,
                   (SELECT COUNT(*) FROM security_events WHERE website_id = w.id) AS event_count
            FROM websites w
            ORDER BY w.created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


@router.post("/websites")
async def create_website(req: WebsiteCreateRequest):
    """Registers a new domain to be monitored and protected by SentinelGrid."""
    domain_clean = req.domain.strip().lower()
    if not domain_clean:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")

    site_id = f"site-{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO websites (id, domain, name, created_at, status, risk_score) VALUES (?, ?, ?, ?, 'active', 0.0)",
                (site_id, domain_clean, req.name.strip(), now)
            )
            # Create active policy v1
            conn.execute(
                "INSERT INTO policies (id, website_id, version, name, threshold_block, threshold_challenge, status, signature, created_at) VALUES (?, ?, 1, 'Standard WAAP Protection', 75, 50, 'active', 'ED25519-SIG-V1', ?)",
                (f"pol-{uuid4().hex[:8]}", site_id, now)
            )
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(status_code=400, detail="A website with this domain already exists.")
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "status": "created",
        "website": {
            "id": site_id,
            "domain": domain_clean,
            "name": req.name.strip(),
            "created_at": now
        }
    }


@router.put("/websites/{website_id}")
async def update_website(website_id: str, req: WebsiteUpdateRequest):
    """Edits domain name, label, or status of a protected website."""
    conn = get_db_connection()
    with conn:
        row = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Website not found.")
        new_domain = req.domain.strip().lower() if req.domain else row["domain"]
        new_name = req.name.strip() if req.name else row["name"]
        new_status = req.status.strip().lower() if req.status else row["status"]
        conn.execute(
            "UPDATE websites SET domain = ?, name = ?, status = ? WHERE id = ?",
            (new_domain, new_name, new_status, website_id)
        )
    return {
        "status": "updated",
        "website_id": website_id,
        "domain": new_domain,
        "name": new_name,
        "state": new_status
    }


@router.patch("/websites/{website_id}/toggle")
async def toggle_website_status(website_id: str):
    """Toggles active/disabled status for a protected domain."""
    conn = get_db_connection()
    with conn:
        row = conn.execute("SELECT status FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Website not found.")
        new_status = "disabled" if row["status"] == "active" else "active"
        conn.execute("UPDATE websites SET status = ? WHERE id = ?", (new_status, website_id))
    return {"status": "toggled", "website_id": website_id, "new_state": new_status}


@router.delete("/websites/{website_id}")
async def delete_website(website_id: str):
    """Deletes a protected website and cascades deletion to child records."""
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM security_events WHERE website_id = ?", (website_id,))
        conn.execute("DELETE FROM api_endpoints WHERE website_id = ?", (website_id,))
        conn.execute("DELETE FROM policies WHERE website_id = ?", (website_id,))
        conn.execute("DELETE FROM ip_rules WHERE website_id = ?", (website_id,))
        conn.execute("DELETE FROM connectors WHERE website_id = ?", (website_id,))
        conn.execute("DELETE FROM api_specs WHERE website_id = ?", (website_id,))
        cur = conn.execute("DELETE FROM websites WHERE id = ?", (website_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Website not found.")
    return {"status": "deleted", "website_id": website_id}


# -----------------------------------------------------------------------------
# Discovered & Documented API Endpoints
# -----------------------------------------------------------------------------

@router.get("/endpoints")
async def list_endpoints(website_id: Optional[str] = None):
    """Returns catalog of discovered API endpoints (documented, shadow, zombie)."""
    conn = get_db_connection()
    with conn:
        if website_id:
            rows = conn.execute(
                "SELECT e.*, w.domain FROM api_endpoints e JOIN websites w ON e.website_id = w.id WHERE e.website_id = ? ORDER BY e.last_seen DESC",
                (website_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT e.*, w.domain FROM api_endpoints e JOIN websites w ON e.website_id = w.id ORDER BY e.last_seen DESC"
            ).fetchall()
    return [dict(r) for r in rows]


@router.post("/api-specs/import")
async def import_openapi_spec(req: ApiSpecImportRequest):
    """
    Parses an OpenAPI 3.0 or Swagger 2.0 specification (JSON or YAML)
    and registers all routes as 'documented', establishing a schema contract.
    """
    conn = get_db_connection()
    site_id = get_or_create_website(conn, req.website_id)

    raw = req.spec_content.strip()
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError:
        try:
            spec = yaml.safe_load(raw)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse specification as JSON or YAML: {e}")

    paths = spec.get("paths", {})
    if not paths:
        raise HTTPException(status_code=400, detail="Specification contains no 'paths' definitions.")

    now = datetime.now(timezone.utc).isoformat()
    imported_count = 0
    title = spec.get("info", {}).get("title", "Imported API Specification")
    version = spec.get("info", {}).get("version", "1.0.0")

    with conn:
        # Save spec record
        spec_id = f"spec-{uuid4().hex[:8]}"
        conn.execute(
            "INSERT INTO api_specs (id, website_id, title, version, spec_json, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (spec_id, site_id, title, version, json.dumps(spec), now)
        )

        # Iterate paths and methods
        valid_methods = {"get", "post", "put", "delete", "patch", "options", "head"}
        documented_count = 0
        zombie_count = 0
        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method_key, op_obj in path_item.items():
                if method_key.lower() in valid_methods:
                    method_upper = method_key.upper()
                    is_deprecated = isinstance(op_obj, dict) and op_obj.get("deprecated", False)
                    target_status = "zombie" if is_deprecated else "documented"
                    risk_lvl = "HIGH" if is_deprecated else "LOW"

                    # Check if already cataloged
                    existing = conn.execute(
                        "SELECT id FROM api_endpoints WHERE website_id = ? AND path = ? AND method = ?",
                        (site_id, path_str, method_upper)
                    ).fetchone()

                    if existing:
                        conn.execute(
                            "UPDATE api_endpoints SET status = ?, risk_level = ?, last_seen = ? WHERE id = ?",
                            (target_status, risk_lvl, now, existing["id"])
                        )
                    else:
                        conn.execute(
                            "INSERT INTO api_endpoints (id, website_id, path, method, status, risk_level, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (f"ep-{uuid4().hex[:8]}", site_id, path_str, method_upper, target_status, risk_lvl, now)
                        )
                    imported_count += 1
                    if is_deprecated:
                        zombie_count += 1
                    else:
                        documented_count += 1

    return {
        "status": "success",
        "title": title,
        "version": version,
        "imported_endpoints_count": imported_count,
        "documented_count": documented_count,
        "zombie_count": zombie_count
    }


# -----------------------------------------------------------------------------
# Dynamic IP Access Control (Allowlist / Blocklist)
# -----------------------------------------------------------------------------

@router.get("/ip-rules")
async def list_ip_rules(website_id: Optional[str] = None):
    """Lists configured IP access control rules (single IPs and CIDR blocks)."""
    conn = get_db_connection()
    with conn:
        if website_id:
            rows = conn.execute("SELECT * FROM ip_rules WHERE website_id = ? ORDER BY created_at DESC", (website_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ip_rules ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@router.post("/ip-rules")
async def create_ip_rule(req: IpRuleCreateRequest):
    """Adds a new IP or CIDR rule (BLOCK or ALLOW)."""
    # Validate IP or CIDR syntax
    try:
        if "/" in req.ip_or_cidr:
            ipaddress.ip_network(req.ip_or_cidr.strip(), strict=False)
        else:
            ipaddress.ip_address(req.ip_or_cidr.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IP address or CIDR notation: {e}")

    conn = get_db_connection()
    site_id = get_or_create_website(conn, req.website_id)
    rule_id = f"ipr-{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    with conn:
        conn.execute(
            "INSERT INTO ip_rules (id, website_id, ip_or_cidr, action, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (rule_id, site_id, req.ip_or_cidr.strip(), req.action.upper(), req.description.strip(), now)
        )

    return {
        "status": "created",
        "rule": {
            "id": rule_id,
            "website_id": site_id,
            "ip_or_cidr": req.ip_or_cidr.strip(),
            "action": req.action.upper(),
            "description": req.description.strip(),
            "created_at": now
        }
    }


@router.delete("/ip-rules/{rule_id}")
async def delete_ip_rule(rule_id: str):
    """Deletes an IP access rule."""
    conn = get_db_connection()
    with conn:
        cur = conn.execute("DELETE FROM ip_rules WHERE id = ?", (rule_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="IP rule not found.")
    return {"status": "deleted", "rule_id": rule_id}


# -----------------------------------------------------------------------------
# Observation Connector & Sidecar Heartbeat Tracking
# -----------------------------------------------------------------------------

@router.get("/connectors")
async def list_connectors(website_id: Optional[str] = None):
    """Lists external observation connectors (Nginx, ASGI, Express, Go, Cloudflare)."""
    conn = get_db_connection()
    with conn:
        if website_id:
            rows = conn.execute("SELECT * FROM connectors WHERE website_id = ? ORDER BY last_heartbeat DESC", (website_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM connectors ORDER BY last_heartbeat DESC").fetchall()

    connectors = []
    now_dt = datetime.now(timezone.utc)
    for r in rows:
        item = dict(r)
        try:
            hb_dt = datetime.fromisoformat(item["last_heartbeat"].replace("Z", "+00:00"))
            if (now_dt - hb_dt).total_seconds() > 90:
                item["status"] = "offline"
            else:
                item["status"] = "online"
        except Exception:
            pass
        connectors.append(item)
    return connectors


@router.post("/connectors/heartbeat")
async def register_connector_heartbeat(req: ConnectorHeartbeatRequest):
    """Registers an observation agent heartbeat from external sites or reverse proxies."""
    conn = get_db_connection()
    site_id = get_or_create_website(conn, req.website_id)
    now = datetime.now(timezone.utc).isoformat()

    with conn:
        existing = conn.execute(
            "SELECT id FROM connectors WHERE website_id = ? AND name = ?",
            (site_id, req.connector_name)
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE connectors SET status = 'online', last_heartbeat = ?, latency_ms = ? WHERE id = ?",
                (now, req.latency_ms, existing["id"])
            )
            connector_id = existing["id"]
        else:
            connector_id = f"conn-{uuid4().hex[:8]}"
            conn.execute(
                "INSERT INTO connectors (id, website_id, name, connector_type, status, last_heartbeat, latency_ms) VALUES (?, ?, ?, ?, 'online', ?, ?)",
                (connector_id, site_id, req.connector_name, req.connector_type, now, req.latency_ms)
            )

    return {
        "status": "acknowledged",
        "connector_id": connector_id,
        "timestamp": now
    }


# -----------------------------------------------------------------------------
# Real-Time In-Line Inspection (<1.5ms budget)
# -----------------------------------------------------------------------------

@router.post("/inspect")
async def inspect_live_request(req: WafTestRequest):
    """
    Sub-1.5ms in-line request inspection engine:
    1. Checks dynamic IP Access Control Lists (Allowlist / Blacklist)
    2. Evaluates adversarial payloads via target-aware SecurityBrain
    3. Dynamically discovers undocumented routes as 'shadow' APIs
    4. Records event telemetry with forensic signature triggers
    """
    import time
    start_time = time.perf_counter()

    conn = get_db_connection()
    site_id = get_or_create_website(conn, req.website_id)
    now = datetime.now(timezone.utc).isoformat()

    # Step 1: Check IP Access Rules
    with conn:
        ip_rules = conn.execute(
            "SELECT ip_or_cidr, action, description FROM ip_rules WHERE website_id = ?",
            (site_id,)
        ).fetchall()

    for rule in ip_rules:
        if ip_in_rule(req.client_ip, rule["ip_or_cidr"]):
            rule_action = rule["action"].upper()
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            event_id = f"ev-{uuid4().hex[:8]}"

            with conn:
                conn.execute("""
                INSERT INTO security_events (id, website_id, timestamp, client_ip, method, path, action, risk_score, rule_triggered, owasp_category, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id, site_id, now, req.client_ip, req.method, req.path,
                    rule_action, 100.0 if rule_action == "BLOCK" else 0.0,
                    f"IP-{rule_action}-LIST", "A01:Broken Access Control",
                    f"Rule: {rule['ip_or_cidr']} ({rule['description'] or 'Custom ACL'})"
                ))

            return {
                "event_id": event_id,
                "action": rule_action,
                "risk_score": 100.0 if rule_action == "BLOCK" else 0.0,
                "rule_triggered": f"IP-{rule_action}-LIST",
                "owasp_category": "A01:Broken Access Control",
                "cve_reference": None,
                "total_matches": 1,
                "all_matches": [{"rule_id": f"IP-{rule_action}-LIST", "name": rule["description"] or "IP Access Rule"}],
                "timestamp": now,
                "execution_latency_ms": elapsed_ms
            }

    # Step 2: Target-Aware Threat Brain Evaluation
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

    # Step 3: Automated Shadow API Discovery
    with conn:
        endpoint = conn.execute(
            "SELECT id, status FROM api_endpoints WHERE website_id = ? AND path = ? AND method = ?",
            (site_id, req.path, req.method.upper())
        ).fetchone()

        if endpoint:
            # Update last_seen
            conn.execute("UPDATE api_endpoints SET last_seen = ? WHERE id = ?", (now, endpoint["id"]))
        else:
            # Undocumented route observed in live traffic -> auto-catalog as SHADOW API
            conn.execute(
                "INSERT INTO api_endpoints (id, website_id, path, method, status, risk_level, last_seen) VALUES (?, ?, ?, ?, 'shadow', 'MEDIUM', ?)",
                (f"ep-{uuid4().hex[:8]}", site_id, req.path, req.method.upper(), now)
            )

    # Step 4: Record Event Telemetry
    event_id = f"ev-{uuid4().hex[:8]}"
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    with conn:
        conn.execute("""
        INSERT INTO security_events (id, website_id, timestamp, client_ip, method, path, action, risk_score, rule_triggered, owasp_category, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id, site_id, now, req.client_ip, req.method, req.path,
            action, risk_score, rule_id, owasp,
            f"CVE: {cve_ref or 'N/A'} | Headers: {req.headers.get('user-agent', 'None')[:60]} | Payload: {req.body[:80]}"
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
        "execution_latency_ms": elapsed_ms
    }


# -----------------------------------------------------------------------------
# Security Events SIEM Export & Live Analytics
# -----------------------------------------------------------------------------

@router.get("/events")
async def list_events(
    website_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    path: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """Retrieves security telemetry events with multi-field filtering for the threat analytics console."""
    conn = get_db_connection()
    conditions = ["1=1"]
    params = []

    if website_id:
        conditions.append("website_id = ?")
        params.append(website_id)
    if client_ip:
        conditions.append("client_ip LIKE ?")
        params.append(f"%{client_ip.strip()}%")
    if path:
        conditions.append("path LIKE ?")
        params.append(f"%{path.strip()}%")
    if action:
        conditions.append("action = ?")
        params.append(action.strip().upper())

    where_clause = " AND ".join(conditions)

    with conn:
        total = conn.execute(f"SELECT COUNT(*) FROM security_events WHERE {where_clause}", params).fetchone()[0]
        query = f"SELECT * FROM security_events WHERE {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        rows = conn.execute(query, params + [limit, offset]).fetchall()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [dict(r) for r in rows]
    }


@router.get("/events/export")
async def export_events(
    website_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    path: Optional[str] = None,
    action: Optional[str] = None,
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = 1000
):
    """Exports structured security events as JSON or RFC 4180 CSV for external SIEM / SOAR pipelines."""
    import csv
    import io
    from fastapi.responses import Response

    conn = get_db_connection()
    conditions = ["1=1"]
    params = []

    if website_id:
        conditions.append("website_id = ?")
        params.append(website_id)
    if client_ip:
        conditions.append("client_ip LIKE ?")
        params.append(f"%{client_ip.strip()}%")
    if path:
        conditions.append("path LIKE ?")
        params.append(f"%{path.strip()}%")
    if action:
        conditions.append("action = ?")
        params.append(action.strip().upper())

    where_clause = " AND ".join(conditions)

    with conn:
        rows = conn.execute(
            f"SELECT * FROM security_events WHERE {where_clause} ORDER BY timestamp DESC LIMIT ?",
            params + [limit]
        ).fetchall()
        events = [dict(r) for r in rows]

    if format == "csv":
        output = io.StringIO()
        fieldnames = ["id", "website_id", "timestamp", "client_ip", "method", "path", "action", "risk_score", "rule_triggered", "owasp_category", "details"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            writer.writerow(ev)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinelgrid-security-events.csv"}
        )

    return Response(
        content=json.dumps(events, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinelgrid-security-events.json"}
    )


# -----------------------------------------------------------------------------
# Policy Simulation & Dry-Run
# -----------------------------------------------------------------------------

@router.post("/simulate-rule")
async def simulate_policy_rule(sim_req: SimulateRequest):
    """
    Replays proposed rule modifications against historical security events.
    Returns false-positive prediction before live deployment.
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
