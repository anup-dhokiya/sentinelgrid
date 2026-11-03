"""
SentinelGrid ASGI Middleware for FastAPI / Starlette
Provides non-blocking async request inspection with stream buffering and fail-open policy.
Author: Anup Dhokiya (@anup-dhokiya) - Lead Architect
"""

import logging
import json
from typing import Callable, Dict, Any, Optional
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("sentinelgrid.asgi")


class SentinelGridASGIMiddleware(BaseHTTPMiddleware):
    """
    Drop-in Starlette/FastAPI middleware for synchronous or asynchronous request inspection.
    Buffers request stream safely without stream exhaustion.
    """

    def __init__(
        self,
        app,
        sentinelgrid_url: str = "http://127.0.0.1:8000/v1/inspect",
        website_id: str = "default-site",
        timeout_seconds: float = 0.05,  # 50ms strict budget
        fail_open: bool = True,
        max_body_bytes: int = 65536     # Inspect up to first 64KB
    ):
        super().__init__(app)
        self.sentinelgrid_url = sentinelgrid_url
        self.website_id = website_id
        self.timeout_seconds = timeout_seconds
        self.fail_open = fail_open
        self.max_body_bytes = max_body_bytes
        self.http_client = httpx.AsyncClient(
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=200),
            timeout=httpx.Timeout(self.timeout_seconds, connect=0.02)
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Extract client IP respecting reverse proxy chain
        client_ip = (
            request.headers.get("x-real-ip")
            or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "127.0.0.1")
        )

        # 2. Buffer request body safely without exhausting stream
        body_bytes = await request.body()
        body_sample = body_bytes[:self.max_body_bytes].decode("utf-8", errors="replace")

        # 3. Construct inspection payload
        payload = {
            "website_id": self.website_id,
            "method": request.method,
            "path": request.url.path,
            "query_params": str(request.url.query),
            "body": body_sample,
            "headers": dict(request.headers),
            "client_ip": client_ip
        }

        # 4. Evaluate with SentinelGrid core engine
        try:
            resp = await self.http_client.post(self.sentinelgrid_url, json=payload)
            if resp.status_code == 200:
                decision = resp.json()
                action = decision.get("action", "ALLOW")

                if action == "BLOCK":
                    event_id = decision.get("event_id", "N/A")
                    rule = decision.get("rule_triggered", "SECURITY-POLICY")
                    logger.warning(
                        "SentinelGrid BLOCKED request: ip=%s path=%s rule=%s event_id=%s",
                        client_ip, request.url.path, rule, event_id
                    )
                    block_html = (
                        f"<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
                        f"<body style='font-family:sans-serif;padding:40px;text-align:center;'>"
                        f"<h2>403 Forbidden - Request Blocked by SentinelGrid WAAP</h2>"
                        f"<p>Malicious signature or policy violation detected.</p>"
                        f"<p style='color:#666;font-family:monospace;font-size:12px;'>Event ID: {event_id} | Rule: {rule}</p>"
                        f"</body></html>"
                    )
                    return Response(
                        content=block_html,
                        status_code=403,
                        media_type="text/html",
                        headers={
                            "X-SentinelGrid-Action": "BLOCK",
                            "X-SentinelGrid-Event-ID": event_id,
                            "X-SentinelGrid-Rule": rule
                        }
                    )
        except Exception as exc:
            if not self.fail_open:
                logger.error("SentinelGrid unreachable and fail_open=False. Aborting request: %s", exc)
                return Response(content="503 Service Unavailable: Security Verification Offline", status_code=503)
            logger.debug("SentinelGrid fail-open triggered (allowing request): %s", exc)

        # 5. Pass clean request to origin application
        response = await call_next(request)
        return response
