"""
SentinelGrid WSGI Middleware for Django & Flask
Synchronous in-line inspection with input buffer rewinding and urllib3 connection pooling.
Author: SentinelGrid Architecture Core Team
"""

import io
import json
import logging
import html
import urllib3
from typing import Dict, Any, Optional

logger = logging.getLogger("sentinelgrid.wsgi")


class SentinelGridWSGIMiddleware:
    """
    Drop-in WSGI middleware for Flask, Django, and Gunicorn/uWSGI stacks.
    Rewinds wsgi.input stream to guarantee multipart/form-data compatibility.
    """

    def __init__(
        self,
        app,
        sentinelgrid_url: str = "http://127.0.0.1:8000/v1/inspect",
        website_id: str = "default-site",
        timeout_seconds: float = 0.05,
        fail_open: bool = True
    ):
        self.app = app
        self.sentinelgrid_url = sentinelgrid_url
        self.website_id = website_id
        self.timeout_seconds = timeout_seconds
        self.fail_open = fail_open
        self.http_pool = urllib3.PoolManager(
            maxsize=50,
            timeout=urllib3.Timeout(total=self.timeout_seconds)
        )

    def __call__(self, environ, start_response):
        # 1. Capture Client IP
        client_ip = (
            environ.get("HTTP_X_REAL_IP")
            or environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
            or environ.get("REMOTE_ADDR", "127.0.0.1")
        )

        # 2. Extract Request URI attributes
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        query = environ.get("QUERY_STRING", "")

        # 3. Buffer input stream and rewind
        content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        body_str = ""
        if content_length > 0:
            raw_body = environ["wsgi.input"].read(content_length)
            body_str = raw_body[:65536].decode("utf-8", errors="replace")
            # Rewind stream for downstream framework
            environ["wsgi.input"] = io.BytesIO(raw_body)

        # 4. Extract HTTP Headers
        headers = {}
        for k, v in environ.items():
            if k.startswith("HTTP_"):
                header_name = k[5:].replace("_", "-").lower()
                headers[header_name] = v

        payload = {
            "website_id": self.website_id,
            "method": method,
            "path": path,
            "query_params": query,
            "body": body_str,
            "headers": headers,
            "client_ip": client_ip
        }

        # 5. In-line inspect
        try:
            encoded_body = json.dumps(payload).encode("utf-8")
            resp = self.http_pool.request(
                "POST",
                self.sentinelgrid_url,
                body=encoded_body,
                headers={"Content-Type": "application/json"}
            )
            if resp.status == 200:
                data = json.loads(resp.data.decode("utf-8"))
                if data.get("action") == "BLOCK":
                    event_id = data.get("event_id", "N/A")
                    rule = data.get("rule_triggered", "POLICY-BLOCK")
                    safe_event_id = html.escape(str(event_id))
                    safe_rule = html.escape(str(rule))
                    block_body = (
                        f"<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
                        f"<body style='font-family:sans-serif;padding:40px;text-align:center;'>"
                        f"<h2>403 Forbidden - Request Blocked by SentinelGrid WAAP</h2>"
                        f"<p>Malicious signature or policy violation detected.</p>"
                        f"<p style='color:#666;font-family:monospace;font-size:12px;'>Event ID: {safe_event_id} | Rule: {safe_rule}</p>"
                        f"</body></html>"
                    ).encode("utf-8")
                    start_response("403 Forbidden", [
                        ("Content-Type", "text/html"),
                        ("Content-Length", str(len(block_body))),
                        ("X-SentinelGrid-Action", "BLOCK"),
                        ("X-SentinelGrid-Event-ID", event_id),
                        ("X-SentinelGrid-Rule", rule)
                    ])
                    return [block_body]
        except Exception as exc:
            if not self.fail_open:
                err_msg = b"503 Service Unavailable: Security Inspection Failure"
                start_response("503 Service Unavailable", [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", str(len(err_msg)))
                ])
                return [err_msg]
            logger.debug("SentinelGrid fail-open (allowing request): %s", exc)

        return self.app(environ, start_response)
