# SentinelGrid WAAP // Master Integration & Setup Guide
**Document ID:** SG-INTEGRATION-2026-V1  
**Classification:** Systems Engineering / Edge Deployment Manual  
**Applies To:** Python (ASGI/WSGI), Node.js (Express/Next.js), Nginx, Go, Cloudflare Workers, Vercel Edge  

---

## 1. Architectural Overview

SentinelGrid operates as an ultra-low latency (<1.5ms) security inspection and telemetry plane. Third-party applications integrate with SentinelGrid using one of two topologies:

- **Mode A: In-Line Synchronous Enforcement (Recommended)**: The ingress proxy or application middleware dispatches incoming HTTP metadata to `POST /v1/inspect`. If malicious, SentinelGrid returns `HTTP 403 BLOCK` with threat forensics. If clean, SentinelGrid returns `HTTP 200 ALLOW` with an Ed25519 cryptographic token.
- **Mode B: Asynchronous Observation Mirror**: Traffic is mirrored to SentinelGrid for passive telemetry, shadow API mapping, and behavioral analysis without blocking the critical path.

```
Client Request
      │
      ▼
┌───────────────────────────────┐
│     Ingress / Edge Tier       │ ── (Vercel Edge, Nginx, Cloudflare, Envoy)
└───────────────┬───────────────┘
                │
                │  (1) POST /v1/inspect (<1.5ms latency budget)
                ▼
┌───────────────────────────────┐
│   SentinelGrid WAAP Kernel    │
│  ├── SmartParse AST Engine    │
│  ├── IP Access Control (ACL)  │
│  ├── OpenAPI Schema Enforcer  │
│  └── Ed25519 Cryptographic Signer
└───────────────┬───────────────┘
                │
       ┌────────┴────────┐
       ▼                 ▼
[Action: BLOCK]   [Action: ALLOW]
  HTTP 403 Drop     HTTP 200 + Ed25519 Origin Seal
  Logged to SIEM    Forwarded to Protected Origin
```

---

## 2. Integration by Environment

### Option A: Vercel / Next.js Edge Middleware
Add `middleware.js` (or `middleware.ts`) to the root of your Next.js or Vercel application:

```javascript
import { NextResponse } from 'next/server';

const SENTINELGRID_ENDPOINT = process.env.SENTINELGRID_URL || 'https://sentinelgrid-one.vercel.app/v1/inspect';
const WEBSITE_ID = process.env.SENTINELGRID_SITE_ID || 'site-production-edge';

export async function middleware(request) {
  const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || '127.0.0.1';
  const path = request.nextUrl.pathname;
  const method = request.method;

  try {
    const payload = {
      website_id: WEBSITE_ID,
      method: method,
      path: path,
      client_ip: clientIp,
      headers: {
        'user-agent': request.headers.get('user-agent') || '',
        'host': request.headers.get('host') || ''
      }
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1200); // 1.2s circuit breaker

    const res = await fetch(SENTINELGRID_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (res.ok) {
      const decision = await res.json();
      if (decision.action === 'BLOCK') {
        return new NextResponse(
          `<!DOCTYPE html><html><body style="background:#0D1117;color:#F0F6FC;font-family:system-ui;padding:40px;text-align:center;">
             <h1 style="color:#F85149;">403 Forbidden // Threat Intercepted</h1>
             <p>Access quarantined by SentinelGrid WAAP. Incident ID: ${decision.event_id}</p>
           </body></html>`,
          { status: 403, headers: { 'Content-Type': 'text/html' } }
        );
      }
    }
  } catch (err) {
    // Fail-open: upstream network errors never break user availability
    console.error('SentinelGrid WAAP bypass (fail-open):', err);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

### Option B: Nginx Reverse Proxy (Any Language: PHP, Go, Ruby, Java)
In your `/etc/nginx/sites-available/default` configuration:

```nginx
server {
    listen 80;
    server_name app.company.internal;

    location / {
        # Sub-request inspection before serving upstream
        auth_request /_sentinel_inspect;
        auth_request_set $sentinel_status $upstream_status;

        proxy_pass http://localhost:3000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location = /_sentinel_inspect {
        internal;
        proxy_pass http://127.0.0.1:8000/v1/inspect;
        proxy_pass_request_body on;
        proxy_set_header Content-Type "application/json";
    }

    error_page 403 = @sentinel_blocked;
    location @sentinel_blocked {
        default_type text/html;
        return 403 '<h1 style="color:#F85149">403 Forbidden: Access Quarantined by SentinelGrid WAAP</h1>';
    }
}
```

---

### Option C: Python ASGI Middleware (FastAPI / Starlette)
```python
from fastapi import FastAPI, Request
from starlette.responses import HTMLResponse
import httpx

app = FastAPI()

SENTINEL_URL = "http://127.0.0.1:8000/v1/inspect"

@app.middleware("http")
async def sentinelgrid_waf_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            resp = await client.post(SENTINEL_URL, json={
                "website_id": "site-python-core",
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "headers": dict(request.headers)
            })
            if resp.status_code == 200 and resp.json().get("action") == "BLOCK":
                return HTMLResponse("<h1>403 Forbidden: Request Blocked by SentinelGrid</h1>", status_code=403)
    except Exception as e:
        pass # Fail-open: application continues uninterrupted

    return await call_next(request)
```

---

### Option D: Node.js / Express Middleware
```javascript
const express = require('express');
const axios = require('axios');
const app = express();

const SENTINEL_URL = 'http://127.0.0.1:8000/v1/inspect';

app.use(async (req, res, next) => {
  try {
    const verdict = await axios.post(SENTINEL_URL, {
      website_id: 'site-express-api',
      method: req.method,
      path: req.path,
      client_ip: req.ip || req.connection.remoteAddress,
      headers: req.headers
    }, { timeout: 1000 });

    if (verdict.data.action === 'BLOCK') {
      return res.status(403).send('<h1>403 Forbidden: Dropped by SentinelGrid WAAP</h1>');
    }
  } catch (err) {
    // Fail-open
  }
  next();
});
```

---

## 3. Verifying the Connection

1. Send a clean request to your protected domain:
   ```bash
   curl -I https://your-site.com/
   # Expect HTTP 200 OK
   ```
2. Send a simulated adversarial probe:
   ```bash
   curl -X POST -d "user=admin' OR 1=1--" https://your-site.com/login
   # Expect HTTP 403 Forbidden (Blocked in < 1.5ms)
   ```
3. Open your **SentinelGrid Console** (`/#livetraffic`) to view the live request stream with zero delay.
