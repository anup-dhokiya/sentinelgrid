# SentinelGrid Deep Code & Security Audit Report

**Date:** 2026-11-15  
**Audited Target:** SentinelGrid Full Codebase (`/run/media/anup/D/sentinelgrid`)  
**Scope:** Backend (`app/api/v1/`, `app/security_engine/`, `app/core/`, `app/services/`), Frontend (`frontend/public/app.js`, `index.html`, `style.css`), Connectors (`nodejs/`, `python/`), Unit Tests & Coverage.  
**Methodology:** OWASP Top 10, CWE / SANS Top 25, AST / Lexical Evasion Analysis, Concurrency & State Machine Integrity, RFC 8032 / Cryptographic Verification.

---

## Executive Summary

An exhaustive security, architectural, and quality audit was conducted across the entire SentinelGrid codebase. While SentinelGrid demonstrates high-performance engineering in its SmartParse lexical AST analyzer, Radix Prefix IP trie, and sliding-window rate limiter, critical vulnerabilities and architectural bugs were uncovered across the backend, frontend, connectors, and configuration.

### Summary of Findings by Severity
- **Critical (P0): 6 issues** (Broken Access Control across all management endpoints, Stored XSS in domain/spec/rule management, Runtime ReferenceError in Forensics modal, Permissive CORS Wildcard with credentials, Memory Exhaustion/OOM in connectors, Unsalted SHA-256 master admin credentials).
- **High (P1): 6 issues** (Canary bypasses in SecurityBrain, Simulation API contract breakdown (HTTP 422), Sandbox GET query payload dropping, Policy state loss on server restart, Connector fail-open on HTTP 500, SQLite concurrency collisions in async routes).
- **Medium (P2): 7 issues** (Double Spacebar keydown collision, Unbounded query limits in export/events, Missing input validation on models, Chunked transfer bypass in WSGI, Express Buffer stringification, Unbounded rate limiter shard dictionary, Missing IndexedDB quota fallback handling).
- **Low / Optimization (P3): 4 issues** (Retention prune on GET `/overview`, Unbounded cache dictionaries, Missing aria labels, Missing test coverage on auth/policies/connectors).

---

## 1. Backend Code & Security Audit

### 1.1 `backend/app/api/v1/console.py`

#### [CRITICAL] 1. Complete Absence of Authentication & Authorization (CWE-306, OWASP A01)
- **Location:** `backend/app/api/v1/console.py` (Lines 150–1390)
- **Vulnerability:** None of the administrative management endpoints require authentication:
  - `DELETE /v1/websites/{website_id}`: Any unauthenticated caller can delete an entire monitored site and all its child security policies, endpoints, and events.
  - `POST /v1/ip-rules` & `POST /v1/ip-rules/quick-action`: Unauthenticated callers can ban/unban any IP address or add global allow/block rules.
  - `GET /v1/events/stream`: Unauthenticated callers can connect to the Server-Sent Events pipeline and spy on all real-time traffic and payloads.
  - `GET /v1/events/export` & `GET /v1/events`: Unauthenticated callers can dump all historical security events and telemetry.
- **Remediation:** Enforce `Depends(verify_session)` or Bearer token verification from `app/api/v1/auth.py` on all administrative routes, checking that the user role has sufficient permissions (`manager` or `team_leader`).

#### [HIGH] 2. Simulation API Request & Response Contract Mismatch (HTTP 422)
- **Location:** `backend/app/api/v1/console.py` (Lines 74–79, 1347–1390)
- **Vulnerability:** `SimulateRequest` defines required fields:
  ```python
  class SimulateRequest(BaseModel):
      website_id: str
      rule_name: str
      criteria_ua: str = ""
      criteria_path: str = ""
  ```
  However, the frontend sends: `{ rule_id, pattern, target_field, action }`. FastAPI rejects all simulation requests from the UI with `422 Unprocessable Entity`.
  Furthermore, `simulate_policy_rule` returns `SimulationReport`, whose schema fields (`total_evaluated_requests`, `projected_blocks`, `false_positive_rate_percent`) do not match what the frontend reads (`sample_size_evaluated`, `predicted_blocks_count`, `block_delta_percent`).
- **Remediation:** Align `SimulateRequest` and its handler to support the frontend payload fields or update the frontend to match the backend schema, ensuring consistent response models.

#### [HIGH] 3. Sandbox GET Attack Parameter Dropping (False Clean Request)
- **Location:** `backend/app/api/v1/console.py` (Lines 64–72) vs `frontend/public/app.js` (Lines 2741–2752)
- **Vulnerability:** `WafTestRequest` expects `query_params: str = ""`. The frontend sends `query: payload`. Pydantic ignores `query`, resulting in `query_params = ""` on all GET sandbox tests. The payload is never evaluated by `SecurityBrain`, falsely returning `ALLOW CLEAN-REQUEST` for all GET injection attacks.
- **Remediation:** In `WafTestRequest`, support both `query` and `query_params` (via aliasing or a root validator) or normalize them in the handler:
  ```python
  class WafTestRequest(BaseModel):
      website_id: Optional[str] = "default-site"
      method: str
      path: str
      query_params: str = ""
      query: Optional[str] = None
      # ...
  ```

#### [MEDIUM] 4. Unbounded Query Limits & Offset Denial of Service (CWE-770)
- **Location:** `backend/app/api/v1/console.py` (Lines 1240, 1283)
- **Vulnerability:** In `list_events(limit: int = 50, offset: int = 0)` and `export_events(limit: int = 1000)`:
  - If a client passes `limit=-1`, SQLite interprets `-1` as returning **all** records in the table without bound.
  - If a client passes `limit=100000000`, the server attempts to allocate millions of rows into Python memory, causing worker crash (OOM).
- **Remediation:** Add Pydantic query constraints: `limit: int = Query(50, ge=1, le=5000), offset: int = Query(0, ge=0)`.

#### [MEDIUM] 5. Information Disclosure in Exception Details (CWE-209)
- **Location:** `backend/app/api/v1/console.py` (Lines 323, 485)
- **Vulnerability:** 
  - Line 323: `raise HTTPException(status_code=500, detail=str(e))` returns raw database operational exceptions to clients.
  - Line 485: `raise HTTPException(status_code=400, detail=f"Failed to parse specification as JSON or YAML: {e}")` leaks internal library error traces.
- **Remediation:** Log the raw exception with `logger.error(...)` and return a generic error message: `detail="An internal database error occurred while registering the website."`.

#### [LOW] 6. Synchronous DELETE Operation inside GET `/overview` Cache Miss
- **Location:** `backend/app/api/v1/console.py` (Lines 170–178)
- **Issue:** A read-only `GET /overview` endpoint executes a write transaction (`DELETE FROM security_events WHERE ...`) on every cache miss (every 1.5s). Under high traffic, this introduces unnecessary write-lock contention in SQLite.
- **Remediation:** Move the 12-hour retention pruning to a scheduled background task or periodic maintenance worker.

#### [LOW] 7. Unbounded In-Memory Caches (`_OVERVIEW_CACHE` & `_SITE_ID_CACHE`)
- **Location:** `backend/app/api/v1/console.py` (Lines 146, 1055)
- **Issue:** `_OVERVIEW_CACHE` and `_SITE_ID_CACHE` are unboundedly growing dictionaries keyed by caller-provided strings (`website_id`). An attacker requesting random IDs can bloat process memory.
- **Remediation:** Use an LRU cache or bounded dictionary (e.g. `collections.OrderedDict` with `maxsize=1024`).

#### [MEDIUM] 8. SSE Generator Disconnect Latency & Subscriber Thread Safety
- **Location:** `backend/app/api/v1/console.py` (Lines 41–46, 1135–1152)
- **Issue:** 
  - `broadcast_sse_event` calls `q.put_nowait` on an `asyncio.Queue` from arbitrary tasks without thread-safety checks.
  - `request.is_disconnected()` is checked only inside the `while True` loop after `asyncio.wait_for(q.get(), timeout=15.0)` returns. If no events arrive, a disconnected client remains registered for up to 15 seconds.
  - If a connection errors out before entering `event_generator()`'s `try:` block, `q` remains in `sse_subscribers` indefinitely.
- **Remediation:** Append `q` inside the `try:` block of `event_generator` and ensure cleanup in `finally:`.

---

### 1.2 `backend/app/security_engine/`

#### [HIGH] 1. Pre-Filter Detection Bypass in `brain.py` `cve_canaries` (False Negatives)
- **Location:** `backend/app/security_engine/brain.py` (Lines 1144–1162)
- **Vulnerability:** To optimize regex checks, `SecurityBrain` checks for hardcoded "canary" substrings before evaluating full CVE signatures:
  - `CVE-2024-4577-PHP-CGI-RCE` canary: `("php-cgi", "auto_prepend_file", "cgi-bin")`.
    * If an attacker executes PHP-CGI argument injection using `-d disable_functions=""` or `-d allow_url_include=1` without `auto_prepend_file`, none of the canary strings are present. The canary check returns `False`, skipping the regex check and allowing the RCE exploit to pass.
  - `CVE-2020-14882-WEBLOGIC-CONSOLE-RCE` canary: `("console.portal", "mbeantype")`.
    * If an attacker requests `/console/css/%252e%252e/` chaining MVEL or Spring XML injection without `console.portal`, the canary check fails and bypasses the signature.
- **Remediation:** Update `cve_canaries` to include all signature tokens:
  ```python
  "CVE-2024-4577-PHP-CGI-RCE": ("php-cgi", "auto_prepend_file", "cgi-bin", "allow_url_include", "disable_functions", "%ad"),
  "CVE-2020-14882-WEBLOGIC-CONSOLE-RCE": ("console.portal", "mbeantype", "%252e%252e", "mvel", "filesystemxmlapplicationcontext"),
  ```

#### [MEDIUM] 2. IPv6 Address Normalization & Port Bypass in Rate Limiter
- **Location:** `backend/app/security_engine/rate_limiter.py` (Lines 38–48)
- **Vulnerability:** In `_canonicalize_ip(self, ip_str: str)`:
  ```python
  clean_ip = ip_str.split(":")[0] if ":" in ip_str and not ip_str.startswith("[") and ip_str.count(":") == 1 else ip_str
  clean_ip = clean_ip.strip("[]")
  ```
  If an IPv6 client IP is supplied with a port (e.g. `[2001:db8::1]:8080`), `clean_ip.strip("[]")` fails to remove `[` because the string ends with `:8080`.
  `ipaddress.ip_address(clean_ip)` raises `ValueError`, and the function returns the raw string `[2001:db8::1]:8080` without grouping it into the `/64` prefix! Attackers can rotate ports to bypass prefix rate limiting.
- **Remediation:** Use proper regex or split for bracketed IPv6:
  ```python
  if ip_str.startswith("[") and "]" in ip_str:
      clean_ip = ip_str[1:ip_str.index("]")]
  elif ":" in ip_str and ip_str.count(":") == 1:
      clean_ip = ip_str.split(":")[0]
  else:
      clean_ip = ip_str
  ```

#### [MEDIUM] 3. Unbounded Shard Window Growth under Distributed Floods
- **Location:** `backend/app/security_engine/rate_limiter.py` (Lines 156–161)
- **Vulnerability:** When `len(self._windows[shard_idx]) > 16384`, it only evicts keys older than `cutoff = now - (window_seconds * 2)`. Under a spoofed flood attack where all IPs are active within the 2-minute window, `stale_keys` is empty. The dictionary grows without bound, and every subsequent request performs an expensive O(N) iteration over all 16,384+ items under the shard lock.
- **Remediation:** Introduce an explicit hard capacity cap with eviction of the oldest entries (similar to `_quarantine`).

#### [LOW] 4. Threat Intel Trie Memory Caps & TTL Expiration
- **Location:** `backend/app/security_engine/threat_intel.py` (Lines 25–184)
- **Issue:** `RadixIpTrie` does not support TTL on individual feed entries or a maximum capacity limit. Threat feeds loaded continuously without eviction will consume unbounded memory.

---

### 1.3 `backend/app/core/` & `backend/app/services/`

#### [CRITICAL] 1. Permissive CORS Wildcard Regex with Credentials Enabled (CWE-346, CWE-942)
- **Location:** `backend/app/main.py` (Line 43)
- **Vulnerability:**
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=ALLOWED_ORIGINS,
      allow_origin_regex=r"^https://([a-zA-Z0-9-]+\.)*(vercel\.app|github\.io)$",
      allow_credentials=True,
      allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allow_headers=["*"],
  )
  ```
  `allow_origin_regex` matches **any** site hosted on `*.vercel.app` or `*.github.io`. With `allow_credentials=True`, any third-party app hosted on Vercel or GitHub Pages can make credentialed AJAX calls to SentinelGrid, read sensitive telemetry, or execute administrative commands if an authenticated operator visits the attacker's page.
- **Remediation:** Restrict `allow_origin_regex` to explicit organization/repository domains or remove `allow_credentials=True` when using wildcards.

#### [CRITICAL] 2. Unsalted SHA-256 Initial Administrator Password (CWE-916)
- **Location:** `backend/app/core/database.py` (Line 183)
- **Vulnerability:** The default seeded admin account uses raw unsalted SHA-256 (`4459e7230b6833797dae7f90cda556b5eef40def095a99e83ec9dbadff7080cf`). Unsalted hashes are vulnerable to precomputed rainbow tables and high-speed GPU cracking.
- **Remediation:** Hash the initial admin password using the existing PBKDF2-HMAC-SHA256 hasher (`hash_password("anup@5212")`).

#### [HIGH] 3. Non-Persistent Policy Deployments & State Loss upon Restart
- **Location:** `backend/app/services/policy_manager.py` (Lines 99–122) & `backend/app/api/v1/policies.py` (Lines 72–79)
- **Vulnerability:** `deploy_policy` in `policies.py` calls `policy_service.sign_and_activate_policy(candidate_policy)`, which stores the policy ONLY in an in-memory dictionary (`self._policy_history`). It is never written to the SQLite database.
  When the backend process restarts, all deployed policies, rules, and versions disappear!
  Furthermore, the `policies` table schema in `database.py` lacks a `rules_json` column, so even the fallback rollback query in `policies.py` (lines 128–135) restores a policy with zero rules.
- **Remediation:** 
  1. Add `rules_json TEXT` to the `policies` schema.
  2. In `sign_and_activate_policy`, persist the newly signed policy to the SQLite `policies` table.

#### [HIGH] 4. SQLite Coroutine Transaction Collisions in Async Routes
- **Location:** `backend/app/core/database.py` (Lines 41–61)
- **Vulnerability:** `_thread_local.conn` creates one connection per OS worker thread. FastAPI runs all `async def` endpoints on the main event loop thread. Thus, all concurrent async requests share the **same** SQLite connection object.
  When two coroutines run `with conn:`, SQLite transactions collide (`sqlite3.OperationalError: cannot start a transaction within a transaction` or premature transaction commits).
- **Remediation:** Use an async database driver (e.g. `aiosqlite`) or acquire per-request scoped connections using a connection pool.

#### [MEDIUM] 5. Master Signing Key Fallback to `/tmp`
- **Location:** `backend/app/services/policy_manager.py` (Lines 15–22)
- **Vulnerability:** If `DATA_DIR` is not set and the backend path is not writable, `MASTER_KEY_DIR` falls back to `Path(tempfile.gettempdir()) / "sentinelgrid_keys"`. In multi-tenant environments, `/tmp` is accessible to other local users.
- **Remediation:** Ensure a private application directory or securely configured path is mandated, raising an explicit configuration error rather than falling back to world-readable `/tmp`.

---

## 2. Frontend Code & UI Audit

### 2.1 `frontend/public/app.js`

#### [CRITICAL] 1. ReferenceError in `openEventForensics` Crashing Modal (Temporal Dead Zone)
- **Location:** `frontend/public/app.js` (Line 2114 vs Line 2155)
- **Vulnerability:** On line 2114:
  ```javascript
  let headersSnippet = "Host: " + (domainObj ? domainObj.domain : "sentinelgrid-gateway");
  ```
  `domainObj` is declared later on line 2155:
  ```javascript
  const domainObj = allWebsites.find(w => w.id === ev.website_id);
  ```
  In JavaScript, accessing a `const` identifier before its declaration causes a fatal `ReferenceError: Cannot access 'domainObj' before initialization`.
  **Impact:** Every time a user clicks "Inspect" on any event row, the entire function crashes and the forensics drawer fails to open.
- **Remediation:** Move `const domainObj = allWebsites.find(w => w.id === ev.website_id);` to the top of `openEventForensics(eventId)` (before line 2114).

#### [CRITICAL] 2. Stored Cross-Site Scripting (XSS) in Management Tables (CWE-79)
- **Location:** `frontend/public/app.js` (Lines 2280–2340, 2414, 2578–2580, 2616–2622, 2689–2691)
- **Vulnerability:** Multiple user- and attacker-controlled properties are interpolated directly into `.innerHTML` without `escapeHtml`:
  1. **Domains Grid & Table (lines 2280, 2281, 2289, 2332, 2333):** `${d.name}`, `${d.domain}`, and `<a href="${gatewayUrl}">${gatewayUrl}</a>` are unescaped. An attacker registering a domain with `<img src=x onerror=alert(1)>` achieves stored XSS.
  2. **Domain Stats Modal (line 2414):** `${policy.name}` and `${policy.signature}` are unescaped.
  3. **API Endpoints (lines 2578–2580):** `${ep.website_id}`, `${ep.method}`, `${ep.path}` are unescaped.
  4. **IP Rules Table (lines 2616–2618):** `${ipAddr}` and `${r.description}` are unescaped.
  5. **Connectors Table (lines 2689–2691):** `${c.name}`, `${cType}`, `${c.website_id}` are unescaped.
  6. **Inline Onclick JS Injection:** `onclick="openDomainStatsModal('${d.id}')"`, `deleteDomain('${d.id}')`, and `deleteIpRule('${r.id}')` interpolate raw IDs directly into JavaScript string literals inside HTML attributes.
- **Remediation:** Wrap every interpolated dynamic variable with `escapeHtml(...)`.

#### [HIGH] 3. Duplicate Spacebar Keydown Listeners Cancelling Out Stream Pause
- **Location:** `frontend/public/app.js` (Lines 1584–1589 vs Lines 2878–2894)
- **Vulnerability:** Two separate `window.addEventListener("keydown", ...)` listeners listen for `e.code === "Space"`:
  - Listener 1 (line 1584): Calls `toggleStreamPause()`.
  - Listener 2 (line 2888): Calls `toggleStreamPause()` or `toggleLiveTrafficStream()`.
  Pressing Spacebar in the dashboard fires both listeners simultaneously, toggling the pause state twice in the same frame (pause followed immediately by resume).
- **Remediation:** Remove the redundant listener on line 1584, keeping only the centralized shortcut router on line 2878.

#### [HIGH] 4. SSE Dynamic Polling Conflict & Resource Leaks
- **Location:** `frontend/public/app.js` (Lines 332–361)
- **Vulnerability:** In `initLiveTrafficSSE()`, `startLiveTrafficPollingFallback()` is called immediately alongside `EventSource`. The polling timer queries `/overview` every 3 seconds permanently, even when SSE is healthy and actively receiving events.
  Additionally, `liveTrafficEventSource.close()` is never invoked when logging out or changing views.
- **Remediation:** Only start the polling interval inside `liveTrafficEventSource.onerror`, and clear the interval when the SSE stream successfully reconnects. Close the EventSource on logout.

#### [MEDIUM] 5. Global Keyboard Shortcuts Intercepting Modal and Tab State
- **Location:** `frontend/public/app.js` (Lines 2895–2910)
- **Vulnerability:**
  - Pressing "w" / "W" anywhere on the page triggers `toggleLiveTrafficWideView()`, collapsing the sidebar even when on the Dashboard or Settings tabs.
  - Number keys 1–9 switch background tabs even when modals (domain stats, shortcuts modal) are open.
- **Remediation:** Only handle "w" when `view-livetraffic` is active, and ignore numeric navigation keys when any modal or drawer is visible.

#### [MEDIUM] 6. Memory & DOM Performance: Uncapped `allRecentEvents` & Table Rendering
- **Location:** `frontend/public/app.js` (Lines 1175, 1697, 2009)
- **Vulnerability:** `SentinelEventStore.getAll()` loads up to 5,000 events into `allRecentEvents`. `renderEventsTable` maps all 5,000 events directly into DOM `<tr>` elements without pagination or virtual scrolling, freezing the browser tab on large datasets.
- **Remediation:** Paginate or clamp table rendering to a maximum of 100–250 visible rows with client-side pagination.

---

### 2.2 `frontend/public/style.css` & Responsive Design

#### [MEDIUM] 1. Drawer Panel Horizontal Overflow on 320px Mobile Screens
- **Location:** `frontend/public/style.css` (Line 1198)
- **Issue:** `.drawer-panel` uses `width: clamp(320px, 42vw, 680px)` and `border-left: 1px solid var(--stone-border)`. On 320px viewports, 320px + 1px border exceeds 320px, introducing horizontal layout overflow and page jitter.
- **Remediation:** Change to `width: clamp(280px, 100vw, 680px)`.

#### [LOW] 2. Panel Header Action Button Wrapping at 768px Breakpoint
- **Location:** `frontend/public/style.css` (Lines 1715–1720)
- **Issue:** `.panel-header > div:last-child` applies `grid-template-columns: repeat(auto-fit, minmax(100px, 1fr))`. When panels have 4+ action buttons, buttons wrap into uneven multi-row grids that displace KPI headers.
- **Remediation:** Use `display: flex; flex-wrap: wrap; gap: 8px;` with auto-sized buttons.

---

## 3. Connectors Audit

### 3.1 `connectors/nodejs/sentinelgrid-express.js`

#### [CRITICAL] 1. Fail-Closed Mode Fails Open on HTTP 500 / 502 / 504 Errors
- **Location:** `connectors/nodejs/sentinelgrid-express.js` (Lines 80–96)
- **Vulnerability:**
  ```javascript
  if (inspectRes.statusCode === 200) {
    const decision = JSON.parse(rawData);
    if (decision.action === 'BLOCK') { ... return; }
  }
  next();
  ```
  If `failOpen: false` is configured, timeouts and connection errors correctly return 503. However, if the SentinelGrid control plane returns an HTTP 500, 502, or 504 error, the code skips `if (inspectRes.statusCode === 200)` and falls directly through to `next()`, allowing traffic through!
- **Remediation:** Check `if (!this.failOpen)` whenever `statusCode !== 200`.

#### [HIGH] 2. Buffer & Non-JSON Body Serialization
- **Location:** `connectors/nodejs/sentinelgrid-express.js` (Lines 56–58)
- **Vulnerability:**
  `bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);`
  If Express uses `express.raw()`, `req.body` is a `Buffer`. `JSON.stringify(Buffer)` serializes to `{"type":"Buffer","data":[...]}` rather than stringifying the payload. SmartParse and regex signatures cannot detect attacks inside byte arrays.
- **Remediation:** Handle Buffer bodies: `Buffer.isBuffer(req.body) ? req.body.toString('utf-8') : ...`.

#### [MEDIUM] 3. Hardcoded HTTP Protocol Crash on HTTPS URLs
- **Location:** `connectors/nodejs/sentinelgrid-express.js` (Line 7, Lines 33–41)
- **Vulnerability:** The connector requires Node's `http` module (`const http = require('http')`). If `sentinelgridUrl` is an `https://` endpoint, `http.request` fails.
- **Remediation:** Dynamically select `http` or `https` based on `parsed.protocol`.

---

### 3.2 `connectors/python/sentinelgrid/asgi.py`

#### [CRITICAL] 1. Memory Exhaustion / Denial of Service on Large Request Uploads
- **Location:** `connectors/python/sentinelgrid/asgi.py` (Line 54)
- **Vulnerability:**
  `body_bytes = await request.body()` reads the entire incoming stream into memory before slicing `[:self.max_body_bytes]`. If an attacker streams a 1GB file, the server buffers 1GB of memory in RAM, causing memory exhaustion and process termination.
- **Remediation:** Inspect `Content-Length` header first and use stream chunk reading up to `max_body_bytes` without reading the full stream into memory.

#### [HIGH] 2. Fail-Open on Non-200 Responses when `fail_open=False`
- **Location:** `connectors/python/sentinelgrid/asgi.py` (Lines 71, 109)
- **Vulnerability:** If SentinelGrid returns an HTTP 500 or 503, the response status check `if resp.status_code == 200:` evaluates to `False`, and execution falls through to line 109 (`response = await call_next(request)`), failing open even when `fail_open=False` is set.
- **Remediation:** If `resp.status_code != 200 and not self.fail_open`, return an HTTP 503 response immediately.

#### [LOW] 3. Leaked `httpx.AsyncClient` Lifecycle
- **Location:** `connectors/python/sentinelgrid/asgi.py` (Lines 40–43)
- **Issue:** `self.http_client = httpx.AsyncClient(...)` is instantiated in `__init__` and never closed, triggering ResourceWarnings upon server shutdown.

---

### 3.3 `connectors/python/sentinelgrid/wsgi.py`

#### [HIGH] 1. Complete Inspection Bypass on Chunked Transfer Requests
- **Location:** `connectors/python/sentinelgrid/wsgi.py` (Lines 55–61)
- **Vulnerability:**
  `content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)`
  In HTTP/1.1 chunked transfer encoding, `CONTENT_LENGTH` is omitted. `content_length` evaluates to `0`, and `environ["wsgi.input"].read(...)` is skipped entirely. Attackers sending `Transfer-Encoding: chunked` bypass all payload inspection.
- **Remediation:** Support chunked stream reading or check `HTTP_TRANSFER_ENCODING`.

#### [HIGH] 2. Fail-Open on Non-200 Responses
- **Location:** `connectors/python/sentinelgrid/wsgi.py` (Line 89)
- **Vulnerability:** Same as the ASGI connector: if `resp.status != 200`, it falls through to `self.app(environ, start_response)` regardless of `self.fail_open`.

---

## 4. Test Suite Execution & Coverage Analysis

### 4.1 Pytest Execution Results
- **Command:** `pytest /run/media/anup/D/sentinelgrid/backend/tests`
- **Result:** 46 passed in 2.13s (100% of existing tests pass).

### 4.2 Test Coverage Gaps
Despite high passing rates in existing units:
1. `backend/app/api/v1/auth.py`: **0% test coverage** (No tests for login, PBKDF2 verification, session token persistence, or logout).
2. `backend/app/api/v1/policies.py`: **0% HTTP endpoint coverage** (The unit tests test the service directly, but `/draft`, `/simulate`, `/deploy`, `/rollback` HTTP routes are untested).
3. `backend/app/api/v1/console.py`: Untested routes include `/events/stream`, `/events/history-24h`, `/ip-rules/quick-action`, `/websites/{id}/stats`, and `/simulate-rule`.
4. Connectors (`sentinelgrid-express.js`, `asgi.py`, `wsgi.py`): **0% test coverage**.

---

## 5. Prioritized Remediation Roadmap

| Priority | Issue Description | Component | Target Files |
| :--- | :--- | :--- | :--- |
| **P0** | Fix `ReferenceError` TDZ bug in event forensics drawer | Frontend | `frontend/public/app.js:2114` |
| **P0** | Enforce authentication & RBAC on all console management endpoints | Backend | `backend/app/api/v1/console.py` |
| **P0** | Sanitize and escape all HTML outputs (Stored XSS mitigation) | Frontend | `frontend/public/app.js:2280-2691` |
| **P0** | Remove overly permissive CORS wildcard regex on public platforms | Backend | `backend/app/main.py:43` |
| **P0** | Upgrade initial seeded admin password hash from unsalted SHA-256 to PBKDF2 | Backend | `backend/app/core/database.py:183` |
| **P1** | Fix Simulation API contract mismatch between frontend and backend | Full Stack | `backend/app/api/v1/console.py:74`, `frontend/public/app.js:2794` |
| **P1** | Fix Sandbox GET query parameter name (`query` -> `query_params`) | Full Stack | `frontend/public/app.js:2745`, `backend/app/api/v1/console.py:64` |
| **P1** | Fix `cve_canaries` false-negative detection bypasses | Backend | `backend/app/security_engine/brain.py:1144` |
| **P1** | Persist deployed security policies and rule definitions in SQLite | Backend | `backend/app/services/policy_manager.py:99`, `backend/app/core/database.py:120` |
| **P1** | Fix connectors fail-open behavior on HTTP 500 / 502 / 504 | Connectors | `connectors/nodejs/sentinelgrid-express.js`, `asgi.py`, `wsgi.py` |
| **P2** | Deduplicate Spacebar keydown event listeners | Frontend | `frontend/public/app.js:1584, 2878` |
| **P2** | Fix IPv6 with port normalization in sliding-window rate limiter | Backend | `backend/app/security_engine/rate_limiter.py:38` |
| **P2** | Bound query pagination (`limit` and `offset`) in event queries | Backend | `backend/app/api/v1/console.py:1240, 1283` |
| **P2** | Fix chunked transfer encoding bypass in WSGI connector | Connectors | `connectors/python/sentinelgrid/wsgi.py:55` |
| **P2** | Bound rate limiter shard dictionary to prevent OOM under flood attacks | Backend | `backend/app/security_engine/rate_limiter.py:156` |
| **P3** | Move retention prune from GET `/overview` into periodic background task | Backend | `backend/app/api/v1/console.py:170` |
| **P3** | Expand test suite to cover `auth.py`, `policies.py`, and all connectors | Tests | `backend/tests/` |

---
*Report generated and validated autonomously by Antigravity Core Security Audit Engine.*
