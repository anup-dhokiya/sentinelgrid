# SentinelGrid — Next-Gen Web Application & API Protection (WAAP) Platform

[![Architecture](https://img.shields.io/badge/Architecture-Application--Aware%20WAAP-blue.svg)](docs/architecture/overview.md)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2016%20Partitioned-green.svg)](docs/database/schema.md)
[![API](https://img.shields.io/badge/API-OpenAPI%203.1-orange.svg)](docs/api/openapi.yaml)
[![Compliance](https://img.shields.io/badge/Legal-GDPR%20%7C%20CFAA%20%7C%20DPDP%20Compliant-success.svg)](docs/security/legal-and-compliance.md)
[![Security Core](https://img.shields.io/badge/WAAP%20Kernel-Ed25519%20%7C%20AST%20DFA-emerald.svg)](backend/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

SentinelGrid is an **autonomous, application-aware Web Application and API Protection (WAAP)** platform that combines deep lexical request inspection (AST + DFA), automated API schema discovery, strict OpenAPI contract enforcement, behavioral anomaly profiling, and reversible automated threat mitigation in under 1.5ms.

---

## 1. Core Engineering Capabilities

1. **In-Line Lexical Analysis (SmartParse AST + DFA)**: Replaces slow, catastrophic-backtracking regular expressions with a compiled deterministic finite automaton and abstract syntax tree parser for SQLi, XSS, SSRF, RCE, and Path Traversal detection.
2. **Autonomous API Discovery & Shadow API Radar**: Passively inventories API endpoints, flags undocumented / zombie routes, and enforces contract adherence against OpenAPI 3.0/3.1 specifications.
3. **Cryptographic Zero-Trust Seal (RFC 8032 Ed25519)**: Every verified clean request is signed with an asymmetric Ed25519 token, allowing upstream origins to verify that incoming traffic genuinely traversed the WAAP inspection kernel.
4. **Quarantined Offender Auto-Banning**: Automatically mitigates repetitive adversarial probes; repeat requests from banned CIDRs are dropped in under 0.15ms with high-priority edge alerts.
5. **Measurable False-Positive Reduction**: Evaluates candidate security policies against historical sanitized traffic before active deployment, predicting false-positive impact with instant rollback capabilities.
6. **24-Hour Non-Destructive Persistent Telemetry**: Security events stream via Server-Sent Events (SSE) into local IndexedDB storage, ensuring live operations data persists across page refreshes and tab switches.

---

## 2. System Architecture

```
Client Traffic
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

## 3. Directory Structure

```text
sentinelgrid/
├── backend/                            # FastAPI Security Engine & WAAP Kernel
│   ├── app/                            # Core inspection, crypto, rate limiting, and database
│   └── tests/                          # 46/46 Automated WAAP unit & integration test suite
├── connectors/                         # Drop-in integration adapters
│   ├── nginx/                          # Nginx auth_request and mirror configurations
│   ├── nodejs/                         # Express and Next.js middleware
│   └── python/                         # ASGI (FastAPI) and WSGI (Django/Flask) connectors
├── docs/                               # Formal Architecture & Integration Guides
│   ├── SETUP_AND_INTEGRATION_GUIDE.md  # Complete third-party site connection manual
│   ├── architecture/                   # Data plane and control plane design
│   └── security/                       # Legal, compliance, and OWASP rule specifications
├── frontend/public/                    # Web Operations & Telemetry Console
│   ├── index.html                      # Real-time SOC dashboard, live traffic stream & forensic drawer
│   ├── landing.html                    # Developer-first overview and interactive WAF lab
│   └── login.html                      # Security Operations authentication portal
├── vercel.json                         # Edge headers, CSP, HSTS, and rate limiters
└── README.md                           # Master project guide
```

---

## 4. Quickstart: Local Development Stack

### Prerequisites
- Python 3.11+
- Git

### Installation & Test Execution
```bash
# Clone the repository
git clone https://github.com/sentinelgrid/sentinelgrid.git
cd sentinelgrid

# Setup Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the full 46-test WAAP verification suite
python3 -m pytest backend/tests/unit/

# Launch the local management engine
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 5. Security & Regulatory Compliance

- **Defensive Operation**: Strictly defensive L7 filtering; zero offensive counter-attacks ("no hack-back") compliant with US CFAA, UK Computer Misuse Act, and international cyber security statutes.
- **Privacy by Design**: Sensitive headers, bearer credentials, and personal parameters are masked locally (`[REDACTED_SENSITIVE]`) before security events enter telemetry stores (GDPR and DPDP compliant).
- **Cryptographic Export Compliance**: Implements standard Ed25519 and HMAC-SHA256 non-proprietary algorithms qualifying under international export exemptions.

---

## 6. Architecture & Governance

SentinelGrid is maintained by the **SentinelGrid Security Architecture Core Team**.  
Contributions, issue reports, and security disclosures are welcome via standard GitHub Pull Requests and issue templates.

*Distributed under the Apache 2.0 Open Source License.*
