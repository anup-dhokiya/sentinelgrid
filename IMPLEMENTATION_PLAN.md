# SentinelGrid — Comprehensive Implementation Plan & Work Processor (WAAP Elevation)

> **Platform Paradigm**: AI-Assisted Web Application & API Protection (WAAP) with Runtime Security, Behavioral Threat Detection, and Safe Reversible Automation.  
> **Global Legal Guarantee**: Strictly defensive, zero offensive countermeasures ("no hack-back"), data minimization, and fully compliant across global jurisdictions (GDPR, CCPA, India DPDP Act 2023, CFAA, Wassenaar Arrangement).

---

## 1. Master Milestone Overview

| Milestone | Deliverable | Order | Priority | Test / Verification Gate |
|---|---|:---:|:---:|---|
| **M1** | Technical Design Document (TDD v2.0) & Architecture Specifications | 1 | Critical | Complete specs for WAAP, API Discovery, Ed25519, and Legal Compliance approved. |
| **M2** | Repository, Environment & Docker Orchestration | 2 | Critical | Multi-container stack (PostgreSQL 16, Redis 7, RabbitMQ 3.12) boots clean with healthchecks. |
| **M3** | PostgreSQL Data Layer, Models & Tenant Isolation | 3 | Critical | 100% pass on cross-tenant isolation tests including new `api_endpoints` and `policy_simulations`. |
| **M4** | Shared Schemas, Data Contracts & Serialization | 4 | Critical | JSON Schema validation suite passes against all sample payloads & OpenAPI fixtures. |
| **M5** | Local Security Engine: Normalizer & Full OWASP WAF | 5 | Critical | 100% detection on SQLi, XSS, Path Traversal, SSRF, XXE, Deserialization, Prototype Pollution. |
| **M6** | Rate Limiter, Reputation Cache & Local Decision Pipeline | 6 | Critical | Token bucket enforcement; local allow/monitor/challenge/block pipeline verified. |
| **M7** | Cloud Ingestion API, RabbitMQ Broker & Event Workers | 7 | Critical | Benchmark 1,000+ events/sec; zero event loss; dead-letter queue recovery. |
| **WAAP-1** | In-Line OpenAPI 3.0/3.1 Contract Validator & Route Trie | 8 | Critical | In-line validation runs in $< 1.5\text{ms}$; shadow/zombie APIs detected and cataloged. |
| **WAAP-2** | Outbound Response DLP Scanner & File Upload Inspector | 9 | High | Response DLP scans credit cards (Luhn-verified), SSNs, JWTs; file magic byte check. |
| **M8** | Threat Intelligence Aggregator & Indicator Feeds | 10 | High | Indicator provenance, TTL expiration, and cross-site indicator propagation. |
| **M9** | Incident Correlation & Reversible Response Engine | 11 | High | Multi-event grouping into incidents; explainable mitigation cards with blast-radius check. |
| **WAAP-BOT**| Bot & Account-Abuse Detection (ATO, Stuffing, Scrapers) | 12 | High | Credential stuffing detection; client-side Proof-of-Work (PoW) challenge validation. |
| **M10** | SaaS Management API & Auth Layer (JWT, RBAC, MFA) | 13 | High | Org signup, website provisioning, connector key rotation, and RBAC enforcement. |
| **M11** | Asymmetric Policy Signing (Ed25519) & Key Lifecycle | 14 | Critical | Ed25519 private key cloud signing & public key connector verification under tamper tests. |
| **WAAP-SIM**| Policy Simulation ("Dry Run"), Replay & 1-Click Rollback | 15 | Critical | 7-day historical traffic replay predicts false-positive impact; 1-click instant rollback $< 1\text{s}$. |
| **M12** | Next.js Operations Dashboard & WebSocket Feeds | 16 | High | API Inventory console, False-Positive Tuning workbench, Incident Triage, Live Map. |
| **M13** | AI Anomaly Pipeline: Feature Extraction & Baselines | 17 | High | 7-feature sliding window calculation; rolling baseline store per site. |
| **M14** | AI Anomaly Detection: Isolation Forest & Scorer | 18 | High | Measured precision/recall; feature attribution explainability reports (SHAP). |
| **WAAP-GENAI**| GenAI Application Security Module (Prompt Injection) | 19 | Strategic | In-line prompt injection defense, system prompt leak guard, and agent tool-call authorization. |
| **WAAP-SIEM**| Enterprise SIEM & Perimeter Firewall Exporter | 20 | High | Splunk HEC, Syslog CEF, and pfSense / Cisco FMC dynamic URL Table blocklist feeds. |
| **M16** | Connector Expansion (PHP, WordPress, Node.js) | 21 | High | Parity across PHP, WordPress, Express, and local reverse proxy agent. |
| **WAAP-REPLAY**| Continuous Attack Replay & Security Regression Testing | 22 | Critical | Automated regression runner evaluates 10,000+ vectors in isolated test sandbox. |
| **M17** | Security Hardening, Penetration Testing & Chaos Recovery | 23 | Critical | ReDoS immunity, cloud outage fail-open resilience, memory leak audit, legal compliance audit. |
| **M18** | Production Hardening, CI/CD & Deployment Readiness | 24 | Critical | Automated GitHub Actions pipeline, database migration validation, prod release. |

---

## 2. Standard Engineering Process Per Milestone

```
[1. Requirements & Spec Review]
              ↓
[2. Interface & Schema Contracts]
              ↓
[3. Core Logic Implementation]
              ↓
[4. Unit Testing (Target >= 90% coverage)]
              ↓
[5. Security, Regression & Legal Boundary Testing]
              ↓
[6. Documentation & Verification Sign-Off]
```

**Never proceed to the next milestone until the verification criteria of the current milestone are fully satisfied.**

---

## 3. Seven Phased Roadmap

### Phase 1: Reliable Core (Weeks 1-2)
- Milestones M1, M2, M3, M4, M5, M6.
- Deliverables: PostgreSQL schema with partitions, request normalizer, full OWASP WAF (SQLi, XSS, Path Traversal, SSRF, XXE, Deserialization, Prototype Pollution), Ed25519 signing, and tenant isolation tests.

### Phase 2: API Protection & Contract Enforcement (Weeks 3-4)
- Milestones WAAP-1, WAAP-2, M7, M10.
- Deliverables: In-line OpenAPI 3.0/3.1 validator, shadow/zombie API discovery, outbound response DLP scanner, file upload inspector, and 1,000 events/sec ingestion pipeline.

### Phase 3: Safe Operations, Simulation & Instant Rollback (Weeks 5-6)
- Milestones WAAP-SIM, M11, M12.
- Deliverables: False-positive review workbench, historical traffic replay simulation, instant 1-click rollback, Next.js API inventory UI, and live WebSocket feed.

### Phase 4: Application Awareness & RASP-Lite (Weeks 7-8)
- Milestones M9, WAAP-BOT.
- Deliverables: In-app runtime execution context hooks (routes, auth status, unhandled 500s), credential stuffing / scraper detection, and Proof-of-Work client challenge.

### Phase 5: Automated Investigation & Safe Response (Weeks 9-10)
- Milestones M8, M9, WAAP-SIEM.
- Deliverables: Explainable reversible response with blast-radius estimation and auto-expiry TTLs, pfSense / Cisco FMC dynamic URL Table feed, and Splunk/Syslog exporters.

### Phase 6: Continuous Validation via Attack Replay (Weeks 11-12)
- Milestones WAAP-REPLAY, M13, M14.
- Deliverables: Continuous attack regression testing harness, 7-D sliding window feature extraction, Isolation Forest behavioral anomaly detection with SHAP explainability.

### Phase 7: Enterprise Integrations, GenAI & Production Release (Weeks 13-14)
- Milestones WAAP-GENAI, M16, M17, M18.
- Deliverables: GenAI prompt injection defense, PHP/WordPress/Node connector parity, compliance reporting (PCI-DSS 4.0, SOC 2, HIPAA), penetration testing, and production release.
