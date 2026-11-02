# SentinelGrid — Next-Gen Web Application & API Protection (WAAP) Platform

[![Architecture](https://img.shields.io/badge/Architecture-Application--Aware%20WAAP-blue.svg)](docs/architecture/overview.md)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2016%20Partitioned-green.svg)](docs/database/schema.md)
[![API](https://img.shields.io/badge/API-OpenAPI%203.1-orange.svg)](docs/api/openapi.yaml)
[![Team Plans](https://img.shields.io/badge/Team%20Plans-9%20Separated%20Streams-purple.svg)](plans/00_MASTER_COORDINATION_AND_FLOWS.md)
[![Team Guide](https://img.shields.io/badge/Team%20Guide-4%20Developer%20Division-teal.svg)](docs/TEAM_COLLABORATION_AND_REQUIREMENTS.md)
[![Compliance](https://img.shields.io/badge/Legal-GDPR%20%7C%20CFAA%20%7C%20DPDP%20Compliant-success.svg)](docs/security/legal-and-compliance.md)
[![Positioning](https://img.shields.io/badge/Positioning-SentinelGrid%20vs%20pfSense%20%7C%20Cisco%20%7C%20Check%20Point-informational.svg)](docs/security/competitive-positioning.md)
[![Author](https://img.shields.io/badge/Author-anup--dhokiya-181717.svg?logo=github)](https://github.com/anup-dhokiya)

> **Author & Lead Architect**: [Anup Dhokiya](https://github.com/anup-dhokiya) ([@anup-dhokiya](https://github.com/anup-dhokiya))
> **Contact**: anupdhokiya0@gmail.com

SentinelGrid is an **AI-assisted Web Application and API Protection (WAAP)** platform that combines deep application-aware request inspection, automated API discovery, strict OpenAPI schema validation, explainable behavioral anomaly detection, and safe, reversible automated response.

---

## 0. About the Author

| Field | Detail |
|---|---|
| **Name** | Anup Dhokiya |
| **GitHub** | [@anup-dhokiya](https://github.com/anup-dhokiya) |
| **Email** | anupdhokiya0@gmail.com |
| **Role** | Lead Architect & Project Owner |
| **Project** | SentinelGrid WAAP Platform |

---

## 1. Strategic Differentiation: Where SentinelGrid Stands Out

Unlike perimeter network firewalls (**pfSense**, **Cisco Secure Firewall**, **Check Point Quantum**) that operate at the network packet layer (L3/L4, routing, NAT, VPN, Snort IPS), SentinelGrid operates **above and alongside** them at the application and API layer (L7):

1. **Application-Aware Attack Detection**: Correlates incoming HTTP requests with internal application context (route dispatch, authenticated user state, object authorization context, and unhandled 500 exceptions).
2. **Measurable False-Positive Reduction Workflow**: Tests candidate policies against historical sanitized traffic before deployment, predicts false-positive impact, and supports instant 1-click automated rollbacks.
3. **Explainable, Reversible Automated Response**: Actions provide clear evidentiary audit cards, blast-radius estimation, and auto-expiring TTLs with zero offensive counter-attacks ("no hack-back").
4. **Continuous Validation via Attack Replay**: Continuous security regression testing harness evaluates thousands of attack and legitimate fixtures in an isolated test environment.
5. **Flexible Deployment with Local Enforcement**: Sub-5ms in-app connectors with local Ed25519-signed policy caches; cloud-managed, sovereign regional cloud, or air-gapped on-premise options.
6. **Perimeter Firewall Integration**: Exports dynamic threat blocklist feeds directly to pfSense (`pfBlockerNG` URL Table) and Cisco FMC to drop malicious packets at the network edge.

---

## 2. Team-Specific Implementation Plans (`plans/`)

The engineering roadmap is divided into **8 modular, team-owned work streams** located in [`plans/`](plans/):

| Document | Assigned Team | Primary Domain & Technical Scope |
|---|---|---|
| [`00_MASTER_COORDINATION_AND_FLOWS.md`](plans/00_MASTER_COORDINATION_AND_FLOWS.md) | Lead Architects & PM | Master sequence flows, cross-team API contracts, WAAP scope, and milestone timeline. |
| [`01_DATABASE_AND_TENANCY_TEAM.md`](plans/01_DATABASE_AND_TENANCY_TEAM.md) | Database & Storage Team | PostgreSQL 16 DDL, partitioned events, API endpoint inventory, policy simulation logs. |
| [`02_CORE_SECURITY_ENGINE_DATA_PLANE_TEAM.md`](plans/02_CORE_SECURITY_ENGINE_DATA_PLANE_TEAM.md) | Data Plane & WAF Team | Full OWASP Top 10, OpenAPI 3.0/3.1 validator, outbound DLP scanner, file upload inspector. |
| [`03_INGESTION_AND_MESSAGE_BROKER_TEAM.md`](plans/03_INGESTION_AND_MESSAGE_BROKER_TEAM.md) | Ingestion & Messaging Team | Ingestion API (`POST /v1/events/batch`), RabbitMQ queues, SIEM dispatch (Splunk/CEF/Syslog). |
| [`04_POLICY_AND_MANAGEMENT_API_TEAM.md`](plans/04_POLICY_AND_MANAGEMENT_API_TEAM.md) | Platform & Auth Team | Asymmetric Ed25519 signing, policy simulation dry-run engine, 1-click rollback, OpenAPI upload. |
| [`05_INCIDENTS_AND_THREAT_INTEL_TEAM.md`](plans/05_INCIDENTS_AND_THREAT_INTEL_TEAM.md) | Incident & Intel Team | Bot & Account-Abuse detection (credential stuffing, ATO), reversible actions with blast radius. |
| [`06_AI_AND_ANOMALY_DETECTION_TEAM.md`](plans/06_AI_AND_ANOMALY_DETECTION_TEAM.md) | AI & Machine Learning Team | API behavioral profiling, Isolation Forest, GenAI prompt injection & tool-call defense. |
| [`07_FRONTEND_AND_SOC_DASHBOARD_TEAM.md`](plans/07_FRONTEND_AND_SOC_DASHBOARD_TEAM.md) | Frontend & Product Team | API Discovery UI, False-Positive Simulation diff viewer, Incident Triage, Compliance reports. |
| [`08_DEVOPS_INFRASTRUCTURE_AND_TESTING_TEAM.md`](plans/08_DEVOPS_INFRASTRUCTURE_AND_TESTING_TEAM.md) | DevOps & Pen-Testing Team | Attack Replay & Security Regression harness, Docker Compose, CI/CD, legal compliance tests. |
| [`09_OPENROUTER_INTEGRATION_PLAN.md`](plans/09_OPENROUTER_INTEGRATION_PLAN.md) | AI Integration Team | OpenRouter free model catalog, "Use OpenRouter to..." task router, SOC AI chat assistant. |

---

## 3. Global Legal & Regulatory Compliance

SentinelGrid is engineered to be **strictly legal and compliant across all countries**:
- **Zero Offensive Countermeasures ("No Hack-Back")**: Strictly defensive; zero outbound port scans or retaliatory payloads under US CFAA 18 U.S.C. § 1030, UK Computer Misuse Act 1990, and India IT Act 2000.
- **Privacy by Design**: Passwords, tokens, credit cards, and PII are masked locally (`[REDACTED_SENSITIVE]`) before security events leave the application boundary (GDPR, CCPA, India DPDP Act 2023).
- **Cryptographic Export Compliance**: Uses standard, non-proprietary algorithms (Ed25519, AES-256-GCM, HMAC-SHA256) qualifying under Wassenaar Arrangement and US EAR 15 C.F.R. § 742.15(b) exemptions.
- For complete legal analysis, read [`docs/security/legal-and-compliance.md`](docs/security/legal-and-compliance.md).

---

## 4. Directory Structure

```text
sentinelgrid/
│
├── plans/                              # 8 Team-Specific Plans + Master Coordination Flow
│   ├── 00_MASTER_COORDINATION_AND_FLOWS.md
│   ├── 01_DATABASE_AND_TENANCY_TEAM.md
│   ├── 02_CORE_SECURITY_ENGINE_DATA_PLANE_TEAM.md
│   ├── 03_INGESTION_AND_MESSAGE_BROKER_TEAM.md
│   ├── 04_POLICY_AND_MANAGEMENT_API_TEAM.md
│   ├── 05_INCIDENTS_AND_THREAT_INTEL_TEAM.md
│   ├── 06_AI_AND_ANOMALY_DETECTION_TEAM.md
│   ├── 07_FRONTEND_AND_SOC_DASHBOARD_TEAM.md
│   └── 08_DEVOPS_INFRASTRUCTURE_AND_TESTING_TEAM.md
│
├── docs/                               # Formal Technical Specifications
│   ├── architecture/                   # High-level architecture & data/control plane flows
│   ├── database/                       # PostgreSQL 16 schema & init.sql with partitions
│   ├── api/                            # Complete OpenAPI 3.1 REST API specification
│   ├── connectors/                     # Connector adapter contract & Ed25519 verification
│   ├── security/
│   │   ├── legal-and-compliance.md     # Global Legal & Cross-Border Compliance Framework
│   │   ├── competitive-positioning.md  # SentinelGrid vs pfSense vs Cisco vs Check Point
│   │   ├── waf-and-scoring.md          # Full OWASP Top 10 rules & risk formula (R)
│   │   └── ai-anomaly-detection.md     # 7-D feature vectors & GenAI prompt guardrails
│   └── operations/                     # Queue topologies, Docker setup & disaster recovery
│
├── connectors/shared-spec/             # JSON Schemas (event, policy) & WAF rule format
├── shared/test-fixtures/               # Attack test suites (SQLi, XSS, Path Traversal, SSRF)
├── docker-compose.yml                  # Complete local development multi-container stack
├── .env.example                        # Documented environment configuration template
├── Makefile                            # Standardized build and test targets
├── IMPLEMENTATION_PLAN.md              # Authoritative 24-milestone master work processor
└── README.md                           # Master project guide (this document)
```

---

## 5. How to Start Implementation

When ready to begin coding:
1. Assign team leads to their corresponding documents in [`plans/`](plans/).
2. Review the cross-team sequence flows in [`plans/00_MASTER_COORDINATION_AND_FLOWS.md`](plans/00_MASTER_COORDINATION_AND_FLOWS.md).
3. Boot shared dependencies:
   ```bash
   cp .env.example .env
   docker compose up -d postgres redis rabbitmq
   ```
4. Teams **01 (Database)**, **02 (Security Core)**, and **08 (DevOps/Testing)** can begin **Phase 1 (Reliable Core)** simultaneously.

---

## 6. Author & Contributing

**Project Author**: [Anup Dhokiya](https://github.com/anup-dhokiya)
**GitHub**: [@anup-dhokiya](https://github.com/anup-dhokiya)
**Email**: anupdhokiya0@gmail.com

### Team Contribution Guide

```bash
# Clone the repo (once published on GitHub)
git clone https://github.com/anup-dhokiya/sentinelgrid.git
cd sentinelgrid

# Create your feature branch
git checkout -b feature/team02-owasp-waf

# Make changes, then commit
git add .
git commit -m "feat(team02): add SQLi detection engine with ReDoS protection"

# Push and open a PR against develop
git push origin feature/team02-owasp-waf
```

**Branch conventions:**
- `feature/<team-id>-<feature-name>` — new feature
- `fix/<team-id>-<bug-description>` — bug fix
- `docs/<topic>` — documentation updates

**PR rules:** All PRs require at least **1 review** from a team member outside your team before merging into `develop`.

---

*Built with ❤️ by [Anup Dhokiya](https://github.com/anup-dhokiya) and team.*
