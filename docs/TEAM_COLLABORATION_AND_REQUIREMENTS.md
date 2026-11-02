# SentinelGrid — Team Collaboration Guide, Role Distribution, Skills Matrix & Requirements Specification

> **Platform**: SentinelGrid — AI-Assisted Web Application & API Protection (WAAP) Platform  
> **Repository Location**: `/run/media/anup/D/sentinelgrid`  
> **Team Size**: 4 Engineers (You + 3 Team Members)  
> **Target Timeline**: 8 Weeks across 4 Coordinated Phased Sprints

---

## 1. System Requirements & Laptop Environment Setup

To develop, run, and test SentinelGrid locally, each developer's laptop should meet the following baseline specifications:

### 1.1 Hardware Specifications
- **Processor**: 4+ Cores (Intel Core i5/i7/i9 10th Gen+, AMD Ryzen 5/7/9, or Apple Silicon M1/M2/M3/M4).
- **RAM**: Minimum **16 GB** (Recommended: 32 GB to run PostgreSQL, Redis, RabbitMQ, FastAPI backend, Celery workers, and Next.js frontend concurrently).
- **Disk Storage**: Minimum **30 GB free NVMe/SSD space** (for Docker images, PostgreSQL database partitions, and local Git repositories).

### 1.2 Operating System & Software Prerequisites
- **Operating System**: **Linux** (Ubuntu 22.04/24.04 LTS, Debian 12, or Arch Linux) or **Windows 11 with WSL2 (Ubuntu)**.
- **Runtimes & Tools**:
  | Software | Required Version | Purpose | Installation Command (Ubuntu/Debian) |
  |---|---|---|---|
  | **Python** | 3.11 or 3.12 | Backend API, Security Engine, Workers, AI Pipeline | `sudo apt install python3 python3-pip python3-venv` |
  | **Node.js** | 20 LTS | Next.js 14 SOC Dashboard & Frontend Tooling | `curl -fsSL https://deb.nodesource.com/setup_20.x \| sudo -E bash - && sudo apt install -y nodejs` |
  | **Docker & Compose** | Docker 24+ & Compose v2 | Orchestrating PostgreSQL 16, Redis 7, and RabbitMQ | `sudo apt install docker.io docker-compose-v2` |
  | **Git** | 2.40+ | Version control & collaboration | `sudo apt install git` |
  | **Make** | 4.3+ | Running standardized build & test commands | `sudo apt install make` |

---

## 2. Best Reference Repositories & Local Accelerators

To build SentinelGrid efficiently, the team has access to the best open-source reference implementations right inside the repository:

### 2.1 Cloned Reference Repositories (`sentinelgrid/references/`)
1. **OWASP Core Rule Set (CRS v4.0)** — [`coreruleset/coreruleset`](https://github.com/coreruleset/coreruleset)
   - *Local Cloned Path*: `/run/media/anup/D/sentinelgrid/references/coreruleset/rules`
   - *Role*: The global standard for WAF rules. Contains ready-to-use detection rules for SQLi (`REQUEST-942`), XSS (`REQUEST-941`), RCE (`REQUEST-932`), LFI (`REQUEST-930`), SSRF (`ssrf.data`), and Data Leakages (`RESPONSE-950`).
2. **Schemathesis** — [`schemathesis/schemathesis`](https://github.com/schemathesis/schemathesis)
   - *Role*: Property-based OpenAPI contract validation and automated regression testing.
   - *Install*: `pip install schemathesis`
3. **fastjsonschema** — [`horejsek/python-fastjsonschema`](https://github.com/horejsek/python-fastjsonschema)
   - *Role*: Compiles JSON schemas to native Python bytecode for sub-millisecond in-line request validation.
   - *Install*: `pip install fastjsonschema`
4. **Metlo & APIClarity** — [`metlolabs/metlo`](https://github.com/metlolabs/metlo) & [`openclarity/apiclarity`](https://github.com/openclarity/apiclarity)
   - *Role*: Architectural blueprints for passive API traffic discovery, shadow endpoint detection, and sensitive data leakage (DLP) filters.

---

## 3. Four-Developer Work Distribution & Ownership

The SentinelGrid architecture is divided into **4 distinct, autonomous developer tracks**:

```
                            [SentinelGrid WAAP Platform]
                                         │
        ┌───────────────────┬────────────┴───────┬───────────────────┐
        ▼                   ▼                    ▼                   ▼
  [Developer 1]       [Developer 2]        [Developer 3]       [Developer 4]
(Lead / Core WAAP   (Backend, Database   (Platform API, Auth, (Frontend Dashboard,
 & Data Plane)       & Ingestion Queue)   Signing & SIEM)      AI & Regression)
        │                   │                    │                   │
  • Normalizer        • PostgreSQL 16      • JWT / MFA Auth    • Next.js 14 SOC
  • OWASP Top 10      • Partitioned Events • Asymmetric Ed25519 • API Inventory UI
  • OpenAPI Validator • RabbitMQ Topologies• Policy Simulation • Incident Triage
  • Response DLP      • Ingestion API      • 1-Click Rollback  • Isolation Forest
  • Python Connector  • Celery Workers     • Bot / ATO Engine  • Attack Replay
  • Ring Buffer       • pfSense URL Feed   • SIEM Exporters    • Legal CI Audit
```

---

## 4. Necessary Technical Skills Matrix by Developer Role

To successfully implement their assigned modules, each developer should have or acquire the following specific technical competencies:

| Role | Necessary Core Skills & Technologies | Key Concepts to Master |
|---|---|---|
| **Developer 1 (Lead & Data Plane)** | • Python Asyncio / ASGI (Starlette / FastAPI)<br>• Advanced Regular Expressions (ReDoS avoidance)<br>• Web Security (OWASP Top 10 & API Top 10)<br>• C/Python Memory Profiling & Ring Buffers | • Recursive percent decoding & Unicode NFKC<br>• Lexical pattern matching without catastrophic backtracking<br>• Luhn algorithm for credit card DLP validation<br>• Zero-copy memory slicing and bounded ring buffers |
| **Developer 2 (Backend, Database & Ingestion)** | • PostgreSQL 16 Administration & SQL DDL<br>• SQLAlchemy 2.0 Async & asyncpg<br>• RabbitMQ & AMQP 0-9-1 Protocol<br>• High-Throughput Micro-Batching | • Declarative range table partitioning by timestamp<br>• Multi-tenant compile-time query scoping<br>• Prefetch limit tuning & Dead Letter Exchanges (DLQ)<br>• PostgreSQL `COPY` / bulk insertion optimization |
| **Developer 3 (Platform API, Auth, Policy & SIEM)** | • Modern Cryptography (`cryptography` library)<br>• JWT & OAuth2 / TOTP MFA (RFC 6238)<br>• REST API Design with FastAPI & Pydantic v2<br>• Enterprise SIEM Protocols (Syslog, CEF, Splunk HEC) | • Asymmetric Ed25519 digital signatures (RFC 8032)<br>• Canonical JSON serialization (RFC 8785)<br>• Client-side Proof-of-Work (PoW) hash puzzles<br>• Common Event Format (CEF) and LEEF formatting |
| **Developer 4 (Frontend, AI Anomaly & Testing)** | • Next.js 14 (App Router) & React 18<br>• TypeScript & Tailwind CSS<br>• scikit-learn & Python Data Science (`pandas`, `numpy`)<br>• Automated Security Fuzzing (Pytest & Schemathesis) | • Real-time WebSocket streaming & TanStack Query<br>• Isolation Forest anomaly scoring & SHAP attribution<br>• Rolling 7-day diurnal diurnal mean/std-dev baselines<br>• Property-based testing and regression runner design |

---

## 5. Conflict-Free Git Branching & Synchronization Strategy

To ensure all 4 developers work in parallel without code collisions:

```
[main] (Production releases only)
  ▲
  │ (Protected PR merge with all tests green)
[develop] (Integration staging branch)
  ▲
  ├── [feat/dev1-core-engine] ────► Developer 1 (security_engine, connectors)
  ├── [feat/dev2-ingestion-db] ───► Developer 2 (models, migrations, workers, broker)
  ├── [feat/dev3-policy-sim] ─────► Developer 3 (auth, policy_service, mitigation)
  └── [feat/dev4-soc-dashboard] ──► Developer 4 (frontend, ai_pipeline, security_tests)
```

### 5.1 Daily Workflow Rules
1. **Directory Isolation**: Each developer primarily writes code in their assigned directory. Cross-cutting shared interfaces (`shared/schemas/` and `connectors/shared-spec/`) are version-controlled and agreed upon in advance.
2. **Contract-First Communication**: If Developer 1 changes a field in the security event, they update `connectors/shared-spec/event-schema.json` first and notify Developer 2.
3. **Pull Request Policy**:
   - Every PR requires passing CI tests (linting, unit tests, security regression tests).
   - At least 1 peer review approval before merging into `develop`.
4. **Daily Standup Cadence**:
   - 15-minute daily sync: What did you complete yesterday? What contract dependencies do you need today? Are any blockers present?

---

## 6. Phased 8-Week Team Execution Schedule

| Sprint | Duration | Developer 1 (WAAP Core) | Developer 2 (DB & Ingestion) | Developer 3 (Policy & Auth) | Developer 4 (Dashboard & QA) |
|:---:|:---:|---|---|---|---|
| **Sprint 1** | Weeks 1–2 | Normalizer, SQLi/XSS/Traversal detectors, Rate limiter | PostgreSQL 16 schema, partitioned events, Docker Compose | JWT auth, RBAC, Ed25519 asymmetric signer | Docker environment, regression test runner base, CI pipeline |
| **Sprint 2** | Weeks 3–4 | Full OWASP (SSRF, XXE, Deser), in-line OpenAPI validator | Ingestion API (`POST /v1/events/batch`), RabbitMQ worker | Policy Simulation dry-run engine, OpenAPI ingestion | Next.js 14 layout, API Inventory UI, WebSocket stream |
| **Sprint 3** | Weeks 5–6 | Response DLP scanner, File upload inspector, Ring buffer | Ingestion load benchmark (1,000 evt/s), pfSense alias feed | Bot/Account-abuse engine, reversible mitigations, SIEM | Simulation diff viewer, Incident triage UI, Isolation Forest |
| **Sprint 4** | Weeks 7–8 | Python ASGI connector finalization, PHP/Node stubs | Multi-tenant isolation verification, DB partition cron | 1-Click rollback engine, enterprise Slack/Splunk webhooks | Compliance matrix UI (PCI-DSS), full penetration test, Release |
