# Team Plan 04 — Asymmetric Policy Signing, Simulation & Management API

> **Owner**: Platform, API & Policy Security Team  
> **Target Milestones**: M10 (Management API & Auth), M11 (Signed Policy Distribution), WAAP-SIM (Policy Simulation & Rollback)  
> **Key Dependents**: Team 01 (Database), Team 02 (Connectors), Team 07 (Frontend)  
> **Legal Baseline**: Export compliance under Wassenaar Arrangement / US EAR 15 C.F.R. § 742.15(b) using standard Ed25519 / HMAC-SHA256 algorithms.

---

## 1. Scope & Core Responsibilities
The Platform & Policy Team is responsible for:
1. **Asymmetric Digital Policy Signing (Ed25519)** & Cryptographic Key Lifecycle Management.
2. **Policy Simulation & Dry-Run Engine**: Replaying historical traffic to estimate false positives prior to production deployment.
3. **Instant 1-Click Rollback & Staged Rollout Engine**.
4. **OpenAPI Specification Upload & Route Ingestion API**.
5. Multi-tenant Authentication, RBAC, and connector key provisioning.

---

## 2. Technical Function Details & Architectural Alternatives

### 2.1 Asymmetric Ed25519 Digital Policy Signing
Upgrading from symmetric HMAC-SHA256 to asymmetric **Ed25519 (RFC 8032)**:
- **Private Signing Key**: Stored exclusively in the central cloud control plane (or cloud KMS / Vault).
- **Public Verification Key**: Embedded safely in customer connectors. Even if a customer website is fully compromised, the attacker cannot forge valid policy updates for other connectors.

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
import base64
import json

class AsymmetricPolicySigner:
    @staticmethod
    def sign_policy(canonical_payload: dict, private_key: ed25519.Ed25519PrivateKey) -> str:
        """
        Signs the deterministic canonical JSON representation of a policy payload.
        Algorithm: Ed25519 (PureEdDSA, RFC 8032).
        """
        canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = private_key.sign(canonical_bytes)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(canonical_payload: dict, signature_b64: str, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verifies policy signature at the connector."""
        canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = base64.b64decode(signature_b64.encode('utf-8'))
        try:
            public_key.verify(signature, canonical_bytes)
            return True
        except Exception:
            return False
```

#### Architectural Alternatives Analysis
| Option | Algorithm | Performance | Key Size | Security / Verdict |
|---|---|---|---|---|
| **Option A (Chosen)** | **Ed25519 (PureEdDSA)** | **~0.05 ms verify** | **32 bytes** | **Selected**: Immune to timing attacks, compact signature (64 bytes), lightning-fast verification on low-CPU connectors. |
| **Option B** | RSA-4096 (PKCS#1 v1.5 / PSS) | ~0.35 ms verify | 512 bytes | *Rejected*: Bulky keys, slower verification, complex padding vulnerabilities. |
| **Option C** | HMAC-SHA256 (Symmetric) | ~0.01 ms verify | 32 bytes | *Limitation*: Shared secret must live on every connector; compromising one connector exposes the signing key for all. |

---

### 2.2 Policy Simulation & Dry-Run Impact Engine
Allows security analysts to test proposed rule changes against real historical traffic before enforcing:

```python
class PolicySimulationEngine:
    def __init__(self, db_session: AsyncSession, engine_factory: SecurityEngineFactory):
        self.db = db_session
        self.engine_factory = engine_factory

    async def simulate_policy_diff(
        self,
        website_id: UUID,
        proposed_policy: dict,
        lookback_days: int = 7
    ) -> PolicySimulationResult:
        """
        Queries sanitized historical security events for website over lookback window.
        Replays requests through prospective security engine in shadow mode.
        Calculates projected block count, delta vs current policy, and false-positive risk.
        """
        query = select(SecurityEvent).where(
            SecurityEvent.website_id == website_id,
            SecurityEvent.timestamp >= datetime.utcnow() - timedelta(days=lookback_days)
        )
        historical_events = (await self.db.execute(query)).scalars().all()

        candidate_engine = self.engine_factory.build(proposed_policy)
        
        projected_blocks = 0
        potential_false_positives = []

        for event in historical_events:
            simulated_decision = candidate_engine.evaluate(event.to_normalized_request())
            if simulated_decision.action == "block":
                projected_blocks += 1
                if event.action_taken == "allow" and event.client_is_crawler:
                    # Legitimate search crawler would be newly blocked!
                    potential_false_positives.append(event)

        fp_rate = (len(potential_false_positives) / max(1, len(historical_events))) * 100.0

        return PolicySimulationResult(
            total_replayed=len(historical_events),
            projected_blocks=projected_blocks,
            potential_false_positives_count=len(potential_false_positives),
            estimated_fp_rate=fp_rate,
            warnings=[f"Would newly block {len(potential_false_positives)} legitimate crawler requests!"]
        )
```

#### Architectural Alternatives Analysis
| Option | Approach | Safety | Speed | Verdict |
|---|---|---|---|---|
| **Option A (Chosen)** | **Asynchronous Historical Event Replay** | **100% Safe (Isolated DB read)** | **Fast (< 5s for 100k events)** | **Selected**: Non-invasive, deterministic, immediate feedback before committing. |
| **Option B** | Live Shadow Mode (Twin Evaluation in Connector) | 100% Safe | Real-time (requires waiting days) | *Complementary*: Can be enabled as step 2 of a staged rollout. |
| **Option C** | Synthetic Fuzzing Only | Safe | High speed | *Incomplete*: Synthetic traffic does not represent legitimate user patterns or edge cases. |

---

### 2.3 Instant 1-Click Rollback & Staged Rollout
- If a newly deployed policy triggers false positives in production, the analyst clicks **"Rollback"**:
  1. API sets `is_active = False` on the problematic version and reactivates the previous verified version in `security_policies`.
  2. A high-priority WebSocket / push notification triggers connectors to immediately reload the previous cached version in $< 1.0\text{ second}$.
  3. Staged Rollouts allow pushing updates to 10% of connector nodes before 100% global rollout.

---

## 3. Verification & Testing Gates

1. **Ed25519 Tamper Test (`backend/tests/unit/test_asymmetric_signing.py`)**:
   - Sign policy payload with private key -> verify passes.
   - Modify 1 character in policy -> assert verification fails.
2. **Policy Simulation Test**:
   - Run simulation over 10,000 synthetic historical events -> confirm simulation finishes in $< 3.0\text{ seconds}$ with accurate projected block counts.
3. **1-Click Rollback Test**:
   - Roll out v5 -> trigger rollback to v4 -> verify connector drops v5 and enforces v4 within 1.0 second.
