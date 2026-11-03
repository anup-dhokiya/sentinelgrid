"""
SentinelGrid - Policy Simulation & Dry-Run Engine
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    rule_id: str
    action: str  # "block", "challenge", "monitor", "allow"
    criteria: Dict[str, Any]
    description: Optional[str] = None


class PolicyPayload(BaseModel):
    policy_id: str
    version: int
    website_id: str
    thresholds: Dict[str, int] = Field(default_factory=lambda: {"block": 75, "challenge": 50, "monitor": 25})
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    ip_blocklist_delta: Dict[str, List[str]] = Field(default_factory=lambda: {"add": [], "remove": []})
    issued_at: str
    expires_at: Optional[str] = None


class HistoricalTrafficSample(BaseModel):
    event_id: str
    path: str
    method: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    client_ip: str
    is_legitimate_crawler: bool = False
    original_action: str  # "allow", "block", "challenge"

    def get_header(self, name: str, default: str = "") -> str:
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return default


class SimulationReport(BaseModel):
    policy_version: int
    total_evaluated_requests: int
    projected_blocks: int
    projected_challenges: int
    projected_allows: int
    newly_blocked_count: int
    potential_false_positive_count: int
    false_positive_rate_percent: float
    high_risk_false_positive_details: List[Dict[str, Any]]
    is_safe_to_deploy: bool
    evaluation_duration_ms: float


class PolicySimulationEngine:
    """
    Offline historical traffic replay & impact evaluator.
    Validates candidate rules before production rollout.
    """

    @classmethod
    def evaluate_rule_against_sample(cls, rule: Dict[str, Any], sample: HistoricalTrafficSample) -> bool:
        """Evaluates whether an individual rule criteria matches the sample traffic."""
        criteria = rule.get("criteria", {})
        
        # Check User-Agent substring match (case-insensitive)
        if "user_agent_contains" in criteria:
            target = criteria["user_agent_contains"].lower()
            ua = sample.get_header("user-agent").lower()
            if target in ua:
                return True

        # Check Path prefix match
        if "path_prefix" in criteria:
            prefix = criteria["path_prefix"]
            if sample.path.startswith(prefix):
                return True

        # Check Query parameter presence / pattern
        if "query_param_exists" in criteria:
            param = criteria["query_param_exists"]
            if param in sample.query_params:
                return True

        return False

    @classmethod
    def simulate_policy_diff(
        cls,
        candidate_policy: PolicyPayload,
        traffic_corpus: List[HistoricalTrafficSample]
    ) -> SimulationReport:
        """
        Replays the candidate policy rules against a corpus of historical traffic.
        Calculates projected block rate and flags false-positive risks.
        """
        start_time = datetime.now(timezone.utc)
        
        total = len(traffic_corpus)
        projected_blocks = 0
        projected_challenges = 0
        projected_allows = 0
        newly_blocked = 0
        false_positives: List[Dict[str, Any]] = []

        block_rules = [r for r in candidate_policy.rules if r.get("action") == "block"]
        challenge_rules = [r for r in candidate_policy.rules if r.get("action") == "challenge"]

        for sample in traffic_corpus:
            matched_block = False
            matched_rule_id = None

            for rule in block_rules:
                if cls.evaluate_rule_against_sample(rule, sample):
                    matched_block = True
                    matched_rule_id = rule.get("rule_id", "unknown")
                    break

            if matched_block:
                projected_blocks += 1
                if sample.original_action == "allow":
                    newly_blocked += 1
                    # Flag legitimate search bots or high-confidence genuine traffic
                    if sample.is_legitimate_crawler:
                        false_positives.append({
                            "event_id": sample.event_id,
                            "path": sample.path,
                            "rule_id": matched_rule_id,
                            "reason": "Legitimate search crawler/partner would be blocked"
                        })
            else:
                matched_challenge = any(cls.evaluate_rule_against_sample(r, sample) for r in challenge_rules)
                if matched_challenge:
                    projected_challenges += 1
                else:
                    projected_allows += 1

        fp_count = len(false_positives)
        fp_rate = (fp_count / total * 100.0) if total > 0 else 0.0
        duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0

        # Policy considered safe if false positive rate is 0.0% on known legitimate traffic
        is_safe = fp_count == 0

        return SimulationReport(
            policy_version=candidate_policy.version,
            total_evaluated_requests=total,
            projected_blocks=projected_blocks,
            projected_challenges=projected_challenges,
            projected_allows=projected_allows,
            newly_blocked_count=newly_blocked,
            potential_false_positive_count=fp_count,
            false_positive_rate_percent=round(fp_rate, 2),
            high_risk_false_positive_details=false_positives,
            is_safe_to_deploy=is_safe,
            evaluation_duration_ms=round(duration_ms, 2)
        )
