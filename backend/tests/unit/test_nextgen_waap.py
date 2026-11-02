"""
Comprehensive Unit Tests for SentinelGrid Next-Gen WAAP Capabilities:
- SmartParse Lexical DFA & DOM Boundary Analysis
- Radix Prefix Trie & Threat Intelligence Engine (IPv4 / IPv6 LPM)
- Sliding-Window Rate Limiter & Autonomous Quarantine State Machine
"""

import pytest
import time
import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, "/run/media/anup/D/sentinelgrid/backend")

from app.security_engine.smart_parse import SmartParse, TokenType
from app.security_engine.threat_intel import RadixIpTrie, ThreatIntelEngine
from app.security_engine.rate_limiter import SlidingWindowLimiter
from app.security_engine.brain import SecurityBrain


class TestSentinelGridNextGenWAAP:

    # =========================================================================
    # 1. SmartParse Lexical Tokenizer & Grammatical AST Tests
    # =========================================================================

    def test_smartparse_sql_comment_slicing_breakout(self):
        payload = "admin'/**/OR/**/1=1#"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] in ("SP-SQL-BOUNDARY-BREAKOUT", "SP-SQL-TAUTOLOGY")
        assert res["severity"] in ("CRITICAL", "HIGH")
        assert res["confidence"] >= 0.95

    def test_smartparse_sql_parenthesized_union_select(self):
        payload = "' UNION(SELECT(1),(2),(3))--"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] == "SP-SQL-UNION-SELECT"
        assert res["severity"] == "CRITICAL"
        assert res["confidence"] == 1.0

    def test_smartparse_sql_stacked_query_execution(self):
        payload = "1; DROP TABLE users;--"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] == "SP-SQL-STACKED-QUERY"
        assert res["severity"] == "CRITICAL"

    def test_smartparse_sql_time_delay_waitfor(self):
        payload = "1; WAITFOR DELAY '0:0:5'--"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] == "SP-SQL-TIME-DELAY"

    def test_smartparse_dom_svg_slash_evasion(self):
        payload = "<svg/onload=alert(1)>"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] in ("SP-DOM-DANGEROUS-TAG", "SP-DOM-EVENT-INJECTION")
        assert res["confidence"] >= 0.98

    def test_smartparse_dom_custom_tag_event_handler(self):
        payload = "<d3v onanimationend=alert(1)>"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] == "SP-DOM-EVENT-INJECTION"

    def test_smartparse_dom_quote_attribute_breakout(self):
        payload = '" onfocus="alert(document.cookie)'
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] == "SP-DOM-EVENT-INJECTION"

    def test_smartparse_dom_tab_obfuscated_javascript_scheme(self):
        payload = "jav\tascript:alert(1)"
        res = SmartParse.inspect(payload)
        assert res is not None
        assert res["rule_id"] == "SP-DOM-SCRIPT-SCHEME"

    def test_smartparse_zero_false_positives_on_technical_discussions(self):
        benign_samples = [
            "What is SQL Injection? An Introduction to Cybersecurity",
            "We are using UNION in our database design documentation",
            "The user selected the second option from the dropdown menu",
            "Please click here to read our updated Privacy Policy",
            "SELECT * FROM articles WHERE published = 1 (written in a tutorial)",
            "The event started on Monday and ended on Tuesday",
            "How to configure PostgreSQL waitfor transactions"
        ]
        for sample in benign_samples:
            # Benign educational strings must not trigger injection breakouts
            res = SmartParse.inspect(sample)
            # Either fast-filtered (None) or confirmed safe
            assert res is None, f"False positive triggered on benign sample: '{sample}' (Rule: {res})"

    # =========================================================================
    # 2. Radix Prefix Trie & Threat Intelligence LPM Tests
    # =========================================================================

    def test_radix_trie_ipv4_longest_prefix_match(self):
        trie = RadixIpTrie()
        trie.insert_cidr("198.51.100.0/24", category="TOR_EXIT_NODE", confidence=99.0, action="BLOCK")
        trie.insert_cidr("198.51.100.128/28", category="TOR_EXIT_SPECIFIC", confidence=100.0, action="BLOCK")

        # More specific match (LPM)
        match_specific = trie.lookup("198.51.100.130")
        assert match_specific is not None
        assert match_specific["category"] == "TOR_EXIT_SPECIFIC"

        # Broad subnet match
        match_broad = trie.lookup("198.51.100.42")
        assert match_broad is not None
        assert match_broad["category"] == "TOR_EXIT_NODE"

        # Clean IP outside subnet
        assert trie.lookup("198.51.101.1") is None
        assert trie.lookup("8.8.8.8") is None

    def test_radix_trie_ipv6_longest_prefix_match(self):
        trie = RadixIpTrie()
        trie.insert_cidr("2001:db8::/32", category="BOTNET_C2_IPV6", confidence=96.0, action="BLOCK")

        match_v6 = trie.lookup("2001:db8:beef:cafe::1")
        assert match_v6 is not None
        assert match_v6["category"] == "BOTNET_C2_IPV6"

        assert trie.lookup("2001:4860:4860::8888") is None

    def test_threat_intel_engine_rcu_reload(self):
        engine = ThreatIntelEngine()
        initial_count = engine.entry_count
        assert initial_count > 0

        # Reload with new feeds atomically
        new_feeds = [
            ("203.0.113.0/24", "TEST_BOTNET", 99.0, "BLOCK", "DYNAMIC_FEED"),
            ("198.18.0.0/15", "BENCHMARK_SCANNER", 95.0, "BLOCK", "DYNAMIC_FEED")
        ]
        count = engine.reload_feeds(new_feeds)
        assert count == 2
        assert engine.lookup_ip("203.0.113.55") is not None
        assert engine.lookup_ip("8.8.8.8") is None

    # =========================================================================
    # 3. Sliding-Window Rate Limiter & Dynamic Quarantine Tests
    # =========================================================================

    def test_sliding_window_rate_limiter_burst_and_drop(self):
        limiter = SlidingWindowLimiter(shards=4)
        client_key = "192.0.2.77"
        limit = 5

        for i in range(limit):
            res = limiter.evaluate_rate(client_key, limit=limit, window_seconds=10.0)
            assert res["allowed"] is True
            assert res["remaining"] == limit - 1 - i

        # Request exceeding limit must be dropped
        overflow_res = limiter.evaluate_rate(client_key, limit=limit, window_seconds=10.0)
        assert overflow_res["allowed"] is False
        assert overflow_res["remaining"] == 0
        assert overflow_res["retry_after"] > 0

    def test_dynamic_quarantine_escalation(self):
        limiter = SlidingWindowLimiter(shards=4)
        attacker_ip = "198.51.100.99"

        # Initially clean
        is_q, _, _ = limiter.check_quarantine(attacker_ip)
        assert is_q is False

        # First violation triggers Level 1 quarantine (600 seconds)
        duration1 = limiter.trigger_violation(attacker_ip, severity="CRITICAL", reason="SQLi Exploit Attempt")
        assert duration1 == 600

        is_q, rem_sec, reason = limiter.check_quarantine(attacker_ip)
        assert is_q is True
        assert rem_sec > 580
        assert "SQLi" in reason

        # Subsequent violation while quarantined escalates to Level 2 (3600 seconds)
        duration2 = limiter.trigger_violation(attacker_ip, severity="CRITICAL", reason="Repeated Attack")
        assert duration2 == 3600

        is_q, rem_sec2, reason2 = limiter.check_quarantine(attacker_ip)
        assert is_q is True
        assert rem_sec2 > 3500
        assert "Escalated to Level 2" in reason2

    # =========================================================================
    # 4. End-to-End Brain Integration with Next-Gen Vectors
    # =========================================================================

    def test_brain_evaluates_threat_intel_ip(self):
        # 198.51.100.89 is in the seeded LAB_TEST_TOR subnet (198.51.100.0/24)
        eval_res = SecurityBrain.evaluate(
            path="/api/v1/profile",
            method="GET",
            query="",
            body="",
            headers={"host": "aegis-pro.security.internal"},
            client_ip="198.51.100.89"
        )
        assert eval_res["action"] == "BLOCK"
        assert eval_res["risk_score"] == 100.0
        assert any("THREAT-INTEL" in m["rule_id"] for m in eval_res["all_matches"])

    def test_brain_evaluates_smartparse_evasion(self):
        eval_res = SecurityBrain.evaluate(
            path="/api/v1/search",
            method="GET",
            query="q=admin'/**/OR/**/1=1#",
            body="",
            headers={"host": "aegis-pro.security.internal"},
            client_ip="127.0.0.1"
        )
        assert eval_res["action"] == "BLOCK"
        assert eval_res["risk_score"] >= 90.0
        assert any(m["rule_id"].startswith("SP-") or "SQLI" in m["rule_id"] for m in eval_res["all_matches"])
