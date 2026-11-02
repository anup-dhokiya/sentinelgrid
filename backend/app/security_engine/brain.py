"""
SentinelGrid - Comprehensive Multi-Layer Security Brain & Threat Signature Matrix
Implements detection across:
- OWASP Top 10 (SQLi, XSS, SSRF, XXE, Deserialization, Prototype Pollution, Path Traversal)
- Major Real-World Remote Code Execution CVEs (Log4j CVE-2021-44228, Spring4Shell CVE-2022-22965)
- Cloud IMDS Credential Theft (AWS, GCP, Azure metadata probes)
- Command Injection & Web Shells
- Automated Attack Scanner Detection & Bad Bots
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from app.security_engine.normalization.normalizer import RequestNormalizer


class SecuritySignature:
    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        owasp_id: str,
        severity: str,
        score: float,
        pattern: re.Pattern,
        cve_ref: Optional[str] = None
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.owasp_id = owasp_id
        self.severity = severity
        self.score = score
        self.pattern = pattern
        self.cve_ref = cve_ref


class SecurityBrain:
    """The central threat detection and payload evaluation brain of SentinelGrid."""

    SIGNATURES: List[SecuritySignature] = [
        # =========================================================================
        # 1. CRITICAL RCE & HISTORICAL HIGH-IMPACT CVEs
        # =========================================================================
        SecuritySignature(
            rule_id="CVE-2021-44228-LOG4J",
            name="Log4j / Log4Shell JNDI Lookup Injection",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(r"\$\{\s*(?:jndi|base64|lower|upper)\s*:[^\}]*\}", re.IGNORECASE),
            cve_ref="CVE-2021-44228"
        ),
        SecuritySignature(
            rule_id="CVE-2022-22965-SPRING4SHELL",
            name="Spring4Shell ClassLoader Exploit Probe",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(r"class\.module\.classLoader", re.IGNORECASE),
            cve_ref="CVE-2022-22965"
        ),
        SecuritySignature(
            rule_id="RCE-CMD-SHELL-INJECTION",
            name="OS Command Injection / Pipe / Backtick Chaining",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(r"(?:;\s*(?:cat|ls|rm|nc|curl|wget|sh|bash|powershell|cmd)\b|\|\s*(?:cat|ls|rm|nc|curl|wget|sh|bash)\b|`[^`]+`|\$\([^)]+\)|\b(?:nc|ncat|bash|sh)\b\s+-[ei])", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="RCE-SYSTEM-CALL-PROBE",
            name="System Command Execution Probe (whoami, id, uname, cat /etc/passwd)",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=92.0,
            pattern=re.compile(r"(?:(?:\b(?:whoami|id|uname -a|ifconfig|ipconfig)\b)|(?:\bcat\s+/etc/(?:passwd|shadow|hosts)))", re.IGNORECASE)
        ),

        # =========================================================================
        # 2. SERVER-SIDE REQUEST FORGERY (SSRF) & CLOUD METADATA EXFILTRATION
        # =========================================================================
        SecuritySignature(
            rule_id="SSRF-CLOUD-IMDS-AWS",
            name="AWS/Cloud IMDSv1 Metadata Theft (169.254.169.254)",
            category="Server-Side Request Forgery",
            owasp_id="A10:Server-Side Request Forgery",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(r"(?:169\.254\.169\.254|latest/meta-data|instance-identity)", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="SSRF-CLOUD-METADATA-GCP-AZURE",
            name="GCP / Azure Cloud Metadata Endpoint Probe",
            category="Server-Side Request Forgery",
            owasp_id="A10:Server-Side Request Forgery",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(r"(?:metadata\.google\.internal|computeMetadata|metadata\.azure\.com)", re.IGNORECASE)
        ),

        # =========================================================================
        # 3. SQL INJECTION (SQLi) - OWASP TOP 10 (A03)
        # =========================================================================
        SecuritySignature(
            rule_id="SQLI-UNION-SELECT",
            name="SQL Injection Union-Based Data Exfiltration",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=95.0,
            pattern=re.compile(r"(?:\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|UNION(?:ALL)?SELECT)", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="SQLI-TAUTOLOGY-OR-EQUALS",
            name="Classic SQL Tautology Auth Bypass (' OR 1=1)",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=94.0,
            pattern=re.compile(r"('|\"|`|\b)\s*(?:OR|AND)\s+('?[^'\s=]+'?)\s*=\s*('?[^'\s=]+'?)(?:\s*--|\s*#|\s*/\*|\s*;)?", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="SQLI-STACKED-QUERIES-DDL",
            name="Stacked SQL Queries & Database DDL / DML Injection",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=92.0,
            pattern=re.compile(r";\s*(?:DROP|ALTER|TRUNCATE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="SQLI-BLIND-TIME-SLEEP",
            name="Time-Based Blind SQL Injection (SLEEP/BENCHMARK/WAITFOR/pg_sleep)",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=88.0,
            pattern=re.compile(r"(?:\b(?:SLEEP|BENCHMARK|pg_sleep)\s*\(\s*\d+\s*\)|\bWAITFOR\s+DELAY\s+['\"][^'\"]+['\"])", re.IGNORECASE)
        ),

        # =========================================================================
        # 4. CROSS-SITE SCRIPTING (XSS) - OWASP TOP 10 (A03)
        # =========================================================================
        SecuritySignature(
            rule_id="XSS-SCRIPT-TAG-INJECTION",
            name="Explicit Script Tag HTML Injection",
            category="Cross-Site Scripting",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=85.0,
            pattern=re.compile(r"<\s*script\b[^>]*>.*?(?:<\s*/\s*script\s*>)?", re.IGNORECASE | re.DOTALL)
        ),
        SecuritySignature(
            rule_id="XSS-EVENT-HANDLER-INJECTION",
            name="HTML Tag Attribute Event Handler (onerror, onload, onclick)",
            category="Cross-Site Scripting",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=85.0,
            pattern=re.compile(r"<\s*\w+\b[^>]*\bon\w+\s*=\s*(?:'|\"|`|&#)?\s*.*?>", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="XSS-JAVASCRIPT-URI-SCHEME",
            name="JavaScript Pseudo-Protocol URI Injection",
            category="Cross-Site Scripting",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=82.0,
            pattern=re.compile(r"(?:javascript|vbscript|data\s*:\s*text/html)\s*:\s*.*", re.IGNORECASE)
        ),

        # =========================================================================
        # 5. PATH TRAVERSAL & LOCAL FILE INCLUSION (LFI) - OWASP TOP 10 (A01)
        # =========================================================================
        SecuritySignature(
            rule_id="PATH-TRAVERSAL-DOT-SLASH",
            name="Canonical / Escaped Path Traversal Sequence",
            category="Path Traversal",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=94.0,
            pattern=re.compile(r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c){2,}", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="LFI-SENSITIVE-SYSTEM-FILE",
            name="Access Attempt on Sensitive Operating System Files",
            category="Path Traversal",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(r"(?:/etc/(?:passwd|shadow|group|security)|/windows/win\.ini|/proc/self/environ|boot\.ini)", re.IGNORECASE)
        ),

        # =========================================================================
        # 6. XML EXTERNAL ENTITY (XXE) & PROTOTYPE POLLUTION (A04/A08)
        # =========================================================================
        SecuritySignature(
            rule_id="XXE-ENTITY-DECLARATION",
            name="XML External Entity (XXE) Injection Attempt",
            category="XML External Entity",
            owasp_id="A05:Security Misconfiguration",
            severity="CRITICAL",
            score=92.0,
            pattern=re.compile(r"<!DOCTYPE\s+[^>]*\[\s*<!ENTITY\s+[^>]+SYSTEM\s+[\"'][^\"']+[\"']", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="PROTO-POLLUTION-PAYLOAD",
            name="JavaScript Prototype Pollution Attempt (__proto__ / constructor.prototype)",
            category="Prototype Pollution",
            owasp_id="A04:Insecure Design",
            severity="HIGH",
            score=86.0,
            pattern=re.compile(r"(?:\"__proto__\"|'__proto__'|__proto__|\"constructor\"\s*:\s*\{\s*\"prototype\")", re.IGNORECASE)
        ),

        # =========================================================================
        # 7. INSECURE DESERIALIZATION (A08)
        # =========================================================================
        SecuritySignature(
            rule_id="DESERIALIZATION-JAVA-MAGIC-BYTES",
            name="Java Serialized Object Injection (rO0AB... magic bytes)",
            category="Insecure Deserialization",
            owasp_id="A08:Software and Data Integrity Failures",
            severity="CRITICAL",
            score=90.0,
            pattern=re.compile(r"(?:rO0AB[A-Za-z0-9+/=]{10,}|aced0005)", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="DESERIALIZATION-PHP-OBJECT",
            name="PHP Object Serialized Payload (O:num:\"class\":)",
            category="Insecure Deserialization",
            owasp_id="A08:Software and Data Integrity Failures",
            severity="HIGH",
            score=88.0,
            pattern=re.compile(r"\bO:\d+:\s*\"[^\"]+\":\d+:\s*\{", re.IGNORECASE)
        ),

        # =========================================================================
        # 8. AUTOMATED MALICIOUS SCANNERS & RECON TOOLING
        # =========================================================================
        SecuritySignature(
            rule_id="SCANNER-KNOWN-TOOL-SIGNATURE",
            name="Known Automated Attack Scanner Identified (SqlMap, Nikto, Acunetix, ZAP)",
            category="Malicious Automation",
            owasp_id="A07:Identification and Authentication Failures",
            severity="CRITICAL",
            score=99.0,
            pattern=re.compile(r"(?:sqlmap|nikto|acunetix|w3af|openvas|zaproxy|dirbuster|gobuster)", re.IGNORECASE)
        ),
        SecuritySignature(
            rule_id="PROBE-SHADOW-DEBUG-ENDPOINT",
            name="Probe on Dangerous Undocumented/Internal Debug Route",
            category="Broken Access Control",
            owasp_id="A01:Broken Access Control",
            severity="HIGH",
            score=88.0,
            pattern=re.compile(r"(?:/(?:internal/debug|admin/dump|\.git/config|\.env|actuator/env))", re.IGNORECASE)
        )
    ]

    @classmethod
    def evaluate(
        cls,
        path: str,
        method: str,
        query: str,
        body: str,
        headers: Dict[str, str],
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Deep inspection pipeline:
        1. Normalizes all request vectors (NFKC, recursive unescape, null-byte strip)
        2. Scans against comprehensive signature matrix
        3. Aggregates composite risk score
        4. Issues sub-5ms policy verdict (BLOCK, CHALLENGE, ALLOW)
        """
        # Step 1: Normalization
        norm = RequestNormalizer.normalize_request_data(path, query, body, headers)
        combined_text = norm["combined"]
        user_agent = norm["headers"].get("user-agent", "")

        matches: List[Dict[str, Any]] = []
        max_score = 0.0

        # Step 2: Signature Scan
        for sig in cls.SIGNATURES:
            # Special check for scanners in User-Agent
            if "SCANNER" in sig.rule_id:
                if sig.pattern.search(user_agent):
                    matches.append({
                        "rule_id": sig.rule_id,
                        "name": sig.name,
                        "category": sig.category,
                        "owasp_id": sig.owasp_id,
                        "severity": sig.severity,
                        "score": sig.score,
                        "cve_ref": sig.cve_ref
                    })
                    max_score = max(max_score, sig.score)
                continue

            # General pattern match on normalized combined payload
            if sig.pattern.search(combined_text):
                matches.append({
                    "rule_id": sig.rule_id,
                    "name": sig.name,
                    "category": sig.category,
                    "owasp_id": sig.owasp_id,
                    "severity": sig.severity,
                    "score": sig.score,
                    "cve_ref": sig.cve_ref
                })
                max_score = max(max_score, sig.score)

        # Step 3: Action Determination
        if max_score >= 75.0:
            action = "BLOCK"
            http_status = 403
        elif max_score >= 50.0:
            action = "CHALLENGE"
            http_status = 429
        else:
            action = "ALLOW"
            http_status = 200
            max_score = 5.0  # Baseline safe score

        top_rule = matches[0] if matches else None

        return {
            "action": action,
            "http_status": http_status,
            "risk_score": round(max_score, 1),
            "total_matches": len(matches),
            "top_match": top_rule,
            "all_matches": matches,
            "is_clean": len(matches) == 0,
            "normalized_path": norm["path"]
        }
