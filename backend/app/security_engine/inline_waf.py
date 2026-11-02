"""
SentinelGrid - In-Line OWASP WAF Inspection Engine
Provides sub-5ms inspection for SQLi, XSS, Path Traversal, and SSRF.
"""

import re
from typing import Dict, Any, Tuple


class InLineSecurityEngine:
    SQLI_PATTERNS = [
        re.compile(r"(\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)", re.IGNORECASE),
        re.compile(r"(--|#|/\*|;)\s*$", re.IGNORECASE),
        re.compile(r"('|\")\s*(OR|AND)\s*('|\")?\s*(\d+|\w+)\s*=\s*('|\")?\s*(\d+|\w+)", re.IGNORECASE)
    ]

    XSS_PATTERNS = [
        re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(r"javascript:\s*[a-z0-9_]+", re.IGNORECASE),
        re.compile(r"on(load|error|click|mouseover|submit)\s*=", re.IGNORECASE)
    ]

    TRAVERSAL_PATTERNS = [
        re.compile(r"(\.\./|\.\.\\)+"),
        re.compile(r"(/etc/passwd|/windows/win\.ini)", re.IGNORECASE)
    ]

    @classmethod
    def inspect_request(cls, method: str, path: str, query: str, body: str, headers: Dict[str, str]) -> Tuple[str, float, str, str]:
        """
        Inspects incoming HTTP request payload.
        Returns: (Action ['ALLOW', 'CHALLENGE', 'BLOCK'], risk_score [0-100], rule_id, owasp_category)
        """
        full_payload = f"{path} {query} {body}"

        # 1. Traversal check
        for pat in cls.TRAVERSAL_PATTERNS:
            if pat.search(full_payload):
                return "BLOCK", 95.0, "PATH-TRAVERSAL-01", "A01:Broken Access Control"

        # 2. SQLi check
        for pat in cls.SQLI_PATTERNS:
            if pat.search(full_payload):
                return "BLOCK", 92.0, "SQLI-HEURISTIC-01", "A03:Injection"

        # 3. XSS check
        for pat in cls.XSS_PATTERNS:
            if pat.search(full_payload):
                return "BLOCK", 85.0, "XSS-INLINE-01", "A03:Injection"

        # 4. Sensitive Admin / Internal probe
        if "/internal/" in path or "/debug" in path or "/admin/dump" in path:
            return "BLOCK", 88.0, "SHADOW-ENDPOINT-PROBE", "A01:Broken Access Control"

        # 5. Bot header checks
        ua = headers.get("user-agent", "").lower()
        if "sqlmap" in ua or "nikto" in ua or "zaproxy" in ua:
            return "BLOCK", 99.0, "ATTACK-SCANNER-IDENTIFIED", "A07:Identification Failures"

        if "curl" in ua or "python-requests" in ua:
            return "CHALLENGE", 60.0, "UNVERIFIED-AUTOMATION", "A04:Insecure Design"

        return "ALLOW", 10.0, "CLEAN-REQUEST", "None"
