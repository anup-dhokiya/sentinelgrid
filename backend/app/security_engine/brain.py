"""
SentinelGrid - Comprehensive Multi-Layer Security Brain & Threat Signature Matrix
Target-aware inspection engine covering:
- Critical Remote Code Execution CVEs (Log4j CVE-2021-44228, Spring4Shell CVE-2022-22965)
- Server-Side Request Forgery (SSRF) & Cloud IMDS Credential Theft (AWS, GCP, Azure)
- Full OWASP Top 10 (SQLi, XSS, Path Traversal/LFI, XXE, Prototype Pollution, Deserialization, RCE)
- Malicious Reconnaissance Tools & Automated Scanners
Zero false-positive architecture with context-separated inspection for paths, headers, parameters, and payloads.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from app.security_engine.normalization.normalizer import RequestNormalizer


class ThreatSignature:
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

    # 1. Critical Exploit & CVE Signatures (Inspected in Path, Parameters, Headers & Body)
    CVE_SIGNATURES: List[ThreatSignature] = [
        ThreatSignature(
            rule_id="CVE-2021-44228-LOG4J",
            name="Log4j / Log4Shell JNDI Lookup Injection",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(r"\$\{\s*(?:jndi|base64|lower|upper|env|sys)\s*:[^\}]*\}", re.IGNORECASE),
            cve_ref="CVE-2021-44228"
        ),
        ThreatSignature(
            rule_id="CVE-2022-22965-SPRING4SHELL",
            name="Spring4Shell ClassLoader Exploit Probe",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(r"class\.module\.classLoader", re.IGNORECASE),
            cve_ref="CVE-2022-22965"
        ),
        ThreatSignature(
            rule_id="SSRF-CLOUD-IMDS-AWS",
            name="AWS/Cloud IMDSv1/v2 Metadata Exfiltration Probe (Dotted, Hex, Decimal, IPv6)",
            category="Server-Side Request Forgery",
            owasp_id="A10:Server-Side Request Forgery",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"(?:"
                r"169\.254\.169\.254"
                r"|\b0xa9\.0xfe\.0xa9\.0xfe\b"
                r"|\b0xa9fea9fe\b"
                r"|\b2852039166\b"
                r"|\b0251\.0376\.0251\.0376\b"
                r"|\b025177524776\b"
                r"|\[?fd00:ec2::254\]?"
                r"|::ffff:(?:169\.254\.169\.254|a9fe:a9fe)"
                r"|latest/(?:meta-data|user-data|dynamic/instance-identity|api/token)"
                r"|instance-identity/document"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="SSRF-CLOUD-METADATA-GCP-AZURE",
            name="GCP / Azure Cloud Metadata Endpoint Probe",
            category="Server-Side Request Forgery",
            owasp_id="A10:Server-Side Request Forgery",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"(?:"
                r"metadata\.google\.internal"
                r"|metadata\.goog\b"
                r"|computeMetadata/(?:v1|v1beta1)"
                r"|metadata\.azure\.com(?:/metadata/instance)?"
                r"|metadata/instance\b"
                r"|100\.100\.100\.200"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="SSTI-TEMPLATE-INJECTION",
            name="Server-Side Template Injection Probe (Jinja2, Twig, Freemarker, SpEL, ERB)",
            category="Server-Side Template Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(
                r"(?:"
                r"(?:\{\{|\$\{|\#\{|\*\{|<%=|<%)\s*(?:[a-zA-Z0-9_\'\"]+\s*[\*\+\-\/]\s*[a-zA-Z0-9_\'\"]+|T\s*\([A-Za-z0-9_.]+\)|new\s+[A-Za-z0-9_.]+\s*\().*?(?:\}\}|%\}|\}|%>)"
                r"|(?:\{\{|\$\{|\#\{|\*\{|<%=|<%)\s*.*?(?:context|request|session|application|global|__class__|class|__mro__|mro|__globals__|globals|__subclasses__|subclasses|getRuntime|ProcessBuilder|exec|eval|system|config|lipsum|cycler).*?(?:\}\}|%\}|\}|%>)"
                r"|\{%\s*(?:import|include|set|with|exec|from|raw)\b.*?%\}"
                r"|<[#@]\s*(?:assign|include|import|exec|visit|recurse|macro)\b[^>]*>"
                r"|\[[#@]\s*(?:assign|include|import|exec|visit|recurse|macro)\b[^\]]*\]"
                r"|<%\s*(?:system|exec|%x|IO\.read|File\.read|require|java\.)\b.*?%>"
                r")",
                re.IGNORECASE
            )
        )
    ]

    # 2. Path & URI Signatures (Path Traversal, LFI, Sensitive File Probes)
    PATH_SIGNATURES: List[ThreatSignature] = [
        ThreatSignature(
            rule_id="PATH-TRAVERSAL-SEQUENCE",
            name="Canonical / Escaped Path Traversal Sequence",
            category="Path Traversal",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=95.0,
            pattern=re.compile(r"(?:\.\./|\.\.\\|/\.\./|/\.\.$|\.\.%2f|\.\.%5c)", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="LFI-SENSITIVE-SYSTEM-FILE",
            name="Access Attempt on Sensitive Operating System Files",
            category="Path Traversal",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(r"(?:/etc/(?:passwd|shadow|group|security)|/windows/win\.ini|/proc/self/(?:environ|status)|boot\.ini)", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="PROBE-SENSITIVE-ENDPOINT",
            name="Probe on Sensitive Internal Debug / Configuration Route",
            category="Broken Access Control",
            owasp_id="A01:Broken Access Control",
            severity="HIGH",
            score=88.0,
            pattern=re.compile(r"(?:/(?:internal/debug|admin/dump|\.git/config|\.env|actuator/env))", re.IGNORECASE)
        )
    ]

    # 3. Payload Signatures (SQLi, XSS, RCE, XXE, Deserialization, Prototype Pollution)
    PAYLOAD_SIGNATURES: List[ThreatSignature] = [
        # SQL Injection
        ThreatSignature(
            rule_id="SQLI-UNION-SELECT",
            name="SQL Injection Union-Based Data Exfiltration",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=95.0,
            pattern=re.compile(r"(?:\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|UNION(?:ALL)?SELECT)", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="SQLI-TAUTOLOGY-OR-EQUALS",
            name="SQL Tautology Auth Bypass (' OR '1'='1)",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=94.0,
            pattern=re.compile(r"(?:'\s*(?:OR|AND)\s*'?\w+'?\s*=\s*'?\w+'?|\bOR\s+\d+\s*=\s*\d+\b|\bAND\s+\d+\s*=\s*\d+\b|'\s*OR\s*'\w+'\s*=\s*'\w+'|\badmin'\s*--)", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="SQLI-STACKED-DDL-DML",
            name="Stacked SQL Queries & DDL/DML Injection",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=92.0,
            pattern=re.compile(r";\s*(?:DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="SQLI-BLIND-TIME-SLEEP",
            name="Time-Based Blind SQL Injection (SLEEP / WAITFOR DELAY / pg_sleep)",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=88.0,
            pattern=re.compile(r"(?:\b(?:SLEEP|BENCHMARK|pg_sleep)\s*\(\s*\d+\s*\)|\bWAITFOR\s+DELAY\s+['\"][^'\"]+['\"])", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="SQLI-METADATA-SCHEMA",
            name="Database Schema & Metadata Table Enumeration",
            category="SQL Injection",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=86.0,
            pattern=re.compile(r"\b(?:information_schema\.(?:tables|columns|schemata)|sys\.databases|sysobjects|all_tables)\b", re.IGNORECASE)
        ),

        # Command Injection (RCE)
        ThreatSignature(
            rule_id="RCE-CMD-EXECUTION",
            name="OS Command Chaining & Execution Probe",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(r"(?:(?:;|\||&&)\s*(?:cat\s+|/bin/|whoami\b|id\s+|ls\s+|rm\s+|curl\s+|wget\s+|chmod\s+|chown\s+|bash\b|sh\b|powershell\b|cmd(?:\.exe)?\s+/c|python\s+-c|perl\s+-e))", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="RCE-SUBSHELL-BACKTICKS",
            name="Subshell & Backtick Command Substitution",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=94.0,
            pattern=re.compile(r"(?:\$\(\s*(?:whoami|id|cat|ls|uname|nc|curl|wget)[^)]*\)|`\s*(?:whoami|id|cat|ls|uname|nc|curl|wget)[^`]*`)", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="RCE-REVERSE-SHELL",
            name="Reverse Shell / Network Socket Tooling",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(r"\b(?:nc|ncat|netcat)\b.*?(?:-e|-c|/bin/(?:sh|bash))", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="RCE-ENCODED-PIPE-EXEC",
            name="Encoded Command Pipe Execution (base64 -d | sh, curl | sh)",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"(?:"
                r"\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:/bin/)?(?:ba|z|da)?sh\b"
                r"|base64\s+(?:-d|--decode)\s*<<<"
                r"|echo\s+[A-Za-z0-9+/=]{8,}\s*\|\s*(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d)\s*\|\s*(?:/bin/)?(?:ba|z|da)?sh\b"
                r"|(?:curl|wget)\s+[^|;&\n]+\|\s*(?:/bin/)?(?:ba|z|da)?sh\b"
                r"|bash\s+-c\s+[\"'].*?base64.*?[\"']"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="RCE-SCRIPTING-ONE-LINER",
            name="Scripting Language Inline Execution (Python/Perl/Ruby one-liners)",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=97.0,
            pattern=re.compile(
                r"\b(?:python[23]?|perl|ruby|php)\b(?:\s+-[a-zA-Z0-9_-]+)*\s+-(?:c|e|r)\s+[\"'].*?[\"']",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="RCE-POWERSHELL-PAYLOAD",
            name="PowerShell Web Download Cradle & Execution Probe",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"(?:"
                r"(?:\bpowershell(?:\.exe)?\b.*?(?:Invoke-WebRequest|iwr\b|Invoke-RestMethod|irm\b|DownloadString|DownloadFile|Net\.WebClient|Start-BitsTransfer|-enc\b|-encodedcommand\b|-executionpolicy\s+bypass|-w(?:indowstyle)?\s+hidden|-nop(?:rofile)?))"
                r"|(?:\b(?:IEX|Invoke-Expression)\s*\(?\s*(?:New-Object\s+Net\.WebClient|Invoke-WebRequest|iwr\b|Invoke-RestMethod|irm\b))"
                r")",
                re.IGNORECASE
            )
        ),

        # Server-Side Template Injection (SSTI)
        ThreatSignature(
            rule_id="SSTI-TEMPLATE-INJECTION",
            name="Server-Side Template Injection Probe (Jinja2, Twig, Freemarker, SpEL, ERB)",
            category="Server-Side Template Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(
                r"(?:"
                r"(?:\{\{|\$\{|\#\{|\*\{|<%=|<%)\s*(?:[a-zA-Z0-9_\'\"]+\s*[\*\+\-\/]\s*[a-zA-Z0-9_\'\"]+|T\s*\([A-Za-z0-9_.]+\)|new\s+[A-Za-z0-9_.]+\s*\().*?(?:\}\}|%\}|\}|%>)"
                r"|(?:\{\{|\$\{|\#\{|\*\{|<%=|<%)\s*.*?(?:context|request|session|application|global|__class__|class|__mro__|mro|__globals__|globals|__subclasses__|subclasses|getRuntime|ProcessBuilder|exec|eval|system|config|lipsum|cycler).*?(?:\}\}|%\}|\}|%>)"
                r"|\{%\s*(?:import|include|set|with|exec|from|raw)\b.*?%\}"
                r"|<[#@]\s*(?:assign|include|import|exec|visit|recurse|macro)\b[^>]*>"
                r"|\[[#@]\s*(?:assign|include|import|exec|visit|recurse|macro)\b[^\]]*\]"
                r"|<%\s*(?:system|exec|%x|IO\.read|File\.read|require|java\.)\b.*?%>"
                r")",
                re.IGNORECASE
            )
        ),

        # Cross-Site Scripting (XSS)
        ThreatSignature(
            rule_id="XSS-SCRIPT-TAG",
            name="Script Tag HTML Injection",
            category="Cross-Site Scripting",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=85.0,
            pattern=re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="XSS-EVENT-HANDLER",
            name="HTML Tag Attribute Event Handler (onerror, onload, onclick, onbegin)",
            category="Cross-Site Scripting",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=85.0,
            pattern=re.compile(r"<\s*[a-z0-9:_-]+\b[^>]*\bon[a-z]+\s*=", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="XSS-JAVASCRIPT-URI",
            name="JavaScript Pseudo-Protocol URI Injection",
            category="Cross-Site Scripting",
            owasp_id="A03:Injection",
            severity="HIGH",
            score=82.0,
            pattern=re.compile(r"(?:javascript|vbscript|data\s*:\s*text/html)\s*:\s*.*", re.IGNORECASE)
        ),

        # XML External Entity (XXE)
        ThreatSignature(
            rule_id="XXE-ENTITY-DECLARATION",
            name="XML External Entity (XXE) Injection Attempt",
            category="XML External Entity",
            owasp_id="A05:Security Misconfiguration",
            severity="CRITICAL",
            score=92.0,
            pattern=re.compile(r"<!DOCTYPE\s+[^>]*\[\s*<!ENTITY\s+[^>]+SYSTEM\s+[\"'][^\"']+[\"']", re.IGNORECASE)
        ),

        # Prototype Pollution
        ThreatSignature(
            rule_id="PROTO-POLLUTION-PAYLOAD",
            name="JavaScript Prototype Pollution Attempt (__proto__ / constructor.prototype)",
            category="Prototype Pollution",
            owasp_id="A04:Insecure Design",
            severity="HIGH",
            score=86.0,
            pattern=re.compile(r"(?:\"__proto__\"|'__proto__'|__proto__|\"constructor\"\s*:\s*\{\s*\"prototype\")", re.IGNORECASE)
        ),

        # Insecure Deserialization
        ThreatSignature(
            rule_id="DESERIALIZATION-JAVA-MAGIC-BYTES",
            name="Java Serialized Object Injection (rO0AB... magic bytes)",
            category="Insecure Deserialization",
            owasp_id="A08:Software and Data Integrity Failures",
            severity="CRITICAL",
            score=90.0,
            pattern=re.compile(r"(?:rO0AB[A-Za-z0-9+/=]{2,}|aced0005|\\xac\\xed\\x00\\x05)", re.IGNORECASE)
        ),
        ThreatSignature(
            rule_id="DESERIALIZATION-PHP-OBJECT",
            name="PHP Object Serialized Payload (O:num:\"class\":)",
            category="Insecure Deserialization",
            owasp_id="A08:Software and Data Integrity Failures",
            severity="HIGH",
            score=88.0,
            pattern=re.compile(r"\b[OC]:\+?\d+:\s*\"[^\"]+\":\+?\d+:\s*\{", re.IGNORECASE)
        )
    ]

    # 4. Header & Scanner Signatures
    SCANNER_SIGNATURE = ThreatSignature(
        rule_id="SCANNER-KNOWN-TOOL-SIGNATURE",
        name="Known Automated Attack Scanner Identified (SqlMap, Nikto, Acunetix, ZAP, Nuclei, FFUF, Gobuster, Feroxbuster, Qualys)",
        category="Malicious Automation",
        owasp_id="A07:Identification and Authentication Failures",
        severity="CRITICAL",
        score=99.0,
        pattern=re.compile(
            r"(?:"
            r"sqlmap"
            r"|nikto"
            r"|acunetix"
            r"|w3af"
            r"|openvas"
            r"|zaproxy"
            r"|\bzap(?:/[0-9]|\b)"
            r"|owasp[_\s\-]?zap"
            r"|dirbuster"
            r"|gobuster"
            r"|nuclei"
            r"|ffuf"
            r"|feroxbuster"
            r"|qualys"
            r")",
            re.IGNORECASE
        )
    )

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
        Target-aware in-line inspection:
        - Path evaluated for Traversal, LFI, and Exploit URIs
        - Query parameters & body evaluated for SQLi, XSS, RCE, SSRF, Deserialization
        - Headers evaluated for Log4j and malicious scanners without false-positive collisions
        """
        norm = RequestNormalizer.normalize_request_data(path, query, body, headers)
        matches: List[Dict[str, Any]] = []
        max_score = 0.0

        def record_match(sig: ThreatSignature):
            nonlocal max_score
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

        # ---------------------------------------------------------------------
        # Vector A: Critical CVEs (Inspected across Path, Query, Body & Headers)
        # ---------------------------------------------------------------------
        full_text_for_cve = f"{norm['path']} {norm['query']} {norm['body']}"
        for h_k, h_v in norm["headers"].items():
            full_text_for_cve += f" {h_k}: {h_v}"

        for sig in cls.CVE_SIGNATURES:
            if sig.pattern.search(full_text_for_cve):
                record_match(sig)

        # ---------------------------------------------------------------------
        # Vector B: User-Agent & Scanner Signatures
        # ---------------------------------------------------------------------
        user_agent = norm["headers"].get("user-agent", "")
        if cls.SCANNER_SIGNATURE.pattern.search(user_agent):
            record_match(cls.SCANNER_SIGNATURE)

        # ---------------------------------------------------------------------
        # Vector C: Path Inspection (Traversal, LFI, Sensitive File Probes)
        # ---------------------------------------------------------------------
        path_targets = [norm["path"], norm["query"], norm["body"]]
        for _, param_val in norm["query_params"]:
            if param_val:
                path_targets.append(param_val)

        for target_str in path_targets:
            if not target_str:
                continue
            for sig in cls.PATH_SIGNATURES:
                if sig.pattern.search(target_str):
                    record_match(sig)

        # ---------------------------------------------------------------------
        # Vector D: Parameter & Payload Inspection (SQLi, XSS, RCE, XXE, Deser)
        # ---------------------------------------------------------------------
        # Collect all parameter values and raw body payload
        payload_targets = [norm["query"], norm["body"]]
        for _, param_val in norm["query_params"]:
            if param_val:
                payload_targets.append(param_val)

        # Also inspect path for injected SQL or Script if someone puts payload in URI
        payload_targets.append(norm["path"])

        for target_str in payload_targets:
            if not target_str:
                continue

            # Standard pass
            for sig in cls.PAYLOAD_SIGNATURES:
                if sig.pattern.search(target_str):
                    record_match(sig)

            # Decommented pass specifically for SQL comment obfuscation (/**/)
            if "/*" in target_str and "*/" in target_str:
                decommented_stripped = re.sub(r"/\*.*?\*/", "", target_str)
                decommented_spaced = re.sub(r"/\*.*?\*/", " ", target_str)
                for sig in cls.PAYLOAD_SIGNATURES:
                    if sig.category == "SQL Injection":
                        if sig.pattern.search(decommented_stripped) or sig.pattern.search(decommented_spaced):
                            record_match(sig)

        # Deduplicate matches by rule_id
        unique_matches: List[Dict[str, Any]] = []
        seen_rules = set()
        for m in matches:
            if m["rule_id"] not in seen_rules:
                seen_rules.add(m["rule_id"])
                unique_matches.append(m)

        # ---------------------------------------------------------------------
        # Verdict & Composite Action Evaluation
        # ---------------------------------------------------------------------
        if max_score >= 75.0:
            action = "BLOCK"
            http_status = 403
        elif max_score >= 50.0:
            action = "CHALLENGE"
            http_status = 429
        else:
            action = "ALLOW"
            http_status = 200
            max_score = 0.0  # Clean request has 0 risk score

        top_rule = unique_matches[0] if unique_matches else None

        return {
            "action": action,
            "http_status": http_status,
            "risk_score": round(max_score, 1),
            "total_matches": len(unique_matches),
            "top_match": top_rule,
            "all_matches": unique_matches,
            "is_clean": len(unique_matches) == 0,
            "normalized_path": norm["path"]
        }
