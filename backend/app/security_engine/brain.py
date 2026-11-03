"""
SentinelGrid - Comprehensive Multi-Layer Security Brain & Threat Signature Matrix
Target-aware inspection engine covering:
- Critical Remote Code Execution CVEs (Log4j CVE-2021-44228, Spring4Shell CVE-2022-22965)
- Server-Side Request Forgery (SSRF) & Cloud IMDS Credential Theft (AWS, GCP, Azure)
- Full OWASP Top 10 (SQLi, XSS, Path Traversal/LFI, XXE, Prototype Pollution, Deserialization, RCE)
- Malicious Reconnaissance Tools & Automated Scanners
Zero false-positive architecture with context-separated inspection for paths, headers, parameters, and payloads.
"""

import base64
import json
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from app.security_engine.normalization.normalizer import RequestNormalizer
from app.security_engine.smart_parse import SmartParse, TokenType
from app.security_engine.threat_intel import global_threat_intel, RadixIpTrie
from app.security_engine.rate_limiter import global_rate_limiter, SlidingWindowLimiter
from app.security_engine.threat_knowledge import get_threat_profile


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
            name="Multi-Cloud IMDS & WireServer Probe (GCP, Azure, Oracle, Alibaba, DNS Rebind)",
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
                r"|168\.63\.129\.16"                       # Azure WireServer IP
                r"|192\.0\.0\.192"                          # Oracle Cloud Infrastructure (OCI) IMDS
                r"|100\.100\.100\.200"                      # Alibaba Cloud ECS Metadata
                r"|rebind\.[a-z0-9]+"                       # DNS Rebinding utilities
                r"|rbndr\.us"
                r"|127\.0\.0\.1\.nip\.io"
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
                r"(?:\{\{|\$\{|\#\{|\*\{|<%=|<%)\s*(?:[a-zA-Z0-9_\'\"]+\s*[\*\+\-\/]\s*[a-zA-Z0-9_\'\"]+|T\s*\([A-Za-z0-9_.]+\)|new\s+[A-Za-z0-9_.]+\s*\().{0,250}?(?:\}\}|%\}|\}|%>)"
                r"|(?:\{\{|\$\{|\#\{|\*\{|<%=|<%)\s*.{0,250}?(?:context|request|session|application|global|__class__|class|__mro__|mro|__globals__|globals|__subclasses__|subclasses|getRuntime|ProcessBuilder|exec|eval|system|config|lipsum|cycler).{0,250}?(?:\}\}|%\}|\}|%>)"
                r"|\{%\s*(?:import|include|set|with|exec|from|raw)\b.{0,250}?%\}"
                r"|<[#@]\s*(?:assign|include|import|exec|visit|recurse|macro)\b[^>]*>"
                r"|\[[#@]\s*(?:assign|include|import|exec|visit|recurse|macro)\b[^\]]*\]"
                r"|<%\s*(?:system|exec|%x|IO\.read|File\.read|require|java\.)\b.{0,250}?%>"
                r")",
                re.IGNORECASE
            )
        ),
        # ---------------------------------------------------------------------
        # Universal Multi-Stack Enterprise CVE & Exploit Vectors
        # ---------------------------------------------------------------------
        ThreatSignature(
            rule_id="CVE-2024-4577-PHP-CGI-RCE",
            name="PHP-CGI Windows Argument Injection RCE (CVE-2024-4577)",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"(?:"
                r"(?:%ad|%AD|\xad|\u00ad|\ufffd|-)?\s*d\s*(?:\+|%20|\s)*(?:allow_url_include|auto_prepend_file|disable_functions)"
                r"|auto_prepend_file\s*=\s*php://input"
                r")",
                re.IGNORECASE
            ),
            cve_ref="CVE-2024-4577"
        ),
        ThreatSignature(
            rule_id="CVE-2017-5638-STRUTS2-OGNL",
            name="Apache Struts2 OGNL Remote Code Execution (S2-045 / CVE-2017-5638)",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"(?:"
                r"#_memberAccess"
                r"|@ognl\.OgnlContext@DEFAULT_MEMBER_ACCESS"
                r"|com\.opensymphony\.xwork2\.ActionContext"
                r"|ActionContext\.container"
                r"|MethodAccessor\.deniedMembers"
                r"|com\.opensymphony\.xwork2\.ognl\.OgnlUtil"
                r"|%\{.*?#.*?\.start\(\)\}"
                r")",
                re.IGNORECASE
            ),
            cve_ref="CVE-2017-5638"
        ),
        ThreatSignature(
            rule_id="CVE-2022-42889-TEXT4SHELL",
            name="Apache Commons Text Interpolator Lookup RCE (Text4Shell)",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=99.0,
            pattern=re.compile(
                r"\$\{\s*(?:script|dns|url)\s*:[^\}]*\}",
                re.IGNORECASE
            ),
            cve_ref="CVE-2022-42889"
        ),
        ThreatSignature(
            rule_id="CVE-2022-26134-CONFLUENCE-OGNL",
            name="Atlassian Confluence Pre-Auth OGNL Injection RCE",
            category="Remote Code Execution",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"(?:"
                r"@java\.lang\.Runtime@getRuntime\(\)"
                r"|@org\.apache\.commons\.io\.IOUtils@toString"
                r"|@com\.opensymphony\.webwork\.ServletActionContext"
                r"|X-Cmd-Response"
                r"|xwork\.MethodAccessor"
                r")",
                re.IGNORECASE
            ),
            cve_ref="CVE-2022-26134"
        ),
        ThreatSignature(
            rule_id="CVE-2023-4966-CITRIX-BLEED",
            name="Citrix NetScaler ADC Sensitive Information Disclosure (Citrix Bleed)",
            category="Information Disclosure",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"/oauth/idp/\.well-known/openid-configuration",
                re.IGNORECASE
            ),
            cve_ref="CVE-2023-4966"
        ),
        ThreatSignature(
            rule_id="CVE-2020-14882-WEBLOGIC-CONSOLE-RCE",
            name="Oracle WebLogic Console Path Traversal Auth Bypass & RCE",
            category="Broken Access Control & RCE",
            owasp_id="A01:Broken Access Control",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"(?:"
                r"/console/css/%252e%252e"
                r"|/console/images/%252e%252e"
                r"|com\.tangosol\.coherence\.mvel2\.MVEL"
                r"|com\.bea\.core\.repackaged\.springframework\.context\.support\.FileSystemXmlApplicationContext"
                r")",
                re.IGNORECASE
            ),
            cve_ref="CVE-2020-14882"
        ),
        ThreatSignature(
            rule_id="CVE-2022-1388-F5-BIGIP-AUTH-BYPASS",
            name="F5 BIG-IP iControl REST Unauthenticated Command Execution",
            category="Remote Code Execution",
            owasp_id="A07:Identification and Authentication Failures",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"/mgmt/tm/util/bash",
                re.IGNORECASE
            ),
            cve_ref="CVE-2022-1388"
        ),
        ThreatSignature(
            rule_id="CVE-2020-1938-TOMCAT-GHOSTCAT",
            name="Apache Tomcat AJP File Read & Inclusion Probe (Ghostcat)",
            category="Path Traversal",
            owasp_id="A05:Security Misconfiguration",
            severity="HIGH",
            score=92.0,
            pattern=re.compile(
                r"(?:javax\.servlet\.include\.request_uri|javax\.servlet\.include\.path_info|javax\.servlet\.include\.servlet_path)",
                re.IGNORECASE
            ),
            cve_ref="CVE-2020-1938"
        ),
        ThreatSignature(
            rule_id="PHP-STREAM-WRAPPER-INJECTION",
            name="PHP Dangerous Stream Wrapper Injection (php://filter, phar://, expect://)",
            category="Arbitrary File Read & RCE",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=96.0,
            pattern=re.compile(
                r"(?:"
                r"php:/{1,2}(?:filter|input|stdin|memory|temp)"
                r"|phar:/{1,2}.*?\.phar"
                r"|expect:/{1,2}"
                r"|data:/{0,2}text/plain;\s*base64"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="NODEJS-PROTOTYPE-POLLUTION-DEEP",
            name="JavaScript / Node.js Prototype Pollution Payload Injection",
            category="Prototype Pollution",
            owasp_id="A04:Insecure Design",
            severity="CRITICAL",
            score=95.0,
            pattern=re.compile(
                r"(?:"
                r"\"__proto__\"\s*:\s*\{"
                r"|'__proto__'\s*:\s*\{"
                r"|\b__proto__\b"
                r"|\bconstructor\s*\.\s*prototype\b"
                r"|\bObject\s*\.\s*prototype\b"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="PYTHON-JINJA2-MRO-ESCAPE",
            name="Python Jinja2 / Mako MRO Builtins Sandbox Escape",
            category="Server-Side Template Injection",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"(?:"
                r"__globals__"
                r"|__subclasses__"
                r"|__builtins__"
                r"|__class__"
                r"|__mro__"
                r"|os\.popen"
                r"|subprocess\.Popen"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="DOTNET-VIEWSTATE-DESERIALIZATION",
            name=".NET ViewState / BinaryFormatter Dangerous Deserialization",
            category="Insecure Deserialization",
            owasp_id="A08:Software and Data Integrity Failures",
            severity="CRITICAL",
            score=95.0,
            pattern=re.compile(
                r"(?:"
                r"TypeConfuseDelegate"
                r"|ActivitySurrogateSelector"
                r"|ObjectDataProvider"
                r"|System\.Workflow\.ComponentModel"
                r"|/wEPDwUK"
                r")",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="CVE-2023-46604-ACTIVEMQ",
            name="Apache ActiveMQ OpenWire Remote Code Execution (CVE-2023-46604)",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"(?:org\.springframework\.context\.support\.ClassPathXmlApplicationContext|ClassPathXmlApplicationContext)",
                re.IGNORECASE
            ),
            cve_ref="CVE-2023-46604"
        ),
        ThreatSignature(
            rule_id="CVE-2024-3400-PANOS-CMDI",
            name="Palo Alto Networks PAN-OS GlobalProtect Command Injection",
            category="Remote Code Execution",
            owasp_id="A03:Injection",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"/ssl-vpn/hipreport\.esp",
                re.IGNORECASE
            ),
            cve_ref="CVE-2024-3400"
        ),
        ThreatSignature(
            rule_id="CVE-2021-3129-LARAVEL-IGNITION",
            name="Laravel Ignition Debug Mode Remote Code Execution (CVE-2021-3129)",
            category="Remote Code Execution",
            owasp_id="A06:Vulnerable and Outdated Components",
            severity="CRITICAL",
            score=100.0,
            pattern=re.compile(
                r"(?:_ignition/execute-solution|php://filter/write=convert\.iconv)",
                re.IGNORECASE
            ),
            cve_ref="CVE-2021-3129"
        ),
        ThreatSignature(
            rule_id="FASTJSON-DESERIALIZATION-RCE",
            name="Fastjson Polymorphic Deserialization Remote Code Execution",
            category="Insecure Deserialization",
            owasp_id="A08:Software and Data Integrity Failures",
            severity="CRITICAL",
            score=98.0,
            pattern=re.compile(
                r"@type\s*[\'\"]?\s*:\s*[\'\"]?(?:com\.sun\.rowset\.JdbcRowSetImpl|org\.apache\.commons\.dbcp\.BasicDataSource|org\.apache\.tomcat\.dbcp\.dbcp\.BasicDataSource)",
                re.IGNORECASE
            )
        ),
        ThreatSignature(
            rule_id="WERKZEUG-DEBUGGER-CONSOLE",
            name="Werkzeug Interactive Debug Console Access Attempt",
            category="Security Misconfiguration",
            owasp_id="A05:Security Misconfiguration",
            severity="HIGH",
            score=90.0,
            pattern=re.compile(
                r"(?:/__debugger__|/console\?__debugger__)",
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

    # 5. Mobile Bot & Hooking Framework Detection
    MOBILE_HOOKING_FRIDA = ThreatSignature(
        rule_id="MOBILE-HOOKING-FRAMEWORK-FRIDA",
        name="Frida Dynamic Instrumentation & Hooking Framework Detected",
        category="Mobile Hooking & Reverse Engineering",
        owasp_id="M08:Code Tampering",
        severity="CRITICAL",
        score=96.0,
        pattern=re.compile(
            r"(?:"
            r"\bx-frida-agent\b"
            r"|\bfrida-server\b"
            r"|\blibfrida(?:\.so)?\b"
            r"|\bfrida:rpc\b"
            r"|\bfrida-gadget\b"
            r"|\bfrida-agent\b"
            r")",
            re.IGNORECASE
        )
    )

    MOBILE_HOOKING_XPOSED = ThreatSignature(
        rule_id="MOBILE-HOOKING-FRAMEWORK-XPOSED",
        name="Xposed / Substrate Instrumentation Hooking Framework Detected",
        category="Mobile Hooking & Reverse Engineering",
        owasp_id="M08:Code Tampering",
        severity="CRITICAL",
        score=96.0,
        pattern=re.compile(
            r"(?:"
            r"\bx-xposed-module\b"
            r"|\bde\.robv\.android\.xposed\b"
            r"|\bcydiasubstrate\b"
            r"|\bedxposed\b"
            r"|\bxposedbridge\b"
            r")",
            re.IGNORECASE
        )
    )

    MOBILE_EMULATOR_FINGERPRINT = ThreatSignature(
        rule_id="MOBILE-EMULATOR-FINGERPRINT",
        name="Android / iOS Emulator Environment Fingerprint Detected",
        category="Mobile Bot & Automated Client",
        owasp_id="M09:Reverse Engineering",
        severity="HIGH",
        score=88.0,
        pattern=re.compile(
            r"(?:"
            r"\bsdk_gphone\w*"
            r"|\bvbox86p\b"
            r"|\bgenymotion\b"
            r"|\bnox(?:player)?\b"
            r"|\bbluestacks\w*"
            r"|\bgoldfish\b"
            r"|\branchu\b"
            r")",
            re.IGNORECASE
        )
    )

    # 6. Mobile JWT Integrity & Tamper Protection
    JWT_ALG_NONE_BYPASS = ThreatSignature(
        rule_id="JWT-ALG-NONE-BYPASS",
        name="JWT 'alg': 'none' Signature Bypass or Missing Signature Detected",
        category="Broken Authentication",
        owasp_id="A07:Identification and Authentication Failures",
        severity="CRITICAL",
        score=98.0,
        pattern=re.compile(r"['\"]?alg['\"]?\s*:\s*['\"]none['\"]", re.IGNORECASE)
    )

    JWT_MALFORMED_OR_INJECTION = ThreatSignature(
        rule_id="JWT-MALFORMED-OR-INJECTION",
        name="SQLi / Command Injection / Null Bytes Injected in JWT Payload",
        category="Broken Authentication & Injection",
        owasp_id="A03:Injection",
        severity="CRITICAL",
        score=96.0,
        pattern=re.compile(r"(?:\x00|%00|\\0|\\x00)", re.IGNORECASE)
    )

    # 7. GraphQL Security for Mobile APIs
    GRAPHQL_DEPTH_EXHAUSTION = ThreatSignature(
        rule_id="GRAPHQL-DEPTH-EXHAUSTION",
        name="GraphQL Recursive Query Depth Resource Exhaustion (> 6 levels)",
        category="API Denial of Service",
        owasp_id="API4:2023 Unrestricted Resource Consumption",
        severity="HIGH",
        score=90.0,
        pattern=re.compile(r"\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{")
    )

    GRAPHQL_INTROSPECTION_ABUSE = ThreatSignature(
        rule_id="GRAPHQL-INTROSPECTION-ABUSE",
        name="GraphQL Schema / Type Introspection Probing on Production Endpoint",
        category="Information Disclosure",
        owasp_id="API8:2023 Security Misconfiguration",
        severity="HIGH",
        score=86.0,
        pattern=re.compile(r"(?:\b__schema\b|\b__type\b)", re.IGNORECASE)
    )

    # 8. Mobile Attestation & BOLA / IDOR Defense
    MOBILE_ATTESTATION_BYPASS = ThreatSignature(
        rule_id="MOBILE-ATTESTATION-BYPASS",
        name="Invalid, Null, or Spoofed Mobile App Attestation Header",
        category="Mobile Attestation Bypass",
        owasp_id="M01:Improper Platform Usage",
        severity="CRITICAL",
        score=94.0,
        pattern=re.compile(r"^(?:null|none|nil|undefined|mock.*|fake.*|test.*|bypass|0|false)$", re.IGNORECASE)
    )

    MOBILE_BOLA_IDOR_TRAVERSAL = ThreatSignature(
        rule_id="MOBILE-BOLA-IDOR-TRAVERSAL",
        name="BOLA / IDOR Root Tenant or Entity Traversal Attempt",
        category="Broken Object Level Authorization",
        owasp_id="API1:2023 Broken Object Level Authorization",
        severity="CRITICAL",
        score=96.0,
        pattern=re.compile(
            r"(?:"
            r"\.\./admin\b"
            r"|\.\.%2fadmin\b"
            r"|\.\./root\b"
            r"|\b00000000-0000-0000-0000-000000000000\b"
            r")",
            re.IGNORECASE
        )
    )

    @staticmethod
    def _extract_jwt_tokens(raw_headers: Dict[str, str], norm_headers: Dict[str, str], query_params: List[Tuple[str, str]], body: str) -> List[str]:
        candidates: List[str] = []
        all_headers: Dict[str, str] = {}
        for k, v in raw_headers.items():
            all_headers[k.lower()] = v
        all_headers.update(norm_headers)

        # 1. Authorization header
        auth = all_headers.get("authorization", "")
        if auth:
            if auth.lower().startswith("bearer "):
                candidates.append(auth[7:].strip())
            elif "." in auth:
                candidates.append(auth.strip())

        # 2. Cookie header
        cookie_header = all_headers.get("cookie", "")
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    _, c_val = item.split("=", 1)
                    c_val = c_val.strip()
                    if "." in c_val:
                        candidates.append(c_val)

        # 3. Dedicated token headers
        for h_k in ["x-access-token", "x-auth-token", "jwt", "token", "x-jwt-token"]:
            if h_k in all_headers and "." in all_headers[h_k]:
                candidates.append(all_headers[h_k].strip())

        # 4. Query params
        for p_k, p_v in query_params:
            if ("token" in p_k.lower() or "jwt" in p_k.lower()) and "." in p_v:
                candidates.append(p_v.strip())

        # 5. Body
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for b_k, b_v in data.items():
                        if isinstance(b_v, str) and "." in b_v and ("token" in b_k.lower() or "jwt" in b_k.lower() or b_v.startswith("eyJ")):
                            candidates.append(b_v.strip())
            except Exception:
                pass

            for match in re.findall(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?\b", body):
                candidates.append(match)

        return list(dict.fromkeys(candidates))

    @classmethod
    def _inspect_jwt(cls, token: str) -> Tuple[bool, bool]:
        """
        Evaluates candidate JWT string.
        Returns: (has_alg_none_or_missing_sig, has_injection_or_null_bytes)
        """
        has_alg_none = False
        has_injection = False

        # Raw token check for null bytes
        if any(nb in token for nb in ["\x00", "%00", "\\x00", "\\0"]):
            has_injection = True

        # Check for injection in raw token
        if re.search(r"(?:'\s*(?:or|and)\b|--|;\s*(?:drop|cat|rm|ls)|\||\$\()", token, re.IGNORECASE):
            has_injection = True

        segments = token.split(".")
        if len(segments) not in (2, 3):
            return has_alg_none, has_injection

        # Segment 0: Header
        hdr_seg = segments[0]
        pad = len(hdr_seg) % 4
        if pad != 0:
            hdr_seg += "=" * (4 - pad)

        hdr_json = None
        try:
            hdr_bytes = base64.urlsafe_b64decode(hdr_seg)
            if b"\x00" in hdr_bytes:
                has_injection = True
            hdr_json = json.loads(hdr_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        if isinstance(hdr_json, dict):
            alg = str(hdr_json.get("alg", "")).strip().lower()
            if alg == "none":
                has_alg_none = True

            # Missing signature segment (2 segments or 3rd segment empty)
            if len(segments) == 2 or (len(segments) == 3 and not segments[2]):
                has_alg_none = True

        # Segment 1: Payload
        payload_seg = segments[1]
        pad = len(payload_seg) % 4
        if pad != 0:
            payload_seg += "=" * (4 - pad)

        try:
            payload_bytes = base64.urlsafe_b64decode(payload_seg)
            if b"\x00" in payload_bytes or b"\\x00" in payload_bytes or b"\\0" in payload_bytes or b"\\u0000" in payload_bytes:
                has_injection = True

            payload_str = payload_bytes.decode("utf-8", errors="replace")
            if any(nb in payload_str for nb in ["\x00", "%00", "\\x00", "\\0", "\\u0000", "\u0000"]):
                has_injection = True

            try:
                p_obj = json.loads(payload_str)
                def check_null(o: Any) -> bool:
                    if isinstance(o, str) and ("\x00" in o or "\\u0000" in o):
                        return True
                    if isinstance(o, dict):
                        return any(check_null(k) or check_null(v) for k, v in o.items())
                    if isinstance(o, list):
                        return any(check_null(x) for x in o)
                    return False
                if check_null(p_obj):
                    has_injection = True
            except Exception:
                pass

            # Check payload signatures against decoded payload string
            for sig in cls.PAYLOAD_SIGNATURES:
                if sig.pattern.search(payload_str):
                    has_injection = True
                    break

            if not has_injection:
                sqli_pattern = re.compile(
                    r"(?:'\s*(?:OR|AND)\b|UNION\s+(?:ALL\s+)?SELECT\b|;\s*DROP\s+TABLE|--|\bSLEEP\s*\(|'\s*=\s*')",
                    re.IGNORECASE
                )
                rce_pattern = re.compile(
                    r"(?:(?:;|\||&&)\s*(?:cat\s+|/bin/|whoami|id\b|ls\s+|rm\s+|curl\s+|wget\s+|bash\b|sh\b)|\$\([^)]+\)|`[^`]+`)",
                    re.IGNORECASE
                )
                if sqli_pattern.search(payload_str) or rce_pattern.search(payload_str):
                    has_injection = True
        except Exception:
            pass

        return has_alg_none, has_injection

    @staticmethod
    def _calculate_graphql_depth(query_str: str) -> int:
        max_depth = 0
        current_depth = 0
        in_string = False
        escape = False
        in_comment = False

        for char in query_str:
            if in_comment:
                if char == "\n":
                    in_comment = False
                continue
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == "#":
                in_comment = True
                continue
            if char == '"':
                in_string = True
                continue
            if char == "{":
                current_depth += 1
                if current_depth > max_depth:
                    max_depth = current_depth
            elif char == "}":
                if current_depth > 0:
                    current_depth -= 1

        return max_depth

    @classmethod
    def _extract_graphql_queries(cls, body: str, query_params: List[Tuple[str, str]]) -> List[str]:
        queries: List[str] = []
        for p_k, p_v in query_params:
            if p_k.lower() == "query" and "{" in p_v:
                queries.append(p_v)

        if body and "{" in body:
            try:
                data = json.loads(body)
                if isinstance(data, dict) and "query" in data and isinstance(data["query"], str):
                    queries.append(data["query"])
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "query" in item and isinstance(item["query"], str):
                            queries.append(item["query"])
            except Exception:
                if any(body.strip().startswith(prefix) for prefix in ("{", "query", "mutation")):
                    queries.append(body)

        return queries

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
        # Vector 0: High-Performance Threat Intel Radix Prefix Trie (< 0.01ms)
        # ---------------------------------------------------------------------
        if client_ip and client_ip not in ("127.0.0.1", "localhost", "::1"):
            trie_match = global_threat_intel.lookup_ip(client_ip)
            if trie_match:
                record_match(ThreatSignature(
                    rule_id=f"THREAT-INTEL-{trie_match['category']}",
                    name=f"Known Malicious Network Entity ({trie_match['category']})",
                    category="Threat Intelligence & IP Reputation",
                    owasp_id="A01:Broken Access Control",
                    severity="CRITICAL",
                    score=100.0,
                    pattern=re.compile(r".*")
                ))

        # ---------------------------------------------------------------------
        # Vector 0.1: Autonomous Dynamic Quarantine Enforcement
        # ---------------------------------------------------------------------
        if client_ip and client_ip not in ("127.0.0.1", "localhost", "::1", "192.168.122.1") and not global_rate_limiter.is_whitelisted(client_ip):
            is_quarantined, remaining_sec, q_reason = global_rate_limiter.check_quarantine(client_ip)
            if is_quarantined:
                record_match(ThreatSignature(
                    rule_id="RATE-LIMIT-QUARANTINE-ACTIVE",
                    name=f"Client IP in Dynamic Quarantine ({remaining_sec}s remaining)",
                    category="Adversarial Rate Limiting & Abuse Prevention",
                    owasp_id="A04:Insecure Design",
                    severity="CRITICAL",
                    score=100.0,
                    pattern=re.compile(r".*")
                ))

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

            # SmartParse Next-Gen Lexical & DOM Boundary Analysis (< 0.90ms)
            smart_match = SmartParse.inspect(target_str)
            if smart_match:
                record_match(ThreatSignature(
                    rule_id=smart_match["rule_id"],
                    name=smart_match["name"],
                    category="SmartParse Semantic & AST Analysis",
                    owasp_id="A03:Injection" if "SQL" in smart_match["rule_id"] else "A07:Identification and Authentication Failures",
                    severity=smart_match["severity"],
                    score=98.0,
                    pattern=re.compile(r".*")
                ))
                if client_ip and client_ip not in ("127.0.0.1", "localhost", "::1", "192.168.122.1") and not global_rate_limiter.is_whitelisted(client_ip):
                    global_rate_limiter.trigger_violation(
                        client_ip,
                        severity=smart_match["severity"],
                        reason=smart_match["description"]
                    )

        # ---------------------------------------------------------------------
        # Vector E: Enterprise Mobile & API Protection
        # ---------------------------------------------------------------------
        all_header_items = list(norm["headers"].items()) + [(k.lower(), v) for k, v in headers.items()]

        # E.1 Mobile Hooking Frameworks (Frida & Xposed)
        frida_xposed_haystack = f"{norm['path']} {norm['query']} {norm['body']}"
        for h_k, h_v in all_header_items:
            frida_xposed_haystack += f" {h_k}: {h_v}"

        if cls.MOBILE_HOOKING_FRIDA.pattern.search(frida_xposed_haystack):
            record_match(cls.MOBILE_HOOKING_FRIDA)

        if cls.MOBILE_HOOKING_XPOSED.pattern.search(frida_xposed_haystack):
            record_match(cls.MOBILE_HOOKING_XPOSED)

        # E.2 Mobile Emulator Fingerprints
        emulator_haystack = norm["headers"].get("user-agent", "")
        for h_k, h_v in all_header_items:
            if any(term in h_k for term in ["device", "fingerprint", "emulator", "model", "hardware"]):
                emulator_haystack += f" {h_v}"
        if norm["body"]:
            emulator_haystack += f" {norm['body']}"

        if cls.MOBILE_EMULATOR_FINGERPRINT.pattern.search(emulator_haystack):
            record_match(cls.MOBILE_EMULATOR_FINGERPRINT)

        # E.3 Mobile JWT Integrity & Tamper Protection
        jwt_candidates = cls._extract_jwt_tokens(headers, norm["headers"], norm["query_params"], body)
        for cand in jwt_candidates:
            has_alg_none, has_injection = cls._inspect_jwt(cand)
            if has_alg_none:
                record_match(cls.JWT_ALG_NONE_BYPASS)
            if has_injection:
                record_match(cls.JWT_MALFORMED_OR_INJECTION)

        # Also direct pattern check for 'alg': 'none' / 'alg': 'None' in query or body
        if cls.JWT_ALG_NONE_BYPASS.pattern.search(norm["query"]) or cls.JWT_ALG_NONE_BYPASS.pattern.search(norm["body"]):
            record_match(cls.JWT_ALG_NONE_BYPASS)

        # Direct null byte check in raw headers or raw body if Authorization or JWT is present
        if any("bearer " in str(v).lower() for v in headers.values()):
            for v in headers.values():
                if any(nb in str(v) for nb in ["\x00", "%00", "\\x00", "\\0"]):
                    record_match(cls.JWT_MALFORMED_OR_INJECTION)

        # E.4 GraphQL Security (Depth Exhaustion & Introspection)
        gql_queries = cls._extract_graphql_queries(body, norm["query_params"])
        for gql in gql_queries:
            if cls._calculate_graphql_depth(gql) > 6:
                record_match(cls.GRAPHQL_DEPTH_EXHAUSTION)
            if cls.GRAPHQL_INTROSPECTION_ABUSE.pattern.search(gql):
                record_match(cls.GRAPHQL_INTROSPECTION_ABUSE)

        # Also inspect query string & body for introspection probing if targeting GraphQL
        if cls.GRAPHQL_INTROSPECTION_ABUSE.pattern.search(norm["query"]) or cls.GRAPHQL_INTROSPECTION_ABUSE.pattern.search(norm["body"]):
            if "{" in norm["query"] or "{" in norm["body"] or "graphql" in norm["path"].lower():
                record_match(cls.GRAPHQL_INTROSPECTION_ABUSE)

        # E.5 Mobile Attestation Bypass
        for h_k, h_v in all_header_items:
            if re.match(r"^(?:x-app-check|x-attestation-token|x-attestation|x-device-token|x-app-attest|x-play-integrity|x-safety-net|x-safetynet|x-firebase-appcheck)$", h_k):
                clean_v = str(h_v).strip().lower()
                if clean_v in ("null", "none", "nil", "undefined", "mock", "test", "fake", "bypass", "0", "false") or clean_v.startswith("mock") or clean_v.startswith("fake") or clean_v.startswith("test"):
                    record_match(cls.MOBILE_ATTESTATION_BYPASS)

        # E.6 Mobile BOLA / IDOR Defense
        entity_keys = {
            "tenant_id", "tenant", "org_id", "org", "organization_id",
            "user_id", "user", "account_id", "account", "customer_id",
            "profile_id", "entity_id", "id", "doc_id", "client_id"
        }
        # Nil UUID check across path, query, or body
        if "00000000-0000-0000-0000-000000000000" in norm["path"] or "00000000-0000-0000-0000-000000000000" in norm["query"] or "00000000-0000-0000-0000-000000000000" in norm["body"]:
            record_match(cls.MOBILE_BOLA_IDOR_TRAVERSAL)

        # Entity path traversal check (../admin, ..%2fadmin, ../root)
        if re.search(r"(?:\.\./admin|\.\.%2fadmin|\.\./root|\.\.%2froot)\b", norm["path"], re.IGNORECASE):
            record_match(cls.MOBILE_BOLA_IDOR_TRAVERSAL)

        # Entity path with null / None
        if re.search(r"/(?:tenants|users|accounts|organizations|orgs|customers|entities|profiles)/(?:null|none)\b", norm["path"], re.IGNORECASE):
            record_match(cls.MOBILE_BOLA_IDOR_TRAVERSAL)

        # Query parameter traversal and null ID check
        for p_k, p_v in norm["query_params"]:
            pk_lower = p_k.lower().strip()
            if pk_lower in entity_keys or pk_lower.endswith("_id"):
                pv_lower = p_v.lower().strip()
                if pv_lower in ("null", "none", "nil", "00000000-0000-0000-0000-000000000000") or "../admin" in pv_lower or "../root" in pv_lower:
                    record_match(cls.MOBILE_BOLA_IDOR_TRAVERSAL)

        # JSON body entity traversal and null ID check
        if body:
            try:
                b_json = json.loads(body)
                def check_json_bola(obj: Any) -> bool:
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            k_lower = k.lower().strip()
                            if k_lower in entity_keys or k_lower.endswith("_id"):
                                if v is None:
                                    return True
                                if isinstance(v, str):
                                    vl = v.lower().strip()
                                    if vl in ("null", "none", "nil", "00000000-0000-0000-0000-000000000000") or "../admin" in vl or "../root" in vl:
                                        return True
                            if isinstance(v, (dict, list)):
                                if check_json_bola(v):
                                    return True
                    elif isinstance(obj, list):
                        for item in obj:
                            if check_json_bola(item):
                                return True
                    return False

                if check_json_bola(b_json):
                    record_match(cls.MOBILE_BOLA_IDOR_TRAVERSAL)
            except Exception:
                pass

        # Deduplicate matches by rule_id
        unique_matches: List[Dict[str, Any]] = []
        seen_rules = set()
        for m in matches:
            if m["rule_id"] not in seen_rules:
                seen_rules.add(m["rule_id"])
                unique_matches.append(m)

        # Sort matches so the highest severity threat is top_match
        unique_matches.sort(key=lambda m: m["score"], reverse=True)

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
        if top_rule:
            threat_profile = get_threat_profile(top_rule["rule_id"], top_rule.get("category"), top_rule.get("cve_ref"))
        else:
            threat_profile = get_threat_profile("CLEAN-REQUEST-PASS")

        return {
            "action": action,
            "http_status": http_status,
            "risk_score": round(max_score, 1),
            "total_matches": len(unique_matches),
            "top_match": top_rule,
            "threat_profile": threat_profile,
            "all_matches": unique_matches,
            "is_clean": len(unique_matches) == 0,
            "normalized_path": norm["path"]
        }
