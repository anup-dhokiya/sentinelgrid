"""
SentinelGrid Explainable Threat Intelligence Knowledge Base (X-TIKB)
Provides rich, plain-English explanations, attacker intent analysis, business impact ratings,
and remediation checklists for every threat detected by the Security Brain.
Designed so anyone—from junior developers to executive CISOs—can immediately understand the risk.
"""

from typing import Dict, Any, Optional

THREAT_PROFILES: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # Critical Remote Code Execution (RCE)
    # -------------------------------------------------------------------------
    "CVE-2021-44228-LOG4J": {
        "title": "Log4Shell Remote Code Execution (JNDI Lookup Injection)",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 100/100)",
        "cve": "CVE-2021-44228",
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "plain_english_summary": (
            "An attacker attempted to inject a malicious Java Naming and Directory Interface (JNDI) "
            "lookup string into the application. If vulnerable, the backend server would automatically connect "
            "to an attacker-controlled LDAP server, download malicious Java bytecode, and execute it with full server privileges."
        ),
        "attacker_objective": "Complete server takeover, installation of backdoors/ransomware, and corporate network lateral movement.",
        "why_blocked": "Request contained unescaped '${jndi:ldap:...}' syntax in HTTP headers, parameters, or body.",
        "business_impact": "Total data breach, complete loss of server control, catastrophic operational downtime, regulatory non-compliance.",
        "remediation_steps": [
            "Upgrade Apache Log4j library to version 2.17.1 or higher immediately.",
            "Remove the JndiLookup class from log4j-core JAR files if patching is delayed.",
            "Ensure outbound LDAP (port 389) and RMI (port 1099) network traffic from servers is blocked by firewall egress rules."
        ]
    },
    "CVE-2022-22965-SPRING4SHELL": {
        "title": "Spring4Shell ClassLoader Access Exploit Probe",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 100/100)",
        "cve": "CVE-2022-22965",
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "plain_english_summary": (
            "The client attempted to exploit a design flaw in Spring Framework's data-binding mechanism by submitting "
            "'class.module.classLoader' parameters. If successful, this modifies JVM ClassLoader properties to drop a webshell into the Tomcat webroot."
        ),
        "attacker_objective": "Drop a persistent backdoor webshell (.jsp) on the server to execute arbitrary shell commands.",
        "why_blocked": "Identified parameter manipulation targeting Tomcat/Spring classLoader properties.",
        "business_impact": "Persistent remote backdoor access, exfiltration of application databases and API keys.",
        "remediation_steps": [
            "Upgrade Spring Framework to 5.3.18+ or 5.2.20+.",
            "Upgrade Spring Boot to 2.6.6+ or 2.5.12+.",
            "Disallow fields starting with 'class.*' in WebDataBinder."
        ]
    },
    "CVE-2024-4577-PHP-CGI-RCE": {
        "title": "PHP-CGI Windows Argument Injection (CVE-2024-4577)",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 100/100)",
        "cve": "CVE-2024-4577",
        "mitre_attack": "T1059.004 - Command and Scripting Interpreter: Unix Shell",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "plain_english_summary": (
            "An attacker utilized soft-hyphen character encoding (%AD) to bypass Windows character conversion protections, "
            "passing command-line arguments to the PHP engine to enable arbitrary code execution via 'allow_url_include'."
        ),
        "attacker_objective": "Execute arbitrary operating system commands on the Windows web host.",
        "why_blocked": "Request contained obfuscated PHP-CGI argument injection '%ADd' or 'auto_prepend_file=php://input'.",
        "business_impact": "Host operating system compromise, domain privilege escalation, ransomware distribution.",
        "remediation_steps": [
            "Upgrade PHP to versions 8.3.8+, 8.2.20+, or 8.1.29+.",
            "Migrate away from legacy PHP-CGI in favor of PHP-FPM or FastCGI.",
            "Block query parameters containing '-d' or soft-hyphen characters via SentinelGrid."
        ]
    },
    "CVE-2024-3400-PANOS-CMDI": {
        "title": "Palo Alto Networks PAN-OS GlobalProtect Command Injection (CVE-2024-3400)",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 100/100)",
        "cve": "CVE-2024-3400",
        "mitre_attack": "T1059 - Command and Scripting Interpreter",
        "owasp": "A03:2021 - Injection",
        "plain_english_summary": (
            "An attacker targeted the GlobalProtect portal with crafted session telemetry filenames to trigger "
            "unauthenticated root-level command injection via shell scripts."
        ),
        "attacker_objective": "Gain unauthenticated root access to perimeter firewall/gateway appliances.",
        "why_blocked": "Detected path traversal and shell injection targeting `/ssl-vpn/hipreport.esp`.",
        "business_impact": "Complete compromise of network perimeter security, MITM interception of corporate traffic.",
        "remediation_steps": [
            "Apply Palo Alto Networks hotfix patches immediately.",
            "Disable Device Telemetry temporarily if hotfix is pending."
        ]
    },
    "CVE-2023-46604-ACTIVEMQ": {
        "title": "Apache ActiveMQ OpenWire Remote Code Execution (CVE-2023-46604)",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 100/100)",
        "cve": "CVE-2023-46604",
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "plain_english_summary": (
            "The client submitted manipulated OpenWire protocol packets containing ClassPathXmlApplicationContext "
            "references to force unauthenticated remote XML configuration loading and code execution."
        ),
        "attacker_objective": "Execute arbitrary code on the message broker server and pivot into backend message queues.",
        "why_blocked": "Detected ClassPathXmlApplicationContext polymorphic gadget invocation.",
        "business_impact": "Total loss of message broker integrity, interception of customer events and payment payloads.",
        "remediation_steps": [
            "Upgrade Apache ActiveMQ to 5.15.16+, 5.16.7+, 5.17.6+, or 5.18.3+.",
            "Restrict access to OpenWire port 61616 using private VPC network rules."
        ]
    },
    # -------------------------------------------------------------------------
    # Cloud Credential Theft & SSRF
    # -------------------------------------------------------------------------
    "SSRF-CLOUD-IMDS-AWS": {
        "title": "AWS Cloud Instance Metadata Service (IMDS) Credential Theft",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 98/100)",
        "cve": "N/A (Cloud Metadata Exploitation)",
        "mitre_attack": "T1552.005 - Cloud Instance Metadata API",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "plain_english_summary": (
            "The client tried to trick the backend server into querying AWS internal metadata IP (169.254.169.254). "
            "If the server blindly fetches this URL, the attacker receives the temporary IAM security credentials for the server's role."
        ),
        "attacker_objective": "Steal AWS IAM access keys and assume cloud administrative roles to access S3 buckets and databases.",
        "why_blocked": "Identified direct, decimal, octal, hex, or IPv6 encoded references to AWS metadata endpoints.",
        "business_impact": "Total cloud infrastructure takeover, unauthorized database downloads, massive cloud billing abuse.",
        "remediation_steps": [
            "Enforce IMDSv2 (token-based session requirement with hop limit = 1) across all EC2 instances.",
            "Validate and restrict all server-side outgoing URL requests using a strict allowlist of domains.",
            "Ensure your application network layer rejects requests destined for link-local addresses (169.254.0.0/16)."
        ]
    },
    "SSRF-CLOUD-METADATA-GCP-AZURE": {
        "title": "GCP/Azure Cloud Metadata API Exfiltration Attempt",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 98/100)",
        "cve": "N/A (Cloud Metadata Exploitation)",
        "mitre_attack": "T1552.005 - Cloud Instance Metadata API",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "plain_english_summary": (
            "The client attempted to trigger a Server-Side Request Forgery targeting Google Cloud (metadata.google.internal) "
            "or Azure instance metadata endpoints to extract OAuth service account tokens."
        ),
        "attacker_objective": "Steal GCP/Azure service account access tokens to compromise cloud project resources.",
        "why_blocked": "Detected request destined for cloud metadata endpoints.",
        "business_impact": "Cloud project compromise, access to production BigQuery/GCS buckets.",
        "remediation_steps": [
            "Enforce metadata server headers (Metadata-Flavor: Google) and disable legacy metadata endpoints.",
            "Enforce egress firewall filters preventing workloads from accessing 169.254.169.254."
        ]
    },
    # -------------------------------------------------------------------------
    # SQL Injection (SQLi)
    # -------------------------------------------------------------------------
    "SP-SQL-UNION-SELECT": {
        "title": "SmartParse AST: SQL Injection UNION-Based Schema Exfiltration",
        "severity": "CRITICAL",
        "risk_tier": "Critical Adversarial Threat (Score: 98/100)",
        "cve": "CWE-89",
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "owasp": "A03:2021 - Injection",
        "plain_english_summary": (
            "An attacker injected a 'UNION SELECT' statement into a query parameter to append their own database query "
            "to the application's query. This forces the database to return confidential records (user passwords, tokens) alongside normal data."
        ),
        "attacker_objective": "Dump entire database contents, bypass user authentication, extract password hashes.",
        "why_blocked": "SmartParse Deterministic Finite Automaton detected high-risk SQL token sequence (UNION ... SELECT).",
        "business_impact": "Catastrophic data breach, disclosure of customer PII, credential leakage.",
        "remediation_steps": [
            "Use parameterized SQL queries (prepared statements) with PDO, SQLAlchemy, or ActiveRecord.",
            "Never concatenate raw user input directly into SQL query strings.",
            "Enforce least-privilege database user accounts."
        ]
    },
    "SP-SQL-BOUNDARY-BREAKOUT": {
        "title": "SmartParse AST: SQL Comment-Slicing & Tautology Breakout",
        "severity": "CRITICAL",
        "risk_tier": "Critical Authentication Bypass Threat (Score: 98/100)",
        "cve": "CWE-89",
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "owasp": "A03:2021 - Injection",
        "plain_english_summary": (
            "The client utilized inline SQL comment markers (/**/) or hash characters (#) to break out of literal string "
            "quotes and inject tautological conditions (OR 1=1), aiming to bypass login credentials."
        ),
        "attacker_objective": "Bypass authentication gates and login as administrator without a valid password.",
        "why_blocked": "Detected obfuscated comment-slicing and boolean tautology syntax.",
        "business_impact": "Unauthorized administrative login, account takeover.",
        "remediation_steps": [
            "Enforce prepared statements with strict parameter binding.",
            "Reject inputs containing unbalanced quote or inline SQL comment sequences."
        ]
    },
    # -------------------------------------------------------------------------
    # Cross-Site Scripting (XSS)
    # -------------------------------------------------------------------------
    "SP-DOM-DANGEROUS-TAG": {
        "title": "SmartParse AST: Cross-Site Scripting (XSS) Executable Tag Injection",
        "severity": "HIGH",
        "risk_tier": "Adversarial Client-Side Attack (Score: 90/100)",
        "cve": "CWE-79",
        "mitre_attack": "T1189 - Drive-by Compromise",
        "owasp": "A03:2021 - Injection",
        "plain_english_summary": (
            "The client attempted to inject executable HTML tags (<script>, <svg>, <object>) into application fields. "
            "If displayed to other users without encoding, the injected JavaScript executes in their browser context."
        ),
        "attacker_objective": "Steal session cookies, hijack victim accounts, deface the website, or redirect users to phishing portals.",
        "why_blocked": "Identified dangerous DOM tags in request parameters or body.",
        "business_impact": "Account takeovers, credential theft, loss of customer trust.",
        "remediation_steps": [
            "Contextually encode all untrusted output before rendering in HTML.",
            "Enforce a strict Content Security Policy (CSP) blocking inline scripts."
        ]
    },
    # -------------------------------------------------------------------------
    # Mobile & API Protection (OWASP API Top 10)
    # -------------------------------------------------------------------------
    "MOBILE-HOOKING-FRAMEWORK-FRIDA": {
        "title": "Mobile App Hooking & Memory Tampering (Frida Framework)",
        "severity": "CRITICAL",
        "risk_tier": "Adversarial Reverse Engineering Threat (Score: 94/100)",
        "cve": "MASVS-RESILIENCE",
        "mitre_attack": "T1407 - Dynamic Instrumentation",
        "owasp": "M08:2024 - Code Tampering",
        "plain_english_summary": (
            "The client request originated from a mobile application runtime instrumented by Frida. "
            "Attackers use Frida to bypass certificate pinning, inspect in-memory cryptography keys, and modify API return values."
        ),
        "attacker_objective": "Bypass SSL pinning, manipulate financial transactions, or dump mobile client application secrets.",
        "why_blocked": "Detected Frida instrumentation headers, agent signatures, or memory-hooking parameters.",
        "business_impact": "Compromise of mobile app integrity, unauthorized access to mobile banking/commerce APIs.",
        "remediation_steps": [
            "Implement runtime application self-protection (RASP) on mobile clients.",
            "Enforce cryptographic hardware attestation (Apple DeviceCheck / Google Play Integrity)."
        ]
    },
    "JWT-ALG-NONE-BYPASS": {
        "title": "JSON Web Token (JWT) Signature Stripping ('alg': 'none')",
        "severity": "CRITICAL",
        "risk_tier": "Critical Authentication Bypass (Score: 98/100)",
        "cve": "CWE-347",
        "mitre_attack": "T1556 - Modify Authentication Process",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "plain_english_summary": (
            "The client submitted a modified authentication token where the cryptographic algorithm was set to 'none'. "
            "If accepted by a vulnerable server, the attacker impersonates any user (including admin) without a valid signature."
        ),
        "attacker_objective": "Gain full administrator privileges by forging an unverified authentication token.",
        "why_blocked": "Detected JWT token containing 'alg': 'none' or missing third signature segment.",
        "business_impact": "Full authentication bypass, unauthorized administrative access, privilege escalation.",
        "remediation_steps": [
            "Configure JWT validation libraries to explicitly require asymmetric algorithms (RS256, EdDSA) or HMAC (HS256).",
            "Explicitly reject any token where 'alg' is set to 'none' or empty."
        ]
    },
    # -------------------------------------------------------------------------
    # Verified Clean Traffic
    # -------------------------------------------------------------------------
    "CLEAN-REQUEST-PASS": {
        "title": "Verified Legitimate Traffic",
        "severity": "BENIGN",
        "risk_tier": "Clean Telemetry (Score: 0/100)",
        "cve": "N/A",
        "mitre_attack": "N/A",
        "owasp": "None",
        "plain_english_summary": "This request passed all deep protocol inspections, AST boundary analysis, and threat intelligence checks. No malicious indicators were detected.",
        "attacker_objective": "Normal user browsing or legitimate API integration.",
        "why_blocked": "N/A (Request was permitted to reach origin server).",
        "business_impact": "None. Normal application operation.",
        "remediation_steps": ["No remediation necessary."]
    }
}


def get_threat_profile(rule_id: str, category: Optional[str] = None, cve_ref: Optional[str] = None) -> Dict[str, Any]:
    """Retrieves or synthesizes a human-readable threat explanation profile for any rule."""
    if rule_id in THREAT_PROFILES:
        return THREAT_PROFILES[rule_id]

    for key, profile in THREAT_PROFILES.items():
        if key in rule_id or rule_id in key:
            return profile

    cat = (category or "").lower()
    r_lower = rule_id.lower()
    if "sql" in cat or "sqli" in r_lower:
        return {
            "title": f"SQL Injection Vulnerability Attempt ({rule_id})",
            "severity": "CRITICAL",
            "risk_tier": "Critical Adversarial Threat (Score: 98/100)",
            "cve": "CWE-89",
            "mitre_attack": "T1190 - Exploit Public-Facing Application",
            "owasp": "A03:2021 - Injection",
            "plain_english_summary": "An attacker attempted to manipulate database queries by injecting structured SQL syntax into input fields.",
            "attacker_objective": "Extract data, bypass authentication, or corrupt the database.",
            "why_blocked": f"Triggered SQL syntax break or AST anomaly: {rule_id}",
            "business_impact": "Data breach, unauthorized modification of financial/user records.",
            "remediation_steps": ["Use prepared statements and parameterized queries for all database interactions."]
        }
    elif "cross-site scripting" in cat or "xss" in r_lower or "dom" in r_lower:
        return {
            "title": f"Cross-Site Scripting (XSS) Exploit Attempt ({rule_id})",
            "severity": "HIGH",
            "risk_tier": "Adversarial Client-Side Attack (Score: 88/100)",
            "cve": "CWE-79",
            "mitre_attack": "T1189 - Drive-by Compromise",
            "owasp": "A03:2021 - Injection",
            "plain_english_summary": "An attacker attempted to inject executable JavaScript code into web pages viewed by other users.",
            "attacker_objective": "Steal session cookies, hijack victim accounts, or redirect users to phishing portals.",
            "why_blocked": f"Detected HTML tags, script elements, or DOM event handlers: {rule_id}",
            "business_impact": "Account takeovers, credential theft, loss of customer trust.",
            "remediation_steps": ["Contextually encode all untrusted output before rendering in HTML, and enforce a strong Content Security Policy (CSP)."]
        }
    elif "traversal" in cat or "lfi" in r_lower:
        return {
            "title": f"Path Traversal & Local File Inclusion ({rule_id})",
            "severity": "CRITICAL",
            "risk_tier": "Critical Server File Access Attempt (Score: 96/100)",
            "cve": "CWE-22",
            "mitre_attack": "T1083 - File and Directory Discovery",
            "owasp": "A01:2021 - Broken Access Control",
            "plain_english_summary": "The client used directory traversal sequences (such as ../..) to navigate outside the intended public web folder.",
            "attacker_objective": "Read sensitive server files such as /etc/passwd, configuration files, and database passwords.",
            "why_blocked": "Identified relative path navigation or attempts to read system configuration files.",
            "business_impact": "Exposure of system credentials, server source code, and API secrets.",
            "remediation_steps": ["Sanitize file paths using path canonicalization (e.g. realpath) and restrict file serving to a strict root directory."]
        }

    return {
        "title": f"Security Anomaly Intercepted ({rule_id})",
        "severity": "HIGH",
        "risk_tier": "Suspicious Request (Score: 85/100)",
        "cve": cve_ref or "N/A",
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "owasp": "A04:2021 - Insecure Design",
        "plain_english_summary": f"This request triggered security policy rule '{rule_id}' due to abnormal or malicious syntax patterns.",
        "attacker_objective": "Probe the server for weaknesses or exploit unpatched vulnerabilities.",
        "why_blocked": f"Rule {rule_id} was matched during deep inspection.",
        "business_impact": "Potential compromise depending on backend application vulnerabilities.",
        "remediation_steps": ["Review request parameters and ensure proper input validation on the endpoint."]
    }
