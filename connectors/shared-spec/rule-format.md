# SentinelGrid WAF Rule Format Specification (v1.0)

## 1. Overview
SentinelGrid rules define pattern-matching, heuristic checks, and behavioural indicators evaluated by the local security engine on every incoming HTTP request.

## 2. Rule Structure
Each rule definition adheres to the following declarative JSON/YAML structure:

```yaml
rule_id: "SG-WAF-SQLI-001"
name: "SQL Injection - Union Based Extraction"
category: "sqli"
severity: "critical"
confidence: 0.95
description: "Detects UNION SELECT statements attempting unauthorized database extraction."
match_targets:
  - location: "query"
  - location: "body"
  - location: "path"
transforms:
  - "url_decode"
  - "lowercase"
  - "remove_whitespace"
patterns:
  - type: "regex"
    pattern: "(?i)union\s+(all\s+)?select\s+.*"
  - type: "keyword"
    keyword: "union select"
risk_contribution: 85
default_action: "block"
```

## 3. Supported Categories
- `sqli`: SQL Injection (union-based, error-based, boolean-blind, time-blind, inline comments).
- `xss`: Cross-Site Scripting (stored, reflected, DOM-based `<script>`, event handlers, `javascript:` pseudoprotocol).
- `path_traversal`: Directory Traversal / Path Traversal (`../`, `..\\`, `%2e%2e%2f`, null bytes `%00`).
- `rfi_lfi`: Remote & Local File Inclusion (`file://`, `php://input`, `php://filter`, `/etc/passwd`, `C:\windows\win.ini`).
- `command_injection`: OS Command Injection (`;`, `|`, `&&`, backticks, `$(...)`, `powershell`, `wget`, `curl`).
- `suspicious_http_method`: Arbitrary or disabled HTTP verbs (e.g. `DEBUG`, `PUT` on static routes, `TRACK`, `TRACE`).
- `credential_stuffing`: Rapid repeated POST attempts against authentication endpoints (`/login`, `/wp-login.php`, `/api/auth/token`).
- `rate_abuse`: High request frequency exceeding per-client or per-IP tokens.
- `bot_abuse`: Headless scraper signatures, automated vulnerability scanners (e.g. `sqlmap`, `nikto`, `acunetix`, missing `User-Agent`).
- `reputation_blacklist`: High-risk or confirmed malicious IP addresses sourced from threat intelligence feeds.

## 4. Input Transforms (Normalization Pipeline)
Before evaluating patterns, targets MUST undergo deterministic normalization to defeat obfuscation:
1. `url_decode`: Recursive percent-decoding (up to 3 passes, checking for double-decoding attacks).
2. `html_entity_decode`: Decodes HTML entities (e.g. `&lt;` -> `<`, `&#x3C;` -> `<`).
3. `unicode_normalize`: Standardizes Unicode representations (NFKC normalization).
4. `null_byte_strip`: Replaces null bytes `%00` and `\x00`.
5. `whitespace_compress`: Collapses multiple spaces, tabs, and newlines into single spaces.
6. `lowercase`: Standardizes casing for case-insensitive matching.

## 5. Safety and Performance Constraints
- **ReDoS Prevention**: Regular expressions must be evaluated with strict timeout limits (<= 2ms per regex execution) and avoid catastrophic backtracking (nested quantifiers).
- **Execution Budget**: Total rule evaluation phase for any request must complete within **5 milliseconds** p95.
- **Fail-Open Policy**: In the event of a catastrophic rule parser error or regex timeout, the connector logs a fault event and allows legitimate traffic unless the website policy specifies explicit lockdown.
