"""
SentinelGrid - Enterprise Mobile App & API Protection Test Suite
Verifies Mobile Bot & Hooking Framework Detection, JWT Integrity & Tamper Defense,
GraphQL Security (Depth & Introspection), Attestation Validation, BOLA/IDOR Defense,
and Zero-False-Positive Guarantee for legitimate mobile traffic.
"""

import sys
import json
import base64
import unittest
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, "/run/media/anup/D/sentinelgrid/backend")

from app.security_engine.brain import SecurityBrain


def create_test_jwt(header: dict, payload: dict, signature: str = "sampleSignature123") -> str:
    """Helper to generate base64url encoded JWT tokens for testing."""
    h_bytes = json.dumps(header).encode("utf-8")
    p_bytes = json.dumps(payload).encode("utf-8")
    h_b64 = base64.urlsafe_b64encode(h_bytes).decode("utf-8").rstrip("=")
    p_b64 = base64.urlsafe_b64encode(p_bytes).decode("utf-8").rstrip("=")
    if signature == "":
        return f"{h_b64}.{p_b64}."
    elif signature is None:
        return f"{h_b64}.{p_b64}"
    return f"{h_b64}.{p_b64}.{signature}"


class TestMobileAndAPIProtection(unittest.TestCase):

    # =========================================================================
    # 1. Mobile Bot & Hooking Framework Detection
    # =========================================================================

    def test_mobile_hooking_framework_frida(self):
        """Verifies detection of Frida dynamic instrumentation across headers, query, and body."""
        frida_test_cases = [
            ("Frida Agent Header", "/api/v1/profile", "GET", "", "", {"x-frida-agent": "16.1.4"}),
            ("Frida Server in Header", "/api/v1/auth", "POST", "", "", {"custom-debug": "frida-server active"}),
            ("Frida Gadget in Header", "/api/v1/data", "GET", "", "", {"x-client-hook": "frida-gadget.dylib"}),
            ("libfrida in Query", "/api/v1/modules", "GET", "module=libfrida.so", "", {}),
            ("frida:rpc in Query", "/api/v1/rpc", "GET", "action=frida:rpc", "", {}),
            ("frida-server in Query", "/api/v1/debug", "GET", "service=frida-server", "", {}),
            ("libfrida in JSON Body", "/api/v1/telemetry", "POST", "", json.dumps({"loaded_lib": "libfrida"}), {}),
            ("frida:rpc in JSON Body", "/api/v1/execute", "POST", "", json.dumps({"invoke": "frida:rpc", "method": "bypassPinning"}), {}),
        ]

        for name, path, method, query, body, headers in frida_test_cases:
            if "user-agent" not in headers:
                headers["user-agent"] = "SentinelMobile/1.0"
            res = SecurityBrain.evaluate(
                path=path,
                method=method,
                query=query,
                body=body,
                headers=headers
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Frida sample: {name}")
            self.assertEqual(res["http_status"], 403, f"Expected 403 for: {name}")
            self.assertTrue(res["risk_score"] >= 90.0, f"Expected high risk score for: {name}")
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("MOBILE-HOOKING-FRAMEWORK-FRIDA", rule_ids, f"Rule not found in matches for: {name}")

    def test_mobile_hooking_framework_xposed(self):
        """Verifies detection of Xposed, EdXposed, and CydiaSubstrate artifacts."""
        xposed_test_cases = [
            ("Xposed Module Header", "/api/v1/feed", "GET", "", "", {"X-Xposed-Module": "de.robv.android.xposed.installer"}),
            ("Substrate Header", "/api/v1/auth", "GET", "", "", {"X-Hook-Runtime": "CydiaSubstrate"}),
            ("de.robv.android.xposed in Body", "/api/v1/crash-report", "POST", "", json.dumps({"stacktrace": "at de.robv.android.xposed.XposedBridge.main"}), {}),
            ("edxposed in Query", "/api/v1/status", "GET", "framework=edxposed", "", {}),
            ("xposedbridge in Body", "/api/v1/logs", "POST", "", "found xposedbridge hook in zygote", {}),
        ]

        for name, path, method, query, body, headers in xposed_test_cases:
            if "user-agent" not in headers:
                headers["user-agent"] = "SentinelMobile/1.0"
            res = SecurityBrain.evaluate(
                path=path,
                method=method,
                query=query,
                body=body,
                headers=headers
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Xposed sample: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("MOBILE-HOOKING-FRAMEWORK-XPOSED", rule_ids, f"Rule not found in matches for: {name}")

    def test_mobile_emulator_fingerprint(self):
        """Verifies detection of Android and iOS emulator signatures."""
        emulator_test_cases = [
            ("Google Android SDK Phone (sdk_gphone)", "Mozilla/5.0 (Linux; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.010)"),
            ("VirtualBox x86 (vbox86p)", "Mozilla/5.0 (Linux; Android 10; vbox86p Build/QQ3A.200805.001)"),
            ("Genymotion Emulator", "Mozilla/5.0 (Linux; Android 11; Genymotion Google Pixel 4 Build/RQ3A.210905.001)"),
            ("NoxPlayer Emulator", "Mozilla/5.0 (Linux; Android 9; nox Build/PI; wv) NoxPlayer/7.0.1"),
            ("Nox Standalone", "Mozilla/5.0 (Linux; Android 9; NOX) AppleWebKit/537.36"),
            ("BlueStacks Emulator", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BlueStacks/5.11.40"),
            ("QEMU Goldfish Kernel", "Mozilla/5.0 (Linux; Android 8.0; goldfish Build/OSR1.180412.003)"),
            ("QEMU Ranchu Kernel", "Mozilla/5.0 (Linux; Android 12; ranchu Build/SP1A.210812.016)"),
        ]

        for name, ua in emulator_test_cases:
            res = SecurityBrain.evaluate(
                path="/api/v1/device-check",
                method="POST",
                query="",
                body=json.dumps({"app_version": "2.4.0"}),
                headers={"user-agent": ua}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block Emulator: {name}")
            self.assertEqual(res["http_status"], 403)
            self.assertTrue(res["risk_score"] >= 80.0)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("MOBILE-EMULATOR-FINGERPRINT", rule_ids, f"Rule not found for: {name}")

        # Also test device headers containing emulator signatures
        res_device_header = SecurityBrain.evaluate(
            path="/api/v1/auth/login",
            method="POST",
            query="",
            body=json.dumps({"username": "mobile_user"}),
            headers={
                "user-agent": "MobileApp/1.0",
                "x-device-model": "Genymotion Virtual Device",
                "x-device-fingerprint": "vbox86p"
            }
        )
        self.assertEqual(res_device_header["action"], "BLOCK")
        self.assertIn("MOBILE-EMULATOR-FINGERPRINT", [m["rule_id"] for m in res_device_header["all_matches"]])

    # =========================================================================
    # 2. Mobile JWT Integrity & Tamper Protection
    # =========================================================================

    def test_jwt_alg_none_bypass(self):
        """Verifies detection of 'alg': 'none' / 'None' or missing signature bypasses."""
        alg_none_token = create_test_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin", "role": "superadmin"}, signature="")
        alg_none_cap_token = create_test_jwt({"alg": "None", "typ": "JWT"}, {"sub": "root"}, signature="")
        missing_sig_token_dot = create_test_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user_bypass"}, signature="")
        missing_sig_token_nodot = create_test_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "user_bypass2"}, signature=None)

        jwt_none_cases = [
            ("Bearer Token with alg:none", {"authorization": f"Bearer {alg_none_token}"}, "", ""),
            ("Bearer Token with alg:None", {"authorization": f"Bearer {alg_none_cap_token}"}, "", ""),
            ("Missing Signature Segment with Dot", {"authorization": f"Bearer {missing_sig_token_dot}"}, "", ""),
            ("Missing Signature Segment without Dot", {"authorization": f"Bearer {missing_sig_token_nodot}"}, "", ""),
            ("Cookie with alg:none", {"cookie": f"session=123; auth_token={alg_none_token}; theme=light"}, "", ""),
            ("Cookie with Missing Signature", {"cookie": f"token={missing_sig_token_dot}"}, "", ""),
            ("Query Param Token with alg:none", {}, f"token={alg_none_token}", ""),
            ("Direct JSON Payload with alg:none", {}, "", json.dumps({"alg": "none", "token": "xyz"})),
        ]

        for name, headers, query, body in jwt_none_cases:
            if "user-agent" not in headers:
                headers["user-agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"
            res = SecurityBrain.evaluate(
                path="/api/v1/protected",
                method="POST" if body else "GET",
                query=query,
                body=body,
                headers=headers
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block JWT alg none case: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("JWT-ALG-NONE-BYPASS", rule_ids, f"JWT-ALG-NONE-BYPASS not in matches for: {name}")

    def test_jwt_malformed_or_injection(self):
        """Verifies detection of SQLi, command injection, and null bytes inside decoded JWT payloads."""
        sqli_jwt = create_test_jwt({"alg": "HS256"}, {"sub": "admin' OR '1'='1--", "role": "admin"})
        union_jwt = create_test_jwt({"alg": "HS256"}, {"user": "alice", "org": "corp' UNION SELECT null, username, password FROM users--"})
        rce_cat_jwt = create_test_jwt({"alg": "HS256"}, {"user": "guest; cat /etc/passwd", "tenant": "t1"})
        rce_subshell_jwt = create_test_jwt({"alg": "HS256"}, {"cmd": "$(whoami)", "action": "eval"})
        rce_pipe_jwt = create_test_jwt({"alg": "HS256"}, {"filter": "test | whoami"})

        # Null byte payload inside JWT
        null_payload_dict = {"sub": "admin\x00guest", "role": "user"}
        null_jwt = create_test_jwt({"alg": "HS256"}, null_payload_dict)

        # Null byte in raw token
        raw_null_token = f"eyJhbGciOiJIUzI1NiJ9\x00.eyJzdWIiOiIxIn0.sig"

        jwt_injection_cases = [
            ("SQLi Tautology in Payload", {"authorization": f"Bearer {sqli_jwt}"}),
            ("UNION SELECT in Payload", {"authorization": f"Bearer {union_jwt}"}),
            ("RCE Cat in Payload", {"authorization": f"Bearer {rce_cat_jwt}"}),
            ("RCE Subshell in Payload", {"authorization": f"Bearer {rce_subshell_jwt}"}),
            ("RCE Pipe in Payload", {"authorization": f"Bearer {rce_pipe_jwt}"}),
            ("Null Byte in Payload", {"authorization": f"Bearer {null_jwt}"}),
            ("Null Byte in Raw Token", {"authorization": f"Bearer {raw_null_token}"}),
            ("SQLi JWT in Cookie", {"cookie": f"auth_token={sqli_jwt}; visitor=abc"}),
        ]

        for name, headers in jwt_injection_cases:
            headers["user-agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"
            res = SecurityBrain.evaluate(
                path="/api/v1/secure-data",
                method="GET",
                query="",
                body="",
                headers=headers
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block JWT injection: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("JWT-MALFORMED-OR-INJECTION", rule_ids, f"JWT-MALFORMED-OR-INJECTION not found in matches for: {name}")

    # =========================================================================
    # 3. GraphQL Security for Mobile APIs
    # =========================================================================

    def test_graphql_depth_exhaustion(self):
        """Verifies detection of recursive query depth exceeding 6 levels."""
        # 7 levels deep query: user(1) -> friends(2) -> friends(3) -> friends(4) -> friends(5) -> friends(6) -> friends(7)
        depth_7_query = """
        query DeepQuery {
            user(id: "101") {
                friends {
                    friends {
                        friends {
                            friends {
                                friends {
                                    friends {
                                        id
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        # 10 levels deep recursive query
        depth_10_query = "query { a { b { c { d { e { f { g { h { i { j { id } } } } } } } } } } }"

        depth_cases = [
            ("Depth 7 in JSON Body", "/graphql", "POST", "", json.dumps({"query": depth_7_query})),
            ("Depth 10 in JSON Body", "/api/v1/graphql", "POST", "", json.dumps({"query": depth_10_query})),
            ("Depth 7 in Raw Body", "/graphql", "POST", "", depth_7_query),
            ("Depth 7 in GET Query Parameter", "/graphql", "GET", f"query={depth_7_query}", ""),
        ]

        for name, path, method, query, body in depth_cases:
            res = SecurityBrain.evaluate(
                path=path,
                method=method,
                query=query,
                body=body,
                headers={"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block excessive GraphQL depth: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("GRAPHQL-DEPTH-EXHAUSTION", rule_ids, f"Rule not in matches for: {name}")

        # Legitimate GraphQL queries (depth <= 6) MUST pass with ALLOW
        legitimate_depth_queries = [
            # Depth 2
            "query { user { id name } }",
            # Depth 3
            "query { user { profile { avatar email } } }",
            # Depth 5
            "query { company { departments { teams { lead { name } } } } }",
            # Depth 6 (at the limit of allowed depth)
            "query { l1 { l2 { l3 { l4 { l5 { id } } } } } }",
        ]

        for idx, query_str in enumerate(legitimate_depth_queries):
            res = SecurityBrain.evaluate(
                path="/graphql",
                method="POST",
                query="",
                body=json.dumps({"query": query_str}),
                headers={"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"}
            )
            self.assertEqual(res["action"], "ALLOW", f"Legitimate GraphQL query at depth {idx + 2} was blocked")
            self.assertEqual(res["risk_score"], 0.0)
            self.assertTrue(res["is_clean"])

    def test_graphql_introspection_abuse(self):
        """Verifies blocking of __schema and __type introspection probing."""
        introspection_cases = [
            ("Introspection __schema in JSON Body", "/graphql", "POST", "", json.dumps({"query": "{ __schema { types { name } } }"})),
            ("Introspection __type in JSON Body", "/api/v1/graphql", "POST", "", json.dumps({"query": "query { __type(name: \"User\") { name fields { name } } }"})),
            ("Introspection __schema in GET query", "/graphql", "GET", "query={__schema{queryType{name}}}", ""),
            ("Introspection Full Probe", "/api/graphql", "POST", "", json.dumps({
                "operationName": "IntrospectionQuery",
                "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }"
            })),
        ]

        for name, path, method, query, body in introspection_cases:
            res = SecurityBrain.evaluate(
                path=path,
                method=method,
                query=query,
                body=body,
                headers={"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block GraphQL introspection: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("GRAPHQL-INTROSPECTION-ABUSE", rule_ids, f"Rule not in matches for: {name}")

    # =========================================================================
    # 4. Mobile Attestation & BOLA / IDOR Defense
    # =========================================================================

    def test_mobile_attestation_bypass(self):
        """Verifies detection of invalid, null, or spoofed mobile attestation headers."""
        attestation_bypass_cases = [
            ("X-App-Check null", {"X-App-Check": "null"}),
            ("X-Attestation-Token None", {"X-Attestation-Token": "None"}),
            ("X-Device-Token mock", {"X-Device-Token": "mock"}),
            ("X-Device-Token mock-hardware-id", {"X-Device-Token": "mock-hardware-id"}),
            ("X-App-Check undefined", {"X-App-Check": "undefined"}),
            ("X-Play-Integrity fake", {"X-Play-Integrity": "fake"}),
            ("X-Safety-Net test", {"X-Safety-Net": "test"}),
            ("X-Attestation-Token bypass", {"X-Attestation-Token": "bypass"}),
            ("X-App-Check 0", {"X-App-Check": "0"}),
            ("X-Device-Token false", {"X-Device-Token": "false"}),
        ]

        for name, headers in attestation_bypass_cases:
            headers["user-agent"] = "SentinelMobileApp/3.0.0 (Android 14; Pixel 8 Pro)"
            res = SecurityBrain.evaluate(
                path="/api/v1/auth/exchange",
                method="POST",
                query="",
                body=json.dumps({"client_nonce": "9934812"}),
                headers=headers
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block attestation bypass: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("MOBILE-ATTESTATION-BYPASS", rule_ids, f"Rule not found in matches for: {name}")

        # Legitimate attestation tokens MUST NOT be blocked
        valid_attestation_headers = {
            "user-agent": "SentinelMobileApp/3.0.0 (Android 14; Pixel 8 Pro)",
            "X-App-Check": "eyJsYS1mYXN0IjoidHJ1ZSIsImFsZyI6IlJTMjU2In0.validPayload.sig",
            "X-Device-Token": "4fa89b21-8893-41a9-9182-38d92a019482",
            "X-Attestation-Token": "d41d8cd98f00b204e9800998ecf8427e"
        }
        res_valid = SecurityBrain.evaluate(
            path="/api/v1/auth/exchange",
            method="POST",
            query="",
            body=json.dumps({"client_nonce": "9934812"}),
            headers=valid_attestation_headers
        )
        self.assertEqual(res_valid["action"], "ALLOW")
        self.assertEqual(res_valid["risk_score"], 0.0)
        self.assertTrue(res_valid["is_clean"])

    def test_mobile_bola_idor_traversal(self):
        """Verifies detection of entity traversals (../admin, null, nil UUID) attempting root tenant access."""
        bola_test_cases = [
            ("Path Traversal to admin entity", "/api/v1/users/../admin", "GET", "", ""),
            ("Path Traversal with nil UUID", "/api/v1/tenants/00000000-0000-0000-0000-000000000000", "GET", "", ""),
            ("Path Traversal with null", "/api/v1/tenants/null", "GET", "", ""),
            ("Path Traversal with None", "/api/v1/organizations/none", "GET", "", ""),
            ("Query param tenant_id=../admin", "/api/v1/dashboard", "GET", "tenant_id=../admin", ""),
            ("Query param tenant_id=00000000-0000-0000-0000-000000000000", "/api/v1/tenants", "GET", "tenant_id=00000000-0000-0000-0000-000000000000", ""),
            ("Query param tenant_id=null", "/api/v1/tenants", "GET", "tenant_id=null", ""),
            ("Query param user_id=null", "/api/v1/accounts", "GET", "user_id=null", ""),
            ("Query param account_id=../root", "/api/v1/accounts", "GET", "account_id=../root", ""),
            ("JSON body tenant_id nil UUID", "/api/v1/tenant/switch", "POST", "", json.dumps({"tenant_id": "00000000-0000-0000-0000-000000000000"})),
            ("JSON body tenant_id null", "/api/v1/tenant/switch", "POST", "", json.dumps({"tenant_id": None})),
            ("JSON body tenant_id ../admin", "/api/v1/tenant/switch", "POST", "", json.dumps({"tenant_id": "../admin"})),
            ("JSON body org_id null string", "/api/v1/org/switch", "POST", "", json.dumps({"org_id": "null"})),
        ]

        for name, path, method, query, body in bola_test_cases:
            res = SecurityBrain.evaluate(
                path=path,
                method=method,
                query=query,
                body=body,
                headers={"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"}
            )
            self.assertEqual(res["action"], "BLOCK", f"Failed to block BOLA/IDOR attempt: {name}")
            self.assertEqual(res["http_status"], 403)
            rule_ids = [m["rule_id"] for m in res["all_matches"]]
            self.assertIn("MOBILE-BOLA-IDOR-TRAVERSAL", rule_ids, f"Rule not found in matches for: {name}")

    # =========================================================================
    # 5. Zero-False-Positive Guarantee
    # =========================================================================

    def test_zero_false_positive_guarantee(self):
        """
        Zero-False-Positive Guarantee:
        Legitimate mobile traffic (real iOS/Android User-Agents, standard JWT tokens with
        HS256/RS256, standard GraphQL queries without excessive depth, valid student logins)
        MUST be classified as ALLOW with risk_score = 0.0.
        """
        valid_hs256_jwt = create_test_jwt(
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "student_9812", "email": "student@university.edu", "role": "student"},
            signature="e2k3j9v4m1p5q8r0s2t4u6v8w0x2y4z6"
        )

        valid_rs256_jwt = create_test_jwt(
            header={"alg": "RS256", "typ": "JWT"},
            payload={"sub": "faculty_441", "dept": "Cybersecurity", "role": "instructor"},
            signature="a8c4f0b2d6e8a0c2e4f6a8b0c2d4e6f8"
        )

        legitimate_requests = [
            # 1. Real iOS User-Agents
            {
                "name": "iOS iPhone 15 Pro Native Request",
                "path": "/api/v1/courses",
                "method": "GET",
                "query": "category=security&level=intro",
                "body": "",
                "headers": {
                    "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                    "authorization": f"Bearer {valid_hs256_jwt}",
                    "accept": "application/json"
                }
            },
            {
                "name": "iOS iPad Pro Native Request",
                "path": "/api/v1/library/catalog",
                "method": "GET",
                "query": "sort=published_desc&limit=20",
                "body": "",
                "headers": {
                    "user-agent": "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
                    "cookie": f"session_id=s_9921; auth_token={valid_rs256_jwt}"
                }
            },
            # 2. Real Android User-Agents
            {
                "name": "Google Pixel 8 Pro Native Request",
                "path": "/api/v1/student/progress",
                "method": "GET",
                "query": "course_id=cs-401&semester=fall2024",
                "body": "",
                "headers": {
                    "user-agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/UD1A.230803.041; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.144 Mobile Safari/537.36",
                    "authorization": f"Bearer {valid_rs256_jwt}",
                    "x-app-check": "valid-app-check-token-pixel8-99201"
                }
            },
            {
                "name": "Samsung Galaxy S23 Ultra Native Request",
                "path": "/api/v1/announcements",
                "method": "GET",
                "query": "unread=true",
                "body": "",
                "headers": {
                    "user-agent": "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
                    "authorization": f"Bearer {valid_hs256_jwt}"
                }
            },
            # 3. Valid Student Login Payloads
            {
                "name": "Valid Student Mobile Login",
                "path": "/api/v1/auth/login",
                "method": "POST",
                "query": "",
                "body": json.dumps({
                    "email": "student@university.edu",
                    "password": "CorrectHorseBatteryStaple2024!",
                    "device_info": {"platform": "android", "app_build": 104}
                }),
                "headers": {
                    "user-agent": "SentinelMobileApp/2.5.0 (Android 14; Pixel 8 Pro)",
                    "x-app-check": "eyJhbGciOiJSUzI1NiJ9.appCheckClaims.sig",
                    "x-device-token": "hardware-token-f9a8b2c1"
                }
            },
            {
                "name": "Valid Student Profile Update",
                "path": "/api/v1/users/profile",
                "method": "PUT",
                "query": "",
                "body": json.dumps({
                    "display_name": "Alex Student",
                    "bio": None,  # Non-entity null field MUST be allowed
                    "preferences": {"email_notifications": True, "dark_mode": True}
                }),
                "headers": {
                    "user-agent": "SentinelMobileApp/2.5.0 (iOS 17.4; iPhone15,2)",
                    "authorization": f"Bearer {valid_hs256_jwt}"
                }
            },
            # 4. Standard GraphQL Mobile Queries (Depth <= 6)
            {
                "name": "Standard GraphQL Student Courses Query",
                "path": "/graphql",
                "method": "POST",
                "query": "",
                "body": json.dumps({
                    "operationName": "GetMyCourses",
                    "query": "query GetMyCourses { me { id name enrolledCourses { id code title credits instructor { name } } } }"
                }),
                "headers": {
                    "user-agent": "SentinelMobileApp/2.5.0 (Android 14; Pixel 8 Pro)",
                    "authorization": f"Bearer {valid_hs256_jwt}"
                }
            },
            {
                "name": "Standard GraphQL Assignments Query",
                "path": "/graphql",
                "method": "POST",
                "query": "",
                "body": json.dumps({
                    "query": "query { course(id: \"cs101\") { syllabus assignments { title dueDate score { points total } } } }"
                }),
                "headers": {
                    "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
                    "authorization": f"Bearer {valid_rs256_jwt}"
                }
            },
            # 5. Legitimate Entity Access with Standard IDs
            {
                "name": "Legitimate Entity ID Access",
                "path": "/api/v1/tenants/tenant_alpha_491/dashboard",
                "method": "GET",
                "query": "user_id=usr_5819&account_id=acc_9921",
                "body": "",
                "headers": {
                    "user-agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/UD1A.230803.041; wv)",
                    "authorization": f"Bearer {valid_hs256_jwt}"
                }
            }
        ]

        for req in legitimate_requests:
            res = SecurityBrain.evaluate(
                path=req["path"],
                method=req["method"],
                query=req["query"],
                body=req["body"],
                headers=req["headers"]
            )
            self.assertEqual(res["action"], "ALLOW", f"Legitimate mobile request falsely blocked: {req['name']}")
            self.assertEqual(res["risk_score"], 0.0, f"Expected 0.0 risk score for: {req['name']}, got {res['risk_score']} with matches {res['all_matches']}")
            self.assertTrue(res["is_clean"], f"Expected is_clean=True for: {req['name']}")


if __name__ == "__main__":
    unittest.main()
