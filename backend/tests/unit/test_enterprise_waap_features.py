"""
SentinelGrid - Verification Suite for Enterprise WAAP Features
Tests Domain Inventory, Dynamic IP ACLs (CIDR), OpenAPI Ingestion & Shadow API Discovery,
SIEM Event Filtering/Export (CSV/JSON), and Connector Heartbeat Monitoring.
"""

import sys
import os
import unittest
import json

# Add backend directory to sys.path
sys.path.insert(0, "/run/media/anup/D/sentinelgrid/backend")

from fastapi.testclient import TestClient
from app.main import app


class TestEnterpriseWAAPFeatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_domain_lifecycle(self):
        """Tests domain creation, listing, updating, status toggling, and cascading deletion."""
        # 1. Create domain
        res = self.client.post("/v1/websites", json={
            "domain": "security-test.acme.com",
            "name": "ACME Payment Gateway"
        })
        self.assertEqual(res.status_code, 200)
        site_id = res.json()["website"]["id"]

        # 2. List domains
        res = self.client.get("/v1/websites")
        self.assertEqual(res.status_code, 200)
        domains = [w["domain"] for w in res.json()]
        self.assertIn("security-test.acme.com", domains)

        # 3. Update domain name
        res = self.client.put(f"/v1/websites/{site_id}", json={
            "name": "ACME Payment Core v2"
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["name"], "ACME Payment Core v2")

        # 4. Toggle domain status
        res = self.client.patch(f"/v1/websites/{site_id}/toggle")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["new_state"], "disabled")

        res = self.client.patch(f"/v1/websites/{site_id}/toggle")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["new_state"], "active")

        # 5. Cleanup
        del_res = self.client.delete(f"/v1/websites/{site_id}")
        self.assertEqual(del_res.status_code, 200)

    def test_02_ip_access_control_lists_and_cidr(self):
        """Tests IP Allowlist/Blocklist, CIDR notation validation, and in-line blocking."""
        # Setup test site
        site_res = self.client.post("/v1/websites", json={
            "domain": "waf-ip-test.corp",
            "name": "WAF IP Test Site"
        })
        site_id = site_res.json()["website"]["id"]

        # Invalid IP should fail with 400
        bad_res = self.client.post("/v1/ip-rules", json={
            "website_id": site_id,
            "ip_or_cidr": "invalid-ip-999.999",
            "action": "BLOCK"
        })
        self.assertEqual(bad_res.status_code, 400)

        # Add single IP block
        rule1 = self.client.post("/v1/ip-rules", json={
            "website_id": site_id,
            "ip_or_cidr": "203.0.113.55",
            "action": "BLOCK",
            "description": "Known Malicious Bot"
        }).json()
        rule1_id = rule1["rule"]["id"]

        # Add CIDR subnet block
        rule2 = self.client.post("/v1/ip-rules", json={
            "website_id": site_id,
            "ip_or_cidr": "198.51.100.0/24",
            "action": "BLOCK",
            "description": "Suspicious VPN Subnet"
        }).json()
        rule2_id = rule2["rule"]["id"]

        # Add Allowlist rule for trusted admin IP
        rule3 = self.client.post("/v1/ip-rules", json={
            "website_id": site_id,
            "ip_or_cidr": "10.0.0.1",
            "action": "ALLOW",
            "description": "Trusted Internal Admin"
        }).json()
        rule3_id = rule3["rule"]["id"]

        # In-line test: Client IP matching blocked single IP
        inspect_res = self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "GET",
            "path": "/api/v1/users",
            "client_ip": "203.0.113.55"
        })
        self.assertEqual(inspect_res.status_code, 200)
        self.assertEqual(inspect_res.json()["action"], "BLOCK")
        self.assertEqual(inspect_res.json()["rule_triggered"], "IP-BLOCK-LIST")

        # In-line test: Client IP inside blocked CIDR subnet (198.51.100.89)
        inspect_cidr = self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "POST",
            "path": "/login",
            "client_ip": "198.51.100.89"
        })
        self.assertEqual(inspect_cidr.status_code, 200)
        self.assertEqual(inspect_cidr.json()["action"], "BLOCK")
        self.assertEqual(inspect_cidr.json()["rule_triggered"], "IP-BLOCK-LIST")

        # In-line test: Client IP matching Allowlist
        inspect_allow = self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "GET",
            "path": "/api/v1/system",
            "client_ip": "10.0.0.1"
        })
        self.assertEqual(inspect_allow.status_code, 200)
        self.assertEqual(inspect_allow.json()["action"], "ALLOW")
        self.assertEqual(inspect_allow.json()["rule_triggered"], "IP-ALLOW-LIST")

        # Delete rules
        self.assertEqual(self.client.delete(f"/v1/ip-rules/{rule1_id}").status_code, 200)
        self.assertEqual(self.client.delete(f"/v1/ip-rules/{rule2_id}").status_code, 200)
        self.assertEqual(self.client.delete(f"/v1/ip-rules/{rule3_id}").status_code, 200)
        self.client.delete(f"/v1/websites/{site_id}")

    def test_03_openapi_ingestion_and_shadow_api_discovery(self):
        """Tests OpenAPI 3.0 spec contract ingestion, zombie route flagging, and shadow API auto-discovery."""
        # Create website
        site_res = self.client.post("/v1/websites", json={
            "domain": "api.cloud-services.io",
            "name": "Cloud Services API"
        })
        site_id = site_res.json()["website"]["id"]

        # OpenAPI 3.0 spec JSON with documented and deprecated (zombie) routes
        openapi_spec = {
            "openapi": "3.0.1",
            "info": {
                "title": "Cloud Services Microservice",
                "version": "2.4.0"
            },
            "paths": {
                "/api/v1/auth/token": {
                    "post": {
                        "summary": "Obtain JWT authentication token",
                        "deprecated": False
                    }
                },
                "/api/v1/legacy/xml-auth": {
                    "post": {
                        "summary": "Deprecated XML auth route",
                        "deprecated": True
                    }
                }
            }
        }

        # 1. Ingest OpenAPI spec
        import_res = self.client.post("/v1/api-specs/import", json={
            "website_id": site_id,
            "spec_content": json.dumps(openapi_spec)
        })
        self.assertEqual(import_res.status_code, 200)
        self.assertEqual(import_res.json()["imported_endpoints_count"], 2)
        self.assertEqual(import_res.json()["documented_count"], 1)
        self.assertEqual(import_res.json()["zombie_count"], 1)

        # 2. Inspect documented route -> clean allow
        clean_res = self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "POST",
            "path": "/api/v1/auth/token",
            "client_ip": "192.168.1.100"
        })
        self.assertEqual(clean_res.status_code, 200)
        self.assertEqual(clean_res.json()["action"], "ALLOW")

        # 3. Inspect undocumented route -> must auto-catalog as SHADOW API
        shadow_path = "/api/internal/secret-debug-tools"
        shadow_res = self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "GET",
            "path": shadow_path,
            "client_ip": "192.168.1.200"
        })
        self.assertEqual(shadow_res.status_code, 200)

        # 4. Check inventory catalog for the new Shadow API
        endpoints_res = self.client.get(f"/v1/endpoints?website_id={site_id}")
        self.assertEqual(endpoints_res.status_code, 200)
        endpoints = endpoints_res.json()

        shadow_ep = next((e for e in endpoints if e["path"] == shadow_path), None)
        self.assertIsNotNone(shadow_ep)
        self.assertEqual(shadow_ep["status"], "shadow")

        zombie_ep = next((e for e in endpoints if e["path"] == "/api/v1/legacy/xml-auth"), None)
        self.assertIsNotNone(zombie_ep)
        self.assertEqual(zombie_ep["status"], "zombie")

        # Cleanup
        self.client.delete(f"/v1/websites/{site_id}")

    def test_04_realtime_events_filtering_and_export(self):
        """Tests live security event filtering and CSV/JSON export."""
        site_res = self.client.post("/v1/websites", json={
            "domain": "export-test.internal",
            "name": "Export Test Site"
        })
        site_id = site_res.json()["website"]["id"]

        # Generate a blocked event (SQL Injection)
        self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "GET",
            "path": "/products",
            "query_params": "id=1' UNION SELECT * FROM users--",
            "client_ip": "172.16.0.42"
        })

        # Generate an allowed event
        self.client.post("/v1/inspect", json={
            "website_id": site_id,
            "method": "GET",
            "path": "/about-us",
            "client_ip": "172.16.0.42"
        })

        # Filter by action='BLOCK'
        events_res = self.client.get(f"/v1/events?website_id={site_id}&action=BLOCK")
        self.assertEqual(events_res.status_code, 200)
        data = events_res.json()
        self.assertTrue(data["total"] >= 1)
        for ev in data["events"]:
            self.assertEqual(ev["action"], "BLOCK")

        # Export as CSV
        csv_res = self.client.get(f"/v1/events/export?website_id={site_id}&format=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertEqual(csv_res.headers["content-type"], "text/csv; charset=utf-8")
        self.assertIn("rule_triggered", csv_res.text)
        self.assertIn("172.16.0.42", csv_res.text)

        # Export as JSON
        json_res = self.client.get(f"/v1/events/export?website_id={site_id}&format=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertEqual(json_res.headers["content-type"], "application/json")
        parsed = json_res.json()
        self.assertTrue(isinstance(parsed, list))
        self.assertTrue(len(parsed) >= 2)

        # Cleanup
        self.client.delete(f"/v1/websites/{site_id}")

    def test_05_connector_heartbeat_and_health(self):
        """Tests external connector heartbeat registration and health state reporting."""
        site_res = self.client.post("/v1/websites", json={
            "domain": "connector-test.org",
            "name": "Connector Test Org"
        })
        site_id = site_res.json()["website"]["id"]

        # Register heartbeat
        hb_res = self.client.post("/v1/connectors/heartbeat", json={
            "website_id": site_id,
            "connector_name": "nginx-ingress-prod-01",
            "connector_type": "nginx",
            "latency_ms": 0.45
        })
        self.assertEqual(hb_res.status_code, 200)
        self.assertEqual(hb_res.json()["status"], "acknowledged")

        # List connectors
        conn_res = self.client.get(f"/v1/connectors?website_id={site_id}")
        self.assertEqual(conn_res.status_code, 200)
        connectors = conn_res.json()
        self.assertEqual(len(connectors), 1)
        self.assertEqual(connectors[0]["name"], "nginx-ingress-prod-01")
        self.assertEqual(connectors[0]["status"], "online")
        self.assertEqual(connectors[0]["latency_ms"], 0.45)

        # Cleanup
        self.client.delete(f"/v1/websites/{site_id}")


if __name__ == "__main__":
    unittest.main()
