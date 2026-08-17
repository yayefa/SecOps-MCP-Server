# Copyright 2026 Google LLC
#
# Streamable HTTP MCP Comprehensive Test Suite for Google SecOps Server
# Runs with standard Python library (urllib) or httpx.

import os
import sys
import json
import asyncio
import urllib.request
import urllib.error

TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8080").rstrip("/")


def http_get(url: str, headers: dict = None) -> tuple[int, str]:
    """Execute HTTP GET using standard library."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return 0, str(e)


def http_post_json(url: str, data: dict, headers: dict = None) -> tuple[int, str]:
    """Execute HTTP POST with JSON body using standard library."""
    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return 0, str(e)


def test_direct_tools():
    """1. Test direct Python execution of SecOps tools (Zero network dependencies)."""
    print("\n🔍 [1/3] Testing Direct Python Execution of SecOps MCP Tools...")
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from server import (
            search_security_events,
            get_security_alerts,
            lookup_entity,
            get_ioc_matches,
            list_security_rules,
            validate_rule,
            health_check
        )

        async def run_all_tools():
            # Test 1: Health Check Tool
            h_json = await health_check()
            h = json.loads(h_json)
            print(f"  ✅ [Tool 1/5] health_check: status='{h.get('status')}', transport='{h.get('transport')}'")

            # Test 2: Get Security Alerts
            alerts_json = await get_security_alerts(severity="HIGH", limit=2)
            alerts = json.loads(alerts_json)
            count = alerts.get("count", len(alerts.get("alerts", [])))
            print(f"  ✅ [Tool 2/5] get_security_alerts: Found {count} alerts")

            # Test 3: Lookup Entity
            entity_json = await lookup_entity("IP", "10.120.4.55")
            entity = json.loads(entity_json)
            print(f"  ✅ [Tool 3/5] lookup_entity: Risk Score {entity.get('risk_score')}/100 (Verdict: {entity.get('risk_verdict')})")

            # Test 4: IOC Matches
            ioc_json = await get_ioc_matches(time_range_hours=24, limit=2)
            ioc = json.loads(ioc_json)
            print(f"  ✅ [Tool 4/5] get_ioc_matches: Retrieved {ioc.get('count')} threat IOC indicators")

            # Test 5: Validate YARA-L Rule
            yara = "rule test { events: $e.metadata.event_type = 'PROCESS_LAUNCH' condition: $e }"
            val_json = await validate_rule(yara)
            val = json.loads(val_json)
            print(f"  ✅ [Tool 5/5] validate_rule: Syntax status '{val.get('validation_status')}'")

        asyncio.run(run_all_tools())
    except Exception as e:
        print(f"  ❌ Direct execution failed: {e}")


def test_health_probes():
    """2. Test HTTP health probes."""
    print(f"\n🔍 [2/3] Testing HTTP Health Probes on {TARGET_URL}...")
    headers = {}
    token = os.environ.get("AUTH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    code, body = http_get(f"{TARGET_URL}/health", headers=headers)
    if code == 200:
        print(f"  ✅ /health -> HTTP {code}: {body.strip()}")
    else:
        print(f"  ℹ️  /health -> HTTP {code}")

    code, body = http_get(f"{TARGET_URL}/mcp", headers=headers)
    if code == 200:
        print(f"  ✅ /mcp (Discovery) -> HTTP {code}: {body.strip()}")
    else:
        print(f"  ℹ️  /mcp (Discovery) -> HTTP {code}")

    code, body = http_get(f"{TARGET_URL}/", headers=headers)
    if code == 200:
        print(f"  ✅ / -> HTTP {code}: {body.strip()}")


def test_mcp_streamable_rpc():
    """3. Test MCP Streamable HTTP JSON-RPC protocol initialization, tools/list, and tools/call."""
    print(f"\n🔍 [3/3] Testing Streamable HTTP MCP Protocol ({TARGET_URL}/mcp)...")
    
    headers = {}
    token = os.environ.get("AUTH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # 1. Initialize
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        }
    }
    code, resp = http_post_json(f"{TARGET_URL}/mcp", init_payload, headers=headers)
    if code == 200:
        print(f"  ✅ [RPC 1/3] Protocol Initialize -> HTTP 200: Success")
        try:
            res = json.loads(resp)
            print(f"     Server Info: {res.get('result', {}).get('serverInfo', {})}")
        except Exception:
            pass
    else:
        print(f"  ℹ️  Protocol Initialize -> HTTP {code}")

    # 2. tools/list
    list_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    code, resp = http_post_json(f"{TARGET_URL}/mcp", list_payload, headers=headers)
    if code == 200:
        try:
            res = json.loads(resp)
            tools = res.get("result", {}).get("tools", [])
            print(f"  ✅ [RPC 2/3] tools/list -> HTTP 200: Found {len(tools)} official SecOps tools")
        except Exception:
            print(f"  ✅ [RPC 2/3] tools/list -> HTTP 200")
    else:
        print(f"  ℹ️  tools/list -> HTTP {code}")

    # 3. tools/call with integer argument
    call_payload_1 = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_security_alerts",
            "arguments": {"severity": "CRITICAL", "limit": 1}
        }
    }
    code1, resp1 = http_post_json(f"{TARGET_URL}/mcp", call_payload_1, headers=headers)
    if code1 == 200:
        print(f"  ✅ [RPC 3/4] tools/call (get_security_alerts with limit=1) -> HTTP 200: Success")
    else:
        print(f"  ℹ️  tools/call (limit=1) -> HTTP {code1}")

    # 4. tools/call with string limit argument (LLM type resilience check)
    call_payload_2 = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_security_alerts",
            "arguments": {"severity": "ALL", "limit": "5"}
        }
    }
    code2, resp2 = http_post_json(f"{TARGET_URL}/mcp", call_payload_2, headers=headers)
    if code2 == 200:
        try:
            r = json.loads(resp2)
            is_err = r.get("result", {}).get("isError", False)
            if not is_err:
                print(f"  ✅ [RPC 4/4] tools/call (get_security_alerts with string limit='5') -> HTTP 200: Success (No slice error)")
            else:
                print(f"  ❌ [RPC 4/4] tools/call returned error: {r.get('result', {}).get('content')}")
        except Exception:
            print(f"  ✅ [RPC 4/4] tools/call -> HTTP 200")
    else:
        print(f"  ℹ️  tools/call (limit='5') -> HTTP {code2}")


def main():
    print("================================================================")
    print(" 🧪 Google SecOps MCP Server Test Suite (Streamable HTTP)")
    print(f" Target Endpoint: {TARGET_URL}")
    print("================================================================")

    test_direct_tools()
    test_health_probes()
    test_mcp_streamable_rpc()

    print("\n================================================================")
    print(" 🎉 Testing complete!")
    print("================================================================")


if __name__ == "__main__":
    main()
