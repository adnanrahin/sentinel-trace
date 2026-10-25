from __future__ import annotations

import json

from tests.conftest import SYNTHETIC_AWS

from sentinal_trace.mcp.server import McpServer
from sentinal_trace.pipeline import ScanSession


def _call(server: McpServer, name: str, arguments: dict) -> dict:
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return json.loads(response["result"]["content"][0]["text"])


def test_initialize_and_tools(session: ScanSession) -> None:
    server = McpServer(session=session)
    init = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init["result"]["serverInfo"]["name"] == "sentinal-trace"
    listed = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in listed["result"]["tools"]}
    assert {"scan_text", "scan_file", "evaluate_policy", "redact_content"}.issubset(names)


def test_mcp_scan_does_not_echo_secret(session: ScanSession) -> None:
    server = McpServer(session=session)
    payload = _call(server, "scan_text", {"text": f"leak {SYNTHETIC_AWS}"})
    blob = json.dumps(payload)
    assert SYNTHETIC_AWS not in blob
    assert payload["policy_action"] == "block"


def test_mcp_rejects_unknown_tool(session: ScanSession) -> None:
    server = McpServer(session=session)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "exec_shell", "arguments": {"cmd": "echo hi"}},
        }
    )
    assert response["result"]["isError"] is True


def test_mcp_scan_file_traversal(session: ScanSession, tmp_path) -> None:
    server = McpServer(session=session)
    server.root = tmp_path
    payload = _call(server, "scan_file", {"path": "../secret.txt"})
    assert "error" in payload
