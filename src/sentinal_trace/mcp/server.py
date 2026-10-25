"""Stdio MCP server for sentinal-trace.

Cursor launches `sentinal-trace mcp` as a subprocess and speaks JSON-RPC on
stdio. This is a security *tooling* interface: it does not intercept prompts
the host never submits to these tools.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from sentinal_trace import __version__
from sentinal_trace.config.settings import AppSettings
from sentinal_trace.enforcement.preflight import preflight
from sentinal_trace.enforcement.redact import redact_matches
from sentinal_trace.pipeline import ScanSession, scan_path, scan_text
from sentinal_trace.security.paths import PathSecurityError, resolve_within

PROTOCOL_VERSION = "2024-11-05"
MAX_TOOL_CHARS = 200_000

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_text",
        "description": (
            "Scan text for credentials, keys, and other sensitive exposures. "
            "Returns sanitized findings only. Does not intercept other prompts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "scan_file",
        "description": "Scan a file under the current workspace root. Path traversal is rejected.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "evaluate_policy",
        "description": "Scan text and return the policy action (allow/warn/redact/block) without a sendable payload.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "redact_content",
        "description": "Return a redacted copy of the text. Original secrets are not stored.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "get_remediation",
        "description": "Return remediation guidance for a finding category or rule id.",
        "inputSchema": {
            "type": "object",
            "properties": {"rule_id": {"type": "string"}},
            "required": ["rule_id"],
        },
    },
    {
        "name": "get_detection_rules",
        "description": "List detection rule identifiers shipped with this version.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_incident_summary",
        "description": "Summarize recent local incidents (no raw prompts or secrets).",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 10}},
        },
    },
]


class McpServer:
    def __init__(self, session: ScanSession | None = None) -> None:
        self.session = session or ScanSession(AppSettings())
        self.root = Path.cwd()

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method", "")
        msg_id = message.get("id")
        if method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                result: Any = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "sentinal-trace", "version": __version__},
                    "instructions": (
                        "sentinal-trace MCP tools scan or redact content you pass in. "
                        "They do not automatically intercept every AI conversation."
                    ),
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = self._tools_call(message.get("params", {}) or {})
            else:
                return self._error(msg_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            return self._error(msg_id, -32603, f"Internal error: {type(exc).__name__}")
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        try:
            payload = self._dispatch(name, args)
            is_error = False
        except (ValueError, PathSecurityError) as exc:
            payload = {"error": str(exc)}
            is_error = True
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "isError": is_error,
        }

    def _bound_text(self, args: dict[str, Any]) -> str:
        text = args.get("text")
        if not isinstance(text, str):
            raise ValueError("text is required")
        if len(text) > MAX_TOOL_CHARS:
            raise ValueError("input exceeds size limit")
        return text

    def _dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "scan_text":
            result = scan_text(self._bound_text(args), adapter="mcp", session=self.session)
            return {
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "policy_action": result.policy_action,
                "capability": "scan",
            }
        if name == "scan_file":
            path = args.get("path")
            if not isinstance(path, str):
                raise ValueError("path is required")
            resolve_within(path, self.root)
            result = scan_path(path, root=self.root, adapter="mcp", session=self.session)
            return {
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "policy_action": result.policy_action,
                "source": result.source,
            }
        if name == "evaluate_policy":
            decision = preflight(self._bound_text(args), adapter="mcp", session=self.session)
            return {
                "allowed": decision.allowed,
                "verdict": decision.verdict,
                "reason": decision.reason,
                "finding_count": len(decision.findings),
            }
        if name == "redact_content":
            text = self._bound_text(args)
            result, matches, document = scan_text(text, adapter="mcp", session=self.session, raw=True)
            return {
                "redacted": redact_matches(document.text, matches),
                "content_changed": True,
                "policy_action": result.policy_action,
            }
        if name == "get_remediation":
            rule_id = str(args.get("rule_id", ""))
            return {
                "rule_id": rule_id,
                "guidance": (
                    "Remove the sensitive value, rotate the credential if it may have been exposed, "
                    "and rescan before sending."
                ),
            }
        if name == "get_detection_rules":
            return {
                "rules": [
                    "cred.aws_access_key_id",
                    "cred.github_pat",
                    "cred.github_fine_grained_pat",
                    "cred.stripe_secret_key",
                    "cred.slack_token",
                    "cred.jwt",
                    "cred.connection_string",
                    "cred.pem_private_key",
                    "cred.assignment",
                    "net.ipv4",
                    "net.internal_host",
                    "infra.k8s_secret",
                    "id.aws_arn",
                    "id.account",
                    "pii.email",
                    "pii.national_id_like",
                    "composite.cred_endpoint",
                ]
            }
        if name == "get_incident_summary":
            limit = int(args.get("limit") or 10)
            limit = max(1, min(limit, 50))
            return {"incidents": self.session.store.recent(limit)}
        raise ValueError(f"Unknown tool: {name}")


def run_stdio_server(session: ScanSession | None = None) -> None:
    server = McpServer(session=session)
    print(f"sentinal-trace MCP server v{__version__} ready (stdio)", file=sys.stderr)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = server.handle_message(message)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("sentinal-trace MCP server stopped", file=sys.stderr)
        sys.exit(0)
