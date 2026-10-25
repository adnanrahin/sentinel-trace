from __future__ import annotations

import json

from tests.conftest import SYNTHETIC_AWS

from sentinal_trace.adapters.cursor_hook import handle_before_submit
from sentinal_trace.install import install_cursor_hooks, install_cursor_mcp
from sentinal_trace.pipeline import ScanSession
from sentinal_trace.status import protection_status, uninstall_cursor_hooks


def test_cursor_hook_blocks_secret_without_user_action(session: ScanSession) -> None:
    payload = json.dumps({"prompt": f"debug this log {SYNTHETIC_AWS}", "attachments": []})
    result = json.loads(handle_before_submit(payload, session=session))
    assert result["continue"] is False
    assert SYNTHETIC_AWS not in json.dumps(result)


def test_cursor_hook_allows_clean_chat(session: ScanSession) -> None:
    payload = json.dumps({"prompt": "explain this function", "attachments": []})
    result = json.loads(handle_before_submit(payload, session=session))
    assert result["continue"] is True


def test_cursor_hook_fail_closed_on_garbage() -> None:
    result = json.loads(handle_before_submit("not-json{"))
    assert result["continue"] is False


def test_cursor_hook_does_not_send_redacted_original(session: ScanSession) -> None:
    """Cursor cannot rewrite prompts; redact policy must still set continue=false."""
    payload = json.dumps({"prompt": f"log {SYNTHETIC_AWS}"})
    result = json.loads(handle_before_submit(payload, session=session))
    assert result["continue"] is False
    assert "payload" not in result
    assert SYNTHETIC_AWS not in result["user_message"]


def test_hook_does_not_use_mcp(session: ScanSession) -> None:
    payload = json.dumps({"prompt": "hello"})
    result = json.loads(handle_before_submit(payload, session=session))
    assert result == {"continue": True}


def test_status_off_until_install(tmp_path) -> None:
    status = protection_status(tmp_path)
    assert status["automatic_protection"] is False
    assert status["can_block"] is False
    assert status["can_redact_in_place"] is False
    assert status["requires_mcp_tool_call"] is False
    install_cursor_hooks(tmp_path)
    on = protection_status(tmp_path)
    assert on["automatic_protection"] is True
    assert on["can_block"] is True
    uninstall_cursor_hooks(tmp_path)
    off = protection_status(tmp_path)
    assert off["automatic_protection"] is False


def test_install_writes_hook_and_mcp(tmp_path) -> None:
    hooks = install_cursor_hooks(tmp_path)
    mcp = install_cursor_mcp(tmp_path)
    hook_data = json.loads(hooks.read_text(encoding="utf-8"))
    mcp_data = json.loads(mcp.read_text(encoding="utf-8"))
    assert hook_data["hooks"]["beforeSubmitPrompt"][0]["failClosed"] is True
    assert "cursor_hook" in hook_data["hooks"]["beforeSubmitPrompt"][0]["command"]
    assert mcp_data["mcpServers"]["sentinal-trace"]["args"] == ["-m", "sentinal_trace.mcp"]
