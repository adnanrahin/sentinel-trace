"""Honest protection status. Never report blocked chats if the hook is not installed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinal_trace.adapters.cursor_hook import cursor_block_enabled
from sentinal_trace.notifications.providers import (
    active_team_notify_path,
    notifiers_from_env,
    notify_identity,
)

HOOK_MARKER = "sentinal_trace.adapters.cursor_hook"


def _cursor_home() -> Path:
    return Path.home() / ".cursor"


def _hooks_configured(hooks_path: Path) -> bool:
    if not hooks_path.exists():
        return False
    try:
        data = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    entries = (data.get("hooks") or {}).get("beforeSubmitPrompt") or []
    return any(HOOK_MARKER in str(e.get("command", "")) for e in entries if isinstance(e, dict))


def protection_status(cursor_home: Path | None = None) -> dict[str, Any]:
    home = cursor_home or _cursor_home()
    hooks_path = home / "hooks.json"
    enabled = _hooks_configured(hooks_path)
    providers = sorted(notifiers_from_env())
    team_notify = active_team_notify_path()
    return {
        "automatic_protection": enabled,
        "notifications_configured": providers,
        "notifications_ready": bool(providers),
        "notifications_identity": notify_identity(),
        "team_notify_file": str(team_notify) if team_notify else None,
        "application": "Cursor local chat",
        "mechanism": "beforeSubmitPrompt",
        "can_block": enabled and cursor_block_enabled(),
        "can_redact_in_place": False,
        "requires_mcp_tool_call": False,
        "covers_cursor_cloud_agents": False,
        "covers_other_ai_apps": False,
        "hooks_file": str(hooks_path),
        "message": (
            "Cursor Send is scanned. Blocking is off; email/webhook fire if configured. "
            "Set SENTINAL_TRACE_CURSOR_BLOCK=1 to refuse the send."
            if enabled
            else "Automatic scan is OFF. Run `sentinal-trace install` and restart Cursor."
        ),
    }


def uninstall_cursor_hooks(cursor_home: Path | None = None) -> Path:
    home = cursor_home or _cursor_home()
    path = home / "hooks.json"
    if not path.exists():
        return path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return path
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return path
    entries = [e for e in (hooks.get("beforeSubmitPrompt") or []) if isinstance(e, dict)]
    hooks["beforeSubmitPrompt"] = [e for e in entries if HOOK_MARKER not in str(e.get("command", ""))]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path
