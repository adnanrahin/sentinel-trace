"""Honest protection status. Never report blocked chats if the hook is not installed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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
    return {
        "automatic_protection": enabled,
        "application": "Cursor local chat",
        "mechanism": "beforeSubmitPrompt",
        "can_block": enabled,
        "can_redact_in_place": False,
        "requires_mcp_tool_call": False,
        "covers_cursor_cloud_agents": False,
        "covers_other_ai_apps": False,
        "hooks_file": str(hooks_path),
        "message": (
            "Automatic pre-send protection is ON for local Cursor chat."
            if enabled
            else "Automatic protection is OFF. Run `sentinal-trace install` and restart Cursor."
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
