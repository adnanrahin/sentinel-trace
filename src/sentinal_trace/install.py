"""One-shot install: Cursor intercepts every Send, MCP tools are available."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _cursor_home() -> Path:
    return Path.home() / ".cursor"


def _hook_command() -> str:
    exe = Path(sys.executable)
    return f'"{exe}" -m sentinal_trace.adapters.cursor_hook'


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def install_cursor_hooks(cursor_home: Path | None = None) -> Path:
    home = cursor_home or _cursor_home()
    path = home / "hooks.json"
    data = _read_json(path)
    data["version"] = 1
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks
    entries = [e for e in (hooks.get("beforeSubmitPrompt") or []) if isinstance(e, dict)]
    entries = [e for e in entries if "sentinal_trace.adapters.cursor_hook" not in str(e.get("command", ""))]
    entries.append({"command": _hook_command(), "failClosed": False})
    hooks["beforeSubmitPrompt"] = entries
    _write_json(path, data)
    return path


def install_cursor_mcp(cursor_home: Path | None = None) -> Path:
    home = cursor_home or _cursor_home()
    path = home / "mcp.json"
    data = _read_json(path)
    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        servers = {}
        data["mcpServers"] = servers
    servers["sentinal-trace"] = {
        "command": sys.executable,
        "args": ["-m", "sentinal_trace.mcp"],
    }
    _write_json(path, data)
    return path


def install_user() -> dict[str, str]:
    from sentinal_trace.notifications.providers import active_team_notify_path

    hooks = install_cursor_hooks()
    mcp = install_cursor_mcp()
    team = active_team_notify_path()
    result = {"hooks": str(hooks), "mcp": str(mcp), "command": _hook_command()}
    if team is not None:
        result["team_notify"] = str(team)
    else:
        result["team_notify"] = ""
        result["team_notify_hint"] = (
            "No team notify file. Admin: put SENTINAL_TRACE_WEBHOOK_URL in "
            r"%PROGRAMDATA%\sentinal-trace\notify.env (Windows) so engineers skip Gmail."
        )
    return result
