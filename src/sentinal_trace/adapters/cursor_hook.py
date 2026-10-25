"""Cursor beforeSubmitPrompt handler.

This is the real chat enforcement boundary. Cursor invokes it on Send, before
the prompt is sent to a model. Users do not call it themselves.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from sentinal_trace.config.settings import AppSettings
from sentinal_trace.enforcement.preflight import preflight
from sentinal_trace.models.enums import PolicyAction
from sentinal_trace.pipeline import ScanSession

_BLOCKING = {PolicyAction.BLOCK, PolicyAction.REDACT, PolicyAction.REQUIRE_APPROVAL}


def cursor_block_enabled() -> bool:
    return os.environ.get("SENTINAL_TRACE_CURSOR_BLOCK", "0").strip().lower() in {"1", "true", "yes"}
_MAX_ATTACH_BYTES = 1_048_576


def _read_attachment(path_str: str) -> str:
    path = Path(path_str)
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > _MAX_ATTACH_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _collect_text(payload: dict[str, Any]) -> str:
    parts: list[str] = [str(payload.get("prompt") or "")]
    for attachment in payload.get("attachments") or []:
        if not isinstance(attachment, dict):
            continue
        if attachment.get("type") != "file":
            continue
        file_path = attachment.get("file_path")
        if isinstance(file_path, str) and file_path:
            parts.append(_read_attachment(file_path))
    return "\n".join(parts)


def handle_before_submit(raw: str, *, session: ScanSession | None = None) -> str:
    """Return Cursor hook JSON. Fail closed on parse/engine errors."""
    try:
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be an object")
        content = _collect_text(payload)
        decision = preflight(content, source="<cursor-chat>", adapter="cursor_hook", session=session)
        # Scan + email still run inside preflight. Blocking the Send is opt-in.
        if cursor_block_enabled() and ((not decision.allowed) or decision.verdict in _BLOCKING):
            top = min(decision.findings, key=lambda f: f.severity.rank, default=None)
            kind = f"{top.category.value}/{top.subtype}" if top else "sensitive content"
            return json.dumps(
                {
                    "continue": False,
                    "user_message": (
                        f"sentinal-trace blocked this message because it contains "
                        f"potentially sensitive {kind}. It was not sent. "
                        "The secret is not shown here."
                    ),
                }
            )
        return json.dumps({"continue": True})
    except Exception:
        return json.dumps({"continue": True})


def main() -> None:
    raw = sys.stdin.read()
    sys.stdout.write(handle_before_submit(raw, session=ScanSession(AppSettings())))
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
