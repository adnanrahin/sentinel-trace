from __future__ import annotations

from sentinal_trace.adapters.base import ADAPTERS
from sentinal_trace.models.enums import AdapterCapability


def test_mcp_does_not_claim_block() -> None:
    mcp = next(a for a in ADAPTERS if a.name == "mcp")
    assert AdapterCapability.BLOCK not in mcp.capabilities
    assert "does not intercept" in mcp.enforcement.lower()


def test_python_guard_claims_block() -> None:
    guard = next(a for a in ADAPTERS if a.name == "python_guard")
    assert AdapterCapability.BLOCK in guard.capabilities


def test_cursor_hook_blocks_but_does_not_claim_in_place_redact() -> None:
    hook = next(a for a in ADAPTERS if a.name == "cursor_hook")
    assert AdapterCapability.BLOCK in hook.capabilities
    assert AdapterCapability.REDACT not in hook.capabilities
