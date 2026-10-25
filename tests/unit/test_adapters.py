from __future__ import annotations

from sentinal_trace.adapters.base import ADAPTERS
from sentinal_trace.models.enums import AdapterCapability


def test_mcp_does_not_claim_block() -> None:
    mcp = next(a for a in ADAPTERS if a.name == "mcp")
    assert AdapterCapability.BLOCK not in mcp.capabilities
    assert "does not intercept" in mcp.notes.lower() or "detection-only" in mcp.enforcement


def test_python_guard_claims_block() -> None:
    guard = next(a for a in ADAPTERS if a.name == "python_guard")
    assert AdapterCapability.BLOCK in guard.capabilities
