from __future__ import annotations

from dataclasses import dataclass

from sentinal_trace.models.enums import AdapterCapability


@dataclass(frozen=True)
class AdapterInfo:
    name: str
    capabilities: frozenset[AdapterCapability]
    enforcement: str
    notes: str


ADAPTERS = (
    AdapterInfo(
        name="cli",
        capabilities=frozenset(
            {
                AdapterCapability.SCAN,
                AdapterCapability.WARN,
                AdapterCapability.REDACT,
                AdapterCapability.BLOCK,
            }
        ),
        enforcement="pre-send for callers that invoke `sentinal-trace preflight`",
        notes="Does not intercept other processes automatically.",
    ),
    AdapterInfo(
        name="python_guard",
        capabilities=frozenset(
            {
                AdapterCapability.SCAN,
                AdapterCapability.WARN,
                AdapterCapability.REDACT,
                AdapterCapability.BLOCK,
            }
        ),
        enforcement="pre-send when code wraps send functions with GuardedCall or preflight()",
        notes="Genuine block: the wrapped function is not called when policy blocks.",
    ),
    AdapterInfo(
        name="git_pre_commit",
        capabilities=frozenset(
            {
                AdapterCapability.SCAN,
                AdapterCapability.WARN,
                AdapterCapability.BLOCK,
            }
        ),
        enforcement="pre-commit: staged files are scanned; commit is aborted on block",
        notes="Protects git commits, not AI chat prompts.",
    ),
    AdapterInfo(
        name="mcp",
        capabilities=frozenset(
            {
                AdapterCapability.SCAN,
                AdapterCapability.WARN,
                AdapterCapability.REDACT,
            }
        ),
        enforcement="detection-only unless the client calls scan/redact tools before sending",
        notes="MCP does not intercept all prompts from Cursor, Claude, or other hosts.",
    ),
    AdapterInfo(
        name="ci",
        capabilities=frozenset({AdapterCapability.SCAN, AdapterCapability.BLOCK}),
        enforcement="pre-merge when the CI job runs `sentinal-trace scan` and fails on block",
        notes="Does not inspect live AI chats.",
    ),
)
