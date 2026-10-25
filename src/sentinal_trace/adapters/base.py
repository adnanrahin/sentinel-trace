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
        name="cursor_hook",
        capabilities=frozenset(
            {
                AdapterCapability.SCAN,
                AdapterCapability.WARN,
                AdapterCapability.BLOCK,
            }
        ),
        enforcement="pre-send: Cursor beforeSubmitPrompt runs on every local chat Send",
        notes="Can block. Cannot redact in place. Does not cover Cursor cloud agents or other AI apps.",
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
        enforcement="tools only; does not intercept chat. Use cursor_hook for automatic Send blocking",
        notes="MCP is optional assist. The Cursor hook is what gates every local chat.",
    ),
    AdapterInfo(
        name="ci",
        capabilities=frozenset({AdapterCapability.SCAN, AdapterCapability.BLOCK}),
        enforcement="pre-merge when the CI job runs `sentinal-trace scan` and fails on block",
        notes="Does not inspect live AI chats.",
    ),
)
