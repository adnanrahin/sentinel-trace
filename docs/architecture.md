# Architecture

sentinal-trace is a single Python package. Detection, policy, and enforcement share one pipeline. Adapters only normalize input and declare capabilities.

```
CLI / Python / Git hook / MCP
        │
        ▼
  Input adapter (capability: scan|warn|redact|block|observe_history)
        │
        ▼
  Normalize (size limits, encoding, format hint)
        │
        ▼
  Detectors → Context/correlation → Policy → Decision
        │
        ├── Audit SQLite (metadata + HMAC fingerprint, never raw secret)
        └── Optional notification outbox
```

## Enforcement contract

`PreflightDecision` is the only send/no-send API:

- `allowed=False` ⇒ `payload` is always `None`
- `verdict=block` cannot be constructed with `allowed=True` (Pydantic validator)
- Callers that ignore `allowed` and send original text are outside the trust boundary; the CLI and `GuardedCall` do not do that

## Why MCP is not the enforcement boundary

MCP tools run when a host invokes them. Cursor and similar clients do not guarantee a pre-send hook for every user message. The MCP adapter therefore advertises scan/warn/redact only.

Genuine prevention in v0.1:

1. CLI `preflight`
2. `GuardedCall` around application send functions
3. Git pre-commit hook
4. CI scan job

## Local state

`SENTINAL_TRACE_HOME` (default `~/.sentinal-trace`):

- `audit.db` — incidents, events, notification outbox
- `hmac.key` — local HMAC key for fingerprints (created 0600)
- `policy.yaml` — optional override

## MCP implementation note

The stdio server speaks MCP JSON-RPC (`initialize`, `tools/list`, `tools/call`). That keeps the wheel small, testable without a browser, and drop-in for Cursor `mcp.json`. The official MCP Python SDK is not a runtime dependency so a GitHub Release install stays local-first and auditable.
