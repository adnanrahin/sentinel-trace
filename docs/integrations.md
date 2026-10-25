# Integrations

## Python (enforcing)

Wrap the function that actually transmits:

```python
from sentinal_trace import GuardedCall

client_send = GuardedCall(your_sdk_complete)
client_send(user_prompt)
```

If policy blocks, `TransmissionBlocked` is raised and `your_sdk_complete` is not called.

## Git pre-commit (enforcing)

```bash
sentinal-trace install-hook --repo .
```

Protects commits, not chat.

## CI (enforcing for the pipeline)

```bash
sentinal-trace scan path . --format json
```

Fail the job on exit code 2.

## MCP (detection / assist)

See [MCP.md](MCP.md). Compatible clients can call `scan_text` and `redact_content`. That is not universal pre-send prevention.

## Cursor / Claude chat

No supported host API intercepts every composer message in a way we can honestly call a block. Do not configure MCP and assume chats are gated. Use GuardedCall in your own bots, preflight in scripts, and the git hook for source.
