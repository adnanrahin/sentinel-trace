# Integrations

## Cursor chat (automatic)

```bash
sentinal-trace install
```

Restart Cursor. Every local chat Send is scanned via `beforeSubmitPrompt`. People in the team do not run extra commands per paste.

MCP is installed at the same time for tools; the hook is what blocks the send.

## Team email / API

Configure environment variables (see `.env.example`). On `block` or `redact`, sentinal-trace POSTs a sanitized incident to the webhook and/or sends SMTP mail. Notification failure does not disable the block.

## Python (enforcing)

```python
from sentinal_trace import GuardedCall

client_send = GuardedCall(your_sdk_complete)
client_send(user_prompt)
```

## Git pre-commit

```bash
sentinal-trace install-hook --repo .
```

## CI

```bash
sentinal-trace scan path . --format json
```

Fail the job on exit code 2.
