# Cursor install (automatic chat scan)

MCP tools alone do **not** see every message. Cursor only sends a prompt to those tools if the agent decides to call them.

The thing that actually gates **every local chat Send** is Cursor’s `beforeSubmitPrompt` hook. `sentinal-trace install` registers that hook **and** the MCP server in one step.

```bash
python -m pip install -e ".[dev]"
sentinal-trace install
```

Then **restart Cursor**. After that, hitting Send runs:

1. Scan the prompt (and attached files)
2. Policy (block / allow)
3. Optional team email / webhook if configured
4. If blocked, Cursor does not send the message

You do not run a scan command on each paste.

Check whether protection is actually on:

```bash
sentinal-trace status
```

`automatic_protection: true` and `can_block: true` means local Cursor Send is gated. If you uninstall or remove the hook, status reports OFF instead of pretending chats are still protected.

## What you should see

- Settings → Hooks: `beforeSubmitPrompt` pointing at `sentinal_trace.adapters.cursor_hook`
- Settings → MCP: `sentinal-trace` (optional tools; the hook is the gate)

## Team alerts (optional)

Set these in the user environment (not in git):

```bash
SENTINAL_TRACE_WEBHOOK_URL=https://your-team-endpoint.example/incidents
SENTINAL_TRACE_ALERT_EMAIL=security@yourteam.com
SENTINAL_TRACE_SMTP_URL=smtp://user:app-password@smtp.example.com:587
SENTINAL_TRACE_ALERT_FROM=sentinal-trace@yourteam.com
```

Alerts contain incident id, severity, and action. They never include the pasted log or the secret.

## Limits

- Works for **local** Cursor chat (the desktop/app Send path).
- Cursor **cloud agents** submit the prompt before a VM exists, so this hook does not run there.
- ChatGPT, Claude Desktop, and other apps are not Cursor; installing this does not wrap those products.
- The hook can **block** a send. It cannot silently redact and still send, because Cursor does not let a hook rewrite the prompt.

## MCP tools (optional)

If a client calls them:

| Tool | Purpose |
|------|---------|
| scan_text | Sanitized findings |
| scan_file | File under workspace root only |
| evaluate_policy | Verdict without a sendable payload |
| redact_content | Placeholder substitution |
| get_remediation | Generic guidance |
| get_detection_rules | Rule ids |
| get_incident_summary | Local incident metadata |

There is no tool that runs shell commands.
