# Cursor install (automatic chat scan)

MCP tools alone do **not** see every message. Cursor only sends a prompt to those tools if the agent decides to call them.

The thing that actually gates **every local chat Send** is Cursor’s `beforeSubmitPrompt` hook. `sentinal-trace install` registers that hook **and** the MCP server in one step.

```bash
python -m pip install -e ".[dev]"
sentinal-trace install
```

Then **restart Cursor**. After that, hitting Send runs:

1. Scan the prompt (and attached files)
2. Policy (block / allow internally)
3. Optional team email / webhook if configured
4. Send proceeds unless `SENTINAL_TRACE_CURSOR_BLOCK=1`

You do not run a scan command on each paste.

Check whether protection is actually on:

```bash
sentinal-trace status
```

`automatic_protection: true` means local Cursor Send is scanned. `can_block` is true only when `SENTINAL_TRACE_CURSOR_BLOCK=1`. If you uninstall or remove the hook, status reports OFF.

## What you should see

- Settings → Hooks: `beforeSubmitPrompt` pointing at `sentinal_trace.adapters.cursor_hook`
- Settings → MCP: `sentinal-trace` (optional tools; the hook is the scanner)

## Team alerts (engineers do not set Gmail)

MCP does **not** look up anyone’s inbox. One admin places a **Slack/Teams webhook** in a machine-wide file. `sentinal-trace install` registers the Send hook; the hook reads that file on every paste.

**Admin (once per laptop image / GPO):** copy `configs/notify.team.example.env` to:

- Windows: `%PROGRAMDATA%\sentinal-trace\notify.env`
- macOS: `/Library/Application Support/sentinal-trace/notify.env`
- Linux: `/etc/sentinal-trace/notify.env`

Put only:

```bash
SENTINAL_TRACE_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Do not commit the real URL. Do not ask each engineer for a Gmail app password.

**Engineer:**

```bash
python -m pip install sentinal-trace
sentinal-trace install
```

Restart Cursor. `sentinal-trace status` shows `team_notify_file` when the admin file is present.

Personal Gmail env vars still work as an override. Alerts contain incident id, severity, and action — not the pasted log.

## Limits

- Works for **local** Cursor chat (the desktop/app Send path).
- Cursor **cloud agents** submit the prompt before a VM exists, so this hook does not run there.
- ChatGPT, Claude Desktop, and other apps are not Cursor; installing this does not wrap those products.
- Default is detect + notify. Set `SENTINAL_TRACE_CURSOR_BLOCK=1` to refuse the send. The hook cannot rewrite the prompt.

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
