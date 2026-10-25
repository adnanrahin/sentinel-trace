# MCP

sentinal-trace ships a stdio MCP server on the same wheel as the CLI. A push to `main` builds the package, publishes a GitHub Release, and you install it with pip, then run `sentinal-trace mcp`.

## Tools

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

## Cursor

Project `.cursor/mcp.json` or user `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "sentinal-trace": {
      "command": "sentinal-trace",
      "args": ["mcp"]
    }
  }
}
```

Reload Cursor → Settings → MCP. You should see `sentinal-trace`.

## Capability statement

MCP **does not** wrap the model’s send path. If the agent never calls `scan_text` / `evaluate_policy`, content is not checked. Add a project rule if you want the agent to call scan tools before pasting secrets — that is still best-effort, not a kernel-level block.
