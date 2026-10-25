# sentinal-trace

**Local-first AI security exposure prevention.** Scan prompts, files, and commits for credentials, keys, and other sensitive data. Block or redact **before send** when the caller uses a real enforcement boundary.

Nothing is uploaded. State lives in `~/.sentinal-trace/` (SQLite metadata only — never the raw secret).

This product was designed as an exposure-prevention engine, not a dashboard. MCP is included so Cursor and other clients can *call* scan tools. MCP does **not** intercept every chat message by itself.

## Quick start

```bash
python -m pip install -e ".[dev]"
sentinal-trace doctor
sentinal-trace scan path examples/demo-synthetic.txt
sentinal-trace preflight --text "hello"
```

Demo file values are **synthetic**. Do not treat them as live credentials.

### Exit codes (CI)

| Code | Meaning |
|------|---------|
| 0 | Clean / allow |
| 1 | Findings with warn/redact/audit |
| 2 | **Blocked** — do not send |
| 3 | Tool error |

## What actually prevents a send

| Integration | Prevents send? | How |
|-------------|----------------|-----|
| `sentinal-trace preflight` CLI | Yes, for that invocation | Exit 2 and `payload: null` |
| `GuardedCall` / `preflight()` in Python | Yes, for wrapped calls | Raises `TransmissionBlocked`; callee never runs |
| Git pre-commit (`sentinal-trace install-hook`) | Yes, for the commit | Hook aborts on block |
| CI `sentinal-trace scan` | Yes, for the pipeline | Job fails on exit 2 |
| MCP tools in Cursor / Claude | **No (detection-only)** | Host must call tools; chats not auto-intercepted |

Run `sentinal-trace capabilities` for the live list.

## MCP

After `pip install` from a GitHub Release wheel:

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

Windows: if the script is not on PATH, use the venv Python:

```json
{
  "mcpServers": {
    "sentinal-trace": {
      "command": "C:\\path\\to\\.venv\\Scripts\\python.exe",
      "args": ["-m", "sentinal_trace.mcp"]
    }
  }
}
```

## Git-push releases

Push to `main` / `master`. GitHub Actions runs tests, builds a wheel, bumps the patch version, tags `vX.Y.Z`, and attaches `.whl` / `.tar.gz` to a GitHub Release. Install with:

```bash
pip install https://github.com/<org>/<repo>/releases/download/v0.1.0/sentinal_trace-0.1.0-py3-none-any.whl
```

## Python API

```python
from sentinal_trace import GuardedCall, preflight

decision = preflight(prompt)
if not decision.allowed:
    raise SystemExit(decision.reason)

def send(text: str) -> str:
    return text

safe_send = GuardedCall(send)
safe_send("no secrets here")
```

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Detection taxonomy](docs/detection-taxonomy.md)
- [Severity and confidence](docs/severity-and-confidence.md)
- [Privacy](docs/privacy.md)
- [Integrations](docs/integrations.md)
- [Policies](docs/policies.md)
- [MCP](docs/MCP.md)
- [Roadmap](docs/roadmap.md)

## Develop

```bash
python -m pip install -e ".[dev]"
python -m pytest
ruff check src tests
mypy --config-file pyproject.toml
```
