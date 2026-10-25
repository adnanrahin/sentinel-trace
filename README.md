# sentinal-trace

Local-first guard for AI chat and developer workflows. It scans what you are about to send, can email or Slack the team, and can optionally refuse the send.

Nothing is uploaded to sentinal-trace. Metadata lives in `~/.sentinal-trace/` (never the raw secret).

**You do not type `/scan`.** After one install, every local Cursor Send is scanned automatically. Blocking the Send is off unless `SENTINAL_TRACE_CURSOR_BLOCK=1`.

---

## One-shot end-to-end (do this once)

Requires **Python 3.11+** and the **Cursor desktop app**.

### 1. Clone and install

**Windows (Git Bash)** — if `python` is 3.10, use the 3.11+ launcher:

```bash
git clone https://github.com/adnanrahin/sentinel-trace.git
cd sentinel-trace
py -3.13 -m venv .venv
source .venv/Scripts/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

**macOS / Linux:**

```bash
git clone https://github.com/adnanrahin/sentinel-trace.git
cd sentinel-trace
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

PowerShell activate: `.venv\Scripts\Activate.ps1`

### 2. Prove the engine (tests)

```bash
python -m pytest -q --tb=short
sentinal-trace version
```

Expect tests to pass. Demo values in `examples/` are synthetic placeholders, not live keys.

### 3. Turn on automatic Cursor protection

```bash
sentinal-trace install
sentinal-trace status
```

`automatic_protection` should be `true`. Chat is **not** blocked by default; findings can still email you. Then **fully quit Cursor and open it again**.

That one command writes:

| File | What it does |
|------|----------------|
| `~/.cursor/hooks.json` | Runs sentinal-trace on **every chat Send** (this is the firewall) |
| `~/.cursor/mcp.json` | Optional MCP tools (not required for scan or email) |
| `~/.sentinal-trace/` | Local audit DB + HMAC key (created on first scan) |

### 4. Prove Gmail (or Slack) works

Open a **new** terminal after setting user environment variables (below), then:

```bash
sentinal-trace status
sentinal-trace notify-test
```

`notifications_configured` must include `"email"`. `notify-test` should print `"sent": true`. Check the inbox for a sanitized alert (no secret, no pasted log).

Pasting a payment log in chat still scans and can email; the Send is **not** blocked. To refuse the Send later, set `SENTINAL_TRACE_CURSOR_BLOCK=1` and restart Cursor.

```bash
sentinal-trace incidents
sentinal-trace doctor
```

If `sentinal-trace status` says the scan is OFF, run `sentinal-trace install` again and restart Cursor. MCP showing up in Settings is not enough by itself.

---

## Team notifications (Slack webhook, not per-user Gmail)

Engineers should not set SMTP. **Admin** drops one incoming webhook in `%PROGRAMDATA%\sentinal-trace\notify.env` (see `configs/notify.team.example.env`). **Engineer** only runs `sentinal-trace install` and restarts Cursor. MCP does not discover email accounts; the Send hook reads that team file.

Per-user Gmail is optional (below) and is **not** the team path. Do not commit webhook URLs or passwords. `.env.example` is a name list only and is **not** loaded.

Do not commit webhook URLs or passwords.

### Slack / Teams / Discord (recommended)

1. Create an **incoming webhook** in Slack (or Teams/Discord).
2. Set `SENTINAL_TRACE_WEBHOOK_URL` to that HTTPS URL.
3. Restart Cursor.

**Windows:** Settings → Environment Variables → User variables → New.

**macOS** (GUI Cursor does not read `~/.zshrc`):

```bash
launchctl setenv SENTINAL_TRACE_WEBHOOK_URL 'https://hooks.slack.com/services/...'
```

Then Cmd+Q Cursor and reopen. Re-run `launchctl` after logout, or add a LaunchAgent.

**Linux** (desktop session):

```bash
mkdir -p ~/.config/environment.d
echo 'SENTINAL_TRACE_WEBHOOK_URL=https://hooks.slack.com/services/...' >> ~/.config/environment.d/sentinal-trace.conf
```

Log out and back in, then start Cursor.

### Gmail (no SMTP server to build)

1. Enable [2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification).
2. Create an [App password](https://myaccount.google.com/apppasswords) for Mail.
3. Set all three (use `%40` instead of `@` in the URL username):

```text
SENTINAL_TRACE_SMTP_URL=smtp://you%40gmail.com:APP_PASSWORD@smtp.gmail.com:587
SENTINAL_TRACE_ALERT_EMAIL=you@gmail.com
SENTINAL_TRACE_ALERT_FROM=you@gmail.com
```

Same Windows / `launchctl` / `environment.d` pattern as Slack. **Git Bash:** an already-open shell will not see Windows GUI variables — `export` the three names in that same window (single quotes), then `sentinal-trace notify-test`. If that reports `smtp authentication failed`, create a fresh Gmail App password and update `SENTINAL_TRACE_SMTP_URL` — Gmail returns 535 when the password is wrong or revoked.

Mail/Slack payloads are incident id, severity, and category — **not** the pasted log.

PagerDuty: set `SENTINAL_TRACE_PAGERDUTY_ROUTING_KEY` the same way.

---

## Optional extras (not required for chat)

CLI scan:

```bash
sentinal-trace preflight --text "hello"
sentinal-trace scan path examples/demo-synthetic.txt --format json
```

Exit codes: `0` allow, `1` warn/redact, `2` blocked, `3` error.

Git pre-commit:

```bash
sentinal-trace install-hook
```

Python wrap (your own send function):

```python
from sentinal_trace import GuardedCall, preflight

decision = preflight(prompt)
if not decision.allowed:
    raise SystemExit(decision.reason)

safe_send = GuardedCall(your_sdk_complete)
safe_send("no secrets here")
```

---

## What is and is not protected

| Path | Scans? | Blocks send by default? |
|------|--------|-------------------------|
| Local Cursor chat after `sentinal-trace install` | Yes | No (`SENTINAL_TRACE_CURSOR_BLOCK=1` to refuse) |
| CLI `preflight` / `GuardedCall` | Yes | Yes, for that call |
| Git hook / CI `sentinal-trace scan` | Yes | Yes, for commit/job |
| MCP tools only | Only if called | No |
| Cursor **cloud** agents | No | No |
| ChatGPT, Claude Desktop, other apps | No | No |

Turn protection off:

```bash
sentinal-trace uninstall
sentinal-trace status
```

---

## Develop / CI

```bash
python -m pytest -q --tb=short
ruff check src tests
ruff format --check src tests
mypy --config-file pyproject.toml
```

Push to `main` / `master` builds a wheel, tags a release, and attaches `.whl` / `.tar.gz`.

## Docs

- [Getting started](docs/GETTING_STARTED.md)
- [Cursor / MCP](docs/MCP.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Detection taxonomy](docs/detection-taxonomy.md)
- [Privacy](docs/privacy.md)
- [Policies](docs/policies.md)
- [Integrations](docs/integrations.md)
