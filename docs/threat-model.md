# Threat model

## Assets

- User prompts, source files, and environment values that may contain secrets
- Local audit database
- HMAC key used for fingerprints
- Optional notification credentials in the environment

## Adversaries

- Accidental disclosure by a developer into an AI chat or git commit
- Prompt-injection text inside scanned content trying to weaken policy
- Path traversal via MCP `scan_file`
- Log/SIEM scraping of scanner output

## Controls

| Threat | Control |
|--------|---------|
| Secret in prompt | Preflight block/redact when caller uses CLI, GuardedCall, git hook, or CI |
| Scanner leaks secret | Findings carry masked evidence only; logs pass a redaction filter; DB stores HMAC fingerprints |
| Prompt injection | Scanned text is untrusted; it cannot change loaded policy |
| Path escape | `resolve_within` + no symlink follow by default |
| Credential stuffing with found secrets | Engine never authenticates with a finding |
| Notification outage | Outbox retries; scan/enforcement still succeed |
| MCP confused deputy | No shell tool; file reads confined to workspace root |

## Out of scope (honest limitations)

- AI hosts that never call sentinal-trace
- Encrypted or binary secrets with no recognizable shape
- Perfect PII detection
- Stopping a user who copies a secret after a warn-only decision
