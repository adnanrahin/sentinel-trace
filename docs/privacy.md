# Privacy

- Default operation is local. No cloud account.
- Raw prompts and raw secrets are **not** stored in SQLite.
- Fingerprints are HMAC-SHA256 with a key in `~/.sentinal-trace/hmac.key`, not a plain hash of the secret.
- Notification payloads include incident id, action, category, severity, adapter — never the prompt.
- Optional providers (email, PagerDuty, webhook) are off until you set environment variables.

There is no “store full prompt” feature in v0.1.
