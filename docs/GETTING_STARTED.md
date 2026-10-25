# Getting started

Follow the **one-shot walkthrough in [README.md](../README.md)** (install, tests, Cursor Send hook, Slack/Gmail, limits).

Short form:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q --tb=short
sentinal-trace install
sentinal-trace status
```

Fully quit and reopen Cursor. Do not paste real secrets while testing.
