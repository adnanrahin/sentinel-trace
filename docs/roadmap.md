# Roadmap / implementation checklist

## Done in this repository

- [x] Phase 0 — architecture, threat model, taxonomy, privacy, integrations
- [x] Phase 1 — detectors, context, policy, CLI scan, JSON, exit codes, synthetic tests
- [x] Phase 2 — preflight, SQLite audit, HMAC fingerprints, leak tests
- [x] Phase 3 — stdio MCP tools, path validation, Cursor install docs
- [x] Phase 4 — enforcing adapters: Python `GuardedCall`, git pre-commit, CI; MCP labeled detection-only
- [x] Phase 5 — outbox, webhook/PagerDuty/email interfaces, mocked delivery tests
- [x] Phase 6 — e2e tests, ruff/mypy/pytest CI, git-push GitHub Release workflow

## Follow-on (not claimed as shipped)

- [ ] Optional local dashboard (read-only incident UI)
- [ ] Additional high-confidence credential formats
- [ ] IDE-native interceptors if/when a vendor documents a stable pre-send hook
- [ ] Team policy distribution without a cloud control plane

## Known limitations

- Pattern coverage is broad but incomplete; entropy heuristics can false-positive.
- National-id-like patterns are low confidence by design.
- Email/IP findings are not critical incidents by default.
- MCP cannot promise prevention inside arbitrary AI apps.
