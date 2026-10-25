# Policies

Starter file: `configs/policy.example.yaml`.

Copy to `.sentinal-trace.yaml` in a repo or `~/.sentinal-trace/policy.yaml`.

Override path with `SENTINAL_TRACE_POLICY`.

## Actions

| Action | Effect in preflight |
|--------|---------------------|
| allow | Send original |
| audit | Send original; record incident |
| warn | Send original; exit 1 |
| redact | Send redacted payload; `content_changed=true` |
| block | `allowed=false`, `payload=null`, exit 2 |
| require_approval | Treated as block unless `--approve` |

Rules are evaluated deterministically. The strongest matching action wins. Path glob exceptions can downgrade (used for synthetic fixtures).
