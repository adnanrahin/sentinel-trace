# Severity and confidence

These axes are independent.

## Severity

| Level | Meaning |
|-------|---------|
| SEV-0 | Critical exposure (private keys, cloud access keys) |
| SEV-1 | High |
| SEV-2 | Medium |
| SEV-3 | Low |
| SEV-4 | Informational |

## Confidence

| Level | Meaning |
|-------|---------|
| confirmed | Format is unambiguous (e.g. PEM header, AKIA key) |
| high | Strong pattern |
| medium | Heuristic / assignment context |
| low | Weak or documentation-like |

Risk score 0–100 is supporting evidence only (`sentinal_trace.risk.supporting_score`).
