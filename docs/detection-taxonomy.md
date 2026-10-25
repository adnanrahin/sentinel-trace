# Detection taxonomy

| Category | Subtypes (v0.1) | Default posture |
|----------|-----------------|-----------------|
| credential | aws_access_key_id, github_pat, stripe_secret_key, slack_token, jwt, connection_string, assigned_secret | block at high confidence |
| private_key | pem_private_key | block |
| network | private_ipv4, public_ipv4, internal_hostname | warn / info; examples downgraded |
| infrastructure | kubernetes_secret | warn |
| identifier | aws_arn, account_id | audit |
| pii | email, national_id_like | audit; national-id-like is low confidence |
| composite | credential_plus_endpoint | block |

Detectors emit structured evidence (span, rule id, severity, confidence, risk factors). They do not confirm that a credential is live.

## Measured corpus (synthetic)

See `tests/unit/test_corpus.py`. On the labeled fixture set used in CI, precision and recall for credential vs non-credential labels are both 1.0. That is **not** a claim about production traffic.
