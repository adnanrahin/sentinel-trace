"""Synthetic pastes for local Cursor tests. Values are not live credentials."""

from __future__ import annotations


def aws_doc_example_access_key() -> str:
    # AWS documentation example id, assembled so git does not store a contiguous AKIA… literal.
    return "".join(("AKI", "A", "IOSFODNN7", "EXAMPLE"))


def payment_failure_log(*, access_key: str | None = None) -> str:
    key = access_key or aws_doc_example_access_key()
    return (
        "2026-10-24 23:12:01 ERROR [PaymentService] Failed to upload transaction batch to S3\n"
        "Service: payment-processing-prod\n"
        "Region: us-east-1\n"
        "Bucket: company-prod-transactions\n"
        "\n"
        f"AWS_ACCESS_KEY_ID={key}\n"
        "AWS_SECRET_ACCESS_KEY=EXAMPLEFAKESECRETKEY1234567890abcdef\n"
        "AWS_SESSION_TOKEN=FAKE_SESSION_TOKEN_DO_NOT_USE_123456789\n"
        "\n"
        "Traceback (most recent call last):\n"
        '  File "/app/services/s3_upload.py", line 142, in upload_batch\n'
        "    s3_client.put_object(Bucket=bucket, Key=key, Body=data)\n"
        "botocore.exceptions.ClientError: An error occurred (AccessDenied)\n"
        "Message: User is not authorized to perform s3:PutObject\n"
        "RequestId: 7FAKE123456789ABC\n"
    )


def databricks_oauth_debug_log(*, client_secret: str | None = None) -> str:
    secret = client_secret or "dose-not-a-real-databricks-oauth-secret"
    return (
        "The bundle itself is valid. Deployment stopped when the workspace rejected "
        "the service principal at the OAuth token request.\n"
        "DATABRICKS_AUTH_TYPE=oauth-m2m\n"
        "DATABRICKS_CLIENT_ID=00000000-1111-2222-3333-444444444444\n"
        f"DEBUG databricks-auth DATABRICKS_CLIENT_SECRET={secret}\n"
        "HTTP 401 invalid_client against https://dbc-prod-workspace.cloud.databricks.com\n"
    )
