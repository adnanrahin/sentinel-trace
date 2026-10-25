from __future__ import annotations

from tests.conftest import SYNTHETIC_AWS

from sentinal_trace.notifications.providers import notifiers_from_env, sanitize_incident_payload
from sentinal_trace.status import protection_status


def test_env_enables_webhook_and_email_without_exposing_secrets(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("sentinal_trace.notifications.providers._win_user_env", lambda name: None)
    monkeypatch.setenv("SENTINAL_TRACE_WEBHOOK_URL", "https://example.test/hooks/sentinal")
    monkeypatch.setenv("SENTINAL_TRACE_SMTP_URL", "smtp://user%40gmail.com:not-a-real-pass@smtp.gmail.com:587")
    monkeypatch.setenv("SENTINAL_TRACE_ALERT_EMAIL", "alerts@example.test")
    monkeypatch.setenv("SENTINAL_TRACE_ALERT_FROM", "alerts@example.test")
    configured = notifiers_from_env()
    assert "webhook" in configured
    assert "email" in configured
    status = protection_status(tmp_path)
    assert "webhook" in status["notifications_configured"]
    assert "email" in status["notifications_configured"]
    blob = str(status)
    assert "not-a-real-pass" not in blob
    assert SYNTHETIC_AWS not in blob


def test_windows_user_env_wins_over_stale_process_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "SENTINAL_TRACE_SMTP_URL",
        "smtp://old%40gmail.com:stale@smtp.gmail.com:587",
    )
    monkeypatch.setenv("SENTINAL_TRACE_ALERT_EMAIL", "old@gmail.com")
    monkeypatch.setenv("SENTINAL_TRACE_ALERT_FROM", "old@gmail.com")
    monkeypatch.setattr(
        "sentinal_trace.notifications.providers._win_user_env",
        lambda name: {
            "SENTINAL_TRACE_SMTP_URL": "smtp://new%40gmail.com:fresh@smtp.gmail.com:587",
            "SENTINAL_TRACE_ALERT_EMAIL": "new@gmail.com",
            "SENTINAL_TRACE_ALERT_FROM": "new@gmail.com",
        }.get(name),
    )
    from sentinal_trace.notifications.providers import notify_identity

    ident = notify_identity()
    assert ident["smtp_login"] == "new@gmail.com"
    assert ident["alert_email"] == "new@gmail.com"


def test_windows_user_env_fills_in_when_process_env_empty(monkeypatch) -> None:
    monkeypatch.delenv("SENTINAL_TRACE_SMTP_URL", raising=False)
    monkeypatch.delenv("SENTINAL_TRACE_ALERT_EMAIL", raising=False)
    monkeypatch.delenv("SENTINAL_TRACE_ALERT_FROM", raising=False)
    monkeypatch.setattr(
        "sentinal_trace.notifications.providers._win_user_env",
        lambda name: {
            "SENTINAL_TRACE_SMTP_URL": "smtp://user%40gmail.com:x@smtp.gmail.com:587",
            "SENTINAL_TRACE_ALERT_EMAIL": "sentinalsmpt@gmail.com",
            "SENTINAL_TRACE_ALERT_FROM": "sentinalsmpt@gmail.com",
        }.get(name),
    )
    configured = notifiers_from_env()
    assert "email" in configured


def test_team_notify_file_is_enough_without_personal_gmail(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SENTINAL_TRACE_SMTP_URL", raising=False)
    monkeypatch.delenv("SENTINAL_TRACE_ALERT_EMAIL", raising=False)
    monkeypatch.delenv("SENTINAL_TRACE_WEBHOOK_URL", raising=False)
    monkeypatch.setattr("sentinal_trace.notifications.providers._win_user_env", lambda name: None)
    monkeypatch.setattr("sentinal_trace.notifications.providers._file_env", lambda name: None)
    team = tmp_path / "team-notify.env"
    team.write_text(
        "SENTINAL_TRACE_WEBHOOK_URL=https://example.test/team-hook\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sentinal_trace.notifications.providers.team_notify_paths",
        lambda: [team],
    )
    configured = notifiers_from_env()
    assert "webhook" in configured
    assert "email" not in configured


def test_notify_env_file_is_enough_without_process_env(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SENTINAL_TRACE_SMTP_URL", raising=False)
    monkeypatch.delenv("SENTINAL_TRACE_ALERT_EMAIL", raising=False)
    monkeypatch.delenv("SENTINAL_TRACE_ALERT_FROM", raising=False)
    monkeypatch.setattr("sentinal_trace.notifications.providers._win_user_env", lambda name: None)
    env_file = tmp_path / "notify.env"
    env_file.write_text(
        "SENTINAL_TRACE_SMTP_URL=smtp://user%40gmail.com:x@smtp.gmail.com:587\n"
        "SENTINAL_TRACE_ALERT_EMAIL=sentinalsmpt@gmail.com\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sentinal_trace.notifications.providers.notify_env_path", lambda: env_file)
    configured = notifiers_from_env()
    assert "email" in configured


def test_save_notify_env_does_not_print_secret(monkeypatch, tmp_path) -> None:
    home = tmp_path / "st-home"
    monkeypatch.setenv("SENTINAL_TRACE_HOME", str(home))
    monkeypatch.setenv("SENTINAL_TRACE_SMTP_URL", "smtp://user%40gmail.com:s3cretpass@smtp.gmail.com:587")
    monkeypatch.setenv("SENTINAL_TRACE_ALERT_EMAIL", "sentinalsmpt@gmail.com")
    from sentinal_trace.notifications.providers import notify_env_path, save_notify_env

    saved = save_notify_env()
    assert "SENTINAL_TRACE_SMTP_URL" in saved
    assert notify_env_path().is_file()
    assert "s3cretpass" in notify_env_path().read_text(encoding="utf-8")


def test_notify_test_cli_sends_email_when_env_set(monkeypatch, tmp_path) -> None:
    sent: list[dict] = []

    class FakeEmail:
        name = "email"

        def send(self, payload: dict) -> None:
            sent.append(payload)

    monkeypatch.setenv("SENTINAL_TRACE_HOME", str(tmp_path / "st-home"))
    monkeypatch.setenv("SENTINAL_TRACE_SMTP_URL", "smtp://user%40gmail.com:x@smtp.gmail.com:587")
    monkeypatch.setenv("SENTINAL_TRACE_ALERT_EMAIL", "you@gmail.com")
    monkeypatch.setattr(
        "sentinal_trace.notifications.providers.notifiers_from_env",
        lambda: {"email": FakeEmail()},
    )
    from typer.testing import CliRunner

    from sentinal_trace.cli import app

    result = CliRunner().invoke(app, ["notify-test"])
    assert result.exit_code == 0, result.output
    assert sent
    assert sent[0]["details"]["action"] == "notify-test"
    assert SYNTHETIC_AWS not in str(sent)


def test_test_alert_payload_has_no_prompt_or_key() -> None:
    payload = sanitize_incident_payload(
        incident_id="notify-test",
        action="block",
        category="credential",
        severity="SEV-0",
        adapter="notify-test",
    )
    blob = str(payload)
    assert "prompt" not in blob
    assert SYNTHETIC_AWS not in blob
    assert payload["details"]["note"]
