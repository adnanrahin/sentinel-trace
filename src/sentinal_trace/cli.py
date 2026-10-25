from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from sentinal_trace import __version__
from sentinal_trace.adapters.base import ADAPTERS
from sentinal_trace.adapters.git_hook import install_pre_commit_hook
from sentinal_trace.config.settings import AppSettings
from sentinal_trace.enforcement.preflight import preflight
from sentinal_trace.enforcement.redact import redact_matches
from sentinal_trace.models.enums import PolicyAction
from sentinal_trace.models.findings import ScanResult
from sentinal_trace.pipeline import ScanSession, scan_path, scan_text

app = typer.Typer(name="sentinal-trace", no_args_is_help=True, add_completion=False)
scan_app = typer.Typer(help="Scan text, files, or stdin.")
app.add_typer(scan_app, name="scan")


def _session() -> ScanSession:
    return ScanSession(AppSettings())


def _exit_for_action(action: PolicyAction | None, finding_count: int) -> int:
    if action in {PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL}:
        return 2
    if action in {PolicyAction.WARN, PolicyAction.REDACT} or finding_count:
        return 1
    return 0


def _emit(result: ScanResult, fmt: str) -> None:
    if fmt == "json":
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        return
    if not result.findings:
        typer.echo("No findings.")
        return
    for finding in result.findings:
        loc = finding.location.line_start or "-"
        typer.echo(
            f"{finding.severity} {finding.confidence} {finding.category}/{finding.subtype} "
            f"line={loc} {finding.sanitized_evidence}"
        )
        typer.echo(f"  rule={finding.rule_id} action={result.policy_action} {finding.remediation}")


@app.callback()
def _root() -> None:
    """Local-first exposure prevention for developer and AI workflows."""


@app.command()
def version() -> None:
    typer.echo(__version__)


@scan_app.command("text")
def scan_text_cmd(
    value: str = typer.Argument(..., help="Text to scan. Use '-' to read stdin."),
    format: str = typer.Option("text", "--format", help="text or json"),
) -> None:
    payload = sys.stdin.read() if value == "-" else value
    session = _session()
    result = scan_text(payload, adapter="cli", session=session)
    session.record(result, result.policy_action or PolicyAction.ALLOW)
    _emit(result, format)
    raise typer.Exit(_exit_for_action(result.policy_action, len(result.findings)))


@scan_app.command("path")
def scan_path_cmd(
    path: Path = typer.Argument(..., exists=True),
    format: str = typer.Option("text", "--format"),
) -> None:
    session = _session()
    result = scan_path(path, adapter="cli", session=session)
    session.record(result, result.policy_action or PolicyAction.ALLOW)
    _emit(result, format)
    raise typer.Exit(_exit_for_action(result.policy_action, len(result.findings)))


@app.command("preflight")
def preflight_cmd(
    text: str | None = typer.Option(None, "--text"),
    file: Path | None = typer.Option(None, "--file"),
    adapter: str = typer.Option("cli", "--adapter"),
    format: str = typer.Option("json", "--format"),
    approved: bool = typer.Option(False, "--approve"),
) -> None:
    """Decide whether content may be sent. Exit 2 means blocked (no payload)."""
    if file is not None:
        content = file.read_text(encoding="utf-8", errors="replace")
        source = str(file)
    elif text is not None:
        content = text
        source = "<input>"
    else:
        content = sys.stdin.read()
        source = "<stdin>"
    decision = preflight(content, source=source, adapter=adapter, approved=approved)
    body: dict[str, Any] = decision.model_dump(mode="json")
    if format == "json":
        typer.echo(json.dumps(body, indent=2))
    else:
        typer.echo(f"{decision.verdict} allowed={decision.allowed} {decision.reason}")
    raise typer.Exit(_exit_for_action(decision.verdict, len(decision.findings)))


@app.command("redact")
def redact_cmd(
    text: str | None = typer.Option(None, "--text"),
    file: Path | None = typer.Option(None, "--file"),
) -> None:
    session = _session()
    content = file.read_text(encoding="utf-8") if file else (text or sys.stdin.read())
    _, matches, document = scan_text(content, adapter="cli", session=session, raw=True)
    typer.echo(redact_matches(document.text, matches))


@app.command("incidents")
def incidents_cmd(limit: int = typer.Option(20, "--limit")) -> None:
    session = _session()
    typer.echo(json.dumps(session.store.recent(limit), indent=2))


@app.command("config")
def config_cmd() -> None:
    settings = AppSettings()
    typer.echo(
        json.dumps(
            {
                "home": str(settings.home),
                "db": str(settings.db_path),
                "policy": str(settings.policy_path),
                "max_input_bytes": settings.max_input_bytes,
                "retention_days": settings.retention_days,
            },
            indent=2,
        )
    )


@app.command("doctor")
def doctor_cmd() -> None:
    from sentinal_trace.status import protection_status

    settings = AppSettings()
    settings.home.mkdir(parents=True, exist_ok=True)
    session = ScanSession(settings)
    status = protection_status()
    typer.echo(
        json.dumps(
            {
                "ok": True,
                "home": str(settings.home),
                "db": settings.db_path.exists(),
                "policy_version": session.policy.version,
                **status,
            },
            indent=2,
        )
    )


@app.command("status")
def status_cmd() -> None:
    """Whether automatic Cursor protection is actually on, and what it can block."""
    from sentinal_trace.status import protection_status

    typer.echo(json.dumps(protection_status(), indent=2))


@app.command("capabilities")
def capabilities_cmd() -> None:
    rows = [
        {
            "adapter": a.name,
            "capabilities": sorted(c.value for c in a.capabilities),
            "enforcement": a.enforcement,
            "notes": a.notes,
        }
        for a in ADAPTERS
    ]
    typer.echo(json.dumps(rows, indent=2))


@app.command("mcp")
def mcp_cmd() -> None:
    from sentinal_trace.mcp.server import run_stdio_server

    run_stdio_server()


@app.command("hook")
def hook_cmd() -> None:
    """Cursor beforeSubmitPrompt entrypoint. Cursor runs this; people do not."""
    from sentinal_trace.adapters.cursor_hook import main as hook_main

    hook_main()


@app.command("install")
def install_cmd() -> None:
    """Register Cursor Send intercept + MCP so every local chat is scanned. Restart Cursor after."""
    from sentinal_trace.install import install_user

    paths = install_user()
    typer.echo(
        json.dumps(
            {
                "installed": paths,
                "next": "Restart Cursor. Engineers do not set Gmail; the hook reads the team notify file if present.",
            },
            indent=2,
        )
    )


@app.command("sample-paste")
def sample_paste_cmd() -> None:
    """Print a synthetic payment log to paste into Cursor. Not a live credential."""
    from sentinal_trace.samples import payment_failure_log

    typer.echo(payment_failure_log())


@app.command("notify-test")
def notify_test_cmd() -> None:
    """Send a sanitized test alert using webhook/email env vars. Contains no secret."""
    from sentinal_trace.notifications.providers import (
        NotificationError,
        notifiers_from_env,
        notify_env_visibility,
        notify_identity,
        sanitize_incident_payload,
        save_notify_env,
    )

    notifiers = notifiers_from_env()
    if not notifiers:
        typer.echo(
            json.dumps(
                {
                    "sent": False,
                    "reason": (
                        "Set SENTINAL_TRACE_SMTP_URL + SENTINAL_TRACE_ALERT_EMAIL, "
                        "or SENTINAL_TRACE_WEBHOOK_URL. Git Bash: export in this window, "
                        "or put KEY=value lines in ~/.sentinal-trace/notify.env."
                    ),
                    "visible": notify_env_visibility(),
                },
                indent=2,
            )
        )
        raise typer.Exit(1)
    payload = sanitize_incident_payload(
        incident_id="notify-test",
        action="notify-test",
        category="credential",
        severity="SEV-0",
        adapter="notify-test",
        names=["NOTIFY_TEST"],
        source="<notify-test>",
    )
    errors: dict[str, str] = {}
    for name, notifier in notifiers.items():
        try:
            notifier.send(payload)
        except Exception as exc:
            if isinstance(exc, NotificationError):
                errors[name] = str(exc)
            else:
                cause = exc.__cause__ or exc
                errors[name] = type(cause).__name__
    replayed = 0
    saved: list[str] = []
    if not errors:
        from sentinal_trace.audit.store import AuditStore
        from sentinal_trace.notifications.dispatcher import drain_outbox

        store = AuditStore(AppSettings().db_path)
        before = len(store.pending_notifications())
        drain_outbox(store, notifiers)
        replayed = max(0, before - len(store.pending_notifications()))
        saved = save_notify_env()
    typer.echo(
        json.dumps(
            {
                "sent": not errors,
                "providers": sorted(notifiers),
                "errors": errors,
                "replayed_outbox": replayed,
                "saved_for_cursor": saved,
                "identity": notify_identity(),
                "note": "Alert has no prompt and no secret. Cursor reads Windows user env, not Git Bash export.",
            },
            indent=2,
        )
    )
    if errors:
        raise typer.Exit(1)


@app.command("notify-save")
def notify_save_cmd() -> None:
    """Copy Git Bash/process notify env into ~/.sentinal-trace/notify.env for Cursor."""
    from sentinal_trace.notifications.providers import notify_env_path, save_notify_env

    saved = save_notify_env()
    typer.echo(
        json.dumps(
            {
                "saved": saved,
                "path": str(notify_env_path()),
                "next": "Paste a log in Cursor. Git Bash export is not visible to Cursor.",
            },
            indent=2,
        )
    )
    if not saved:
        raise typer.Exit(1)


@app.command("uninstall")
def uninstall_cmd() -> None:
    """Remove the Cursor Send hook. Status will report protection OFF."""
    from sentinal_trace.status import protection_status, uninstall_cursor_hooks

    uninstall_cursor_hooks()
    typer.echo(json.dumps(protection_status(), indent=2))


@app.command("install-hook")
def install_hook_cmd(repo: Path = typer.Option(Path("."), "--repo")) -> None:
    path = install_pre_commit_hook(repo.resolve())
    typer.echo(f"installed {path}")


@app.command("policy")
def policy_cmd() -> None:
    session = _session()
    typer.echo(session.policy.model_dump_json(indent=2))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
