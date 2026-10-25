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
    settings = AppSettings()
    settings.home.mkdir(parents=True, exist_ok=True)
    session = ScanSession(settings)
    typer.echo(f"ok home={settings.home} db={settings.db_path.exists()} policy_version={session.policy.version}")


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
