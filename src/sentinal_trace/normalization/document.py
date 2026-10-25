from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from sentinal_trace.config.settings import AppSettings
from sentinal_trace.models.findings import ScanLimits


class NormalizedDocument(BaseModel):
    text: str
    path: str | None = None
    content_type: str = "text"
    limits: ScanLimits = Field(default_factory=ScanLimits)


_TEXT_SUFFIXES = {
    ".txt",
    ".md",
    ".py",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".log",
    ".xml",
    ".tf",
    ".sh",
    ".ps1",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".cs",
}


def infer_content_type(path: Path | None, text: str) -> str:
    if path is None:
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        return "text"
    suffix = path.suffix.lower()
    if path.name.startswith(".env") or suffix == ".env":
        return "env"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    if suffix in _TEXT_SUFFIXES:
        return "code" if suffix not in {".txt", ".md", ".log"} else "text"
    return "text"


def normalize_text(text: str, *, path: str | None = None, settings: AppSettings | None = None) -> NormalizedDocument:
    settings = settings or AppSettings()
    raw = text.replace("\r\n", "\n").replace("\r", "\n")
    encoded = raw.encode("utf-8", errors="replace")
    truncated = False
    if len(encoded) > settings.max_input_bytes:
        truncated = True
        raw = encoded[: settings.max_input_bytes].decode("utf-8", errors="replace")
    p = Path(path) if path else None
    return NormalizedDocument(
        text=raw,
        path=path,
        content_type=infer_content_type(p, raw),
        limits=ScanLimits(
            truncated=truncated,
            bytes_scanned=min(len(encoded), settings.max_input_bytes),
            max_bytes=settings.max_input_bytes,
        ),
    )


def normalize_file(path: Path, *, settings: AppSettings | None = None) -> NormalizedDocument:
    settings = settings or AppSettings()
    errors: list[str] = []
    try:
        data = path.read_bytes()
    except OSError as exc:
        errors.append(f"unreadable: {type(exc).__name__}")
        return NormalizedDocument(
            text="",
            path=str(path),
            limits=ScanLimits(errors=errors, max_bytes=settings.max_file_bytes),
        )
    truncated = False
    if len(data) > settings.max_file_bytes:
        truncated = True
        data = data[: settings.max_file_bytes]
    text = data.decode("utf-8", errors="replace")
    doc = normalize_text(text, path=str(path), settings=settings)
    doc.limits.truncated = truncated or doc.limits.truncated
    doc.limits.errors = errors
    return doc
