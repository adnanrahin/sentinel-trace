from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


def default_home() -> Path:
    override = os.environ.get("SENTINAL_TRACE_HOME")
    if override:
        return Path(override)
    return Path.home() / ".sentinal-trace"


class AppSettings(BaseModel):
    home: Path = Field(default_factory=default_home)
    max_input_bytes: int = 1_048_576
    max_file_bytes: int = 1_048_576
    retention_days: int = 90
    follow_symlinks: bool = False

    @property
    def db_path(self) -> Path:
        return self.home / "audit.db"

    @property
    def hmac_key_path(self) -> Path:
        return self.home / "hmac.key"

    @property
    def policy_path(self) -> Path:
        env = os.environ.get("SENTINAL_TRACE_POLICY")
        if env:
            return Path(env)
        local = Path.cwd() / ".sentinal-trace.yaml"
        if local.exists():
            return local
        return self.home / "policy.yaml"
