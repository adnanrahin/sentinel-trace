from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinal_trace.policy.engine import PolicyConfig, load_policy


def test_invalid_policy_fails_safely(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: '1'\ndefault_action: not-a-real-action\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_policy(path)


def test_default_policy_parses() -> None:
    policy = load_policy(None)
    assert isinstance(policy, PolicyConfig)
    assert policy.version == "1"
