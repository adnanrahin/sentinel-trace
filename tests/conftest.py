from __future__ import annotations

from pathlib import Path

import pytest

from sentinal_trace.config.settings import AppSettings
from sentinal_trace.pipeline import ScanSession

# Built at runtime so the repository never contains vendor-shaped key literals
# that GitHub push protection treats as live secrets.
# AWS access key ids are AKIA + exactly 16 alphanumeric characters.
SYNTHETIC_AWS = "".join(("AKI", "A", "0" * 10, "FAKEEX"))
SYNTHETIC_GITHUB = "".join(("gh", "p_", "0" * 36))
SYNTHETIC_STRIPE = "".join(("sk_", "test_", "0" * 24))
assert len(SYNTHETIC_AWS) == 20
assert len(SYNTHETIC_GITHUB) == 40


@pytest.fixture
def session(tmp_path: Path) -> ScanSession:
    settings = AppSettings(home=tmp_path / "home", max_input_bytes=65_536, max_file_bytes=65_536)
    return ScanSession(settings)
