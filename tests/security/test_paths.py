from __future__ import annotations

from pathlib import Path

import pytest

from sentinal_trace.pipeline import scan_path
from sentinal_trace.security.paths import PathSecurityError


def test_symlink_escape_not_followed(session, tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    target = secret_dir / "leak.env"
    target.write_text("password=synthetic-not-used-outside", encoding="utf-8")
    link = root / "link"
    try:
        link.symlink_to(secret_dir, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted")
    result = scan_path(root, root=root, session=session)
    assert all("leak.env" not in (f.location.path or "") for f in result.findings)


def test_directory_scan_stays_in_root(session, tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "ok.txt").write_text("hello", encoding="utf-8")
    scan_path(root, root=root, session=session)
    with pytest.raises(PathSecurityError):
        scan_path(tmp_path, root=root, session=session)
