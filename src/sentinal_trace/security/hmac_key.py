from __future__ import annotations

import os
from pathlib import Path

from sentinal_trace.security.paths import PathSecurityError


def load_or_create_hmac_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = path.read_bytes()
        if len(key) < 32:
            raise PathSecurityError("HMAC key file is too short")
        return key
    key = os.urandom(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key
