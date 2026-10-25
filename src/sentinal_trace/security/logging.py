from __future__ import annotations

import logging
from typing import Any

from sentinal_trace.security.sanitize import scrub_for_log


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub_for_log(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _scrub_arg(v) for k, v in record.args.items()}
            else:
                record.args = tuple(_scrub_arg(a) for a in record.args)
        return True


def _scrub_arg(value: Any) -> Any:
    return scrub_for_log(value) if isinstance(value, str) else value


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
