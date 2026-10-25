# Contributing

```bash
python -m pip install -e ".[dev]"
python -m pytest
ruff check src tests && ruff format src tests
mypy --config-file pyproject.toml
```

Do not add real credentials to fixtures. Use the `SYNTHETIC_` / `FAKE` / `example` markers already in `tests/fixtures` and `examples/demo-synthetic.txt`.

Do not add a generic shell-exec MCP tool.

Releases: merge to `main`. The Release workflow tags and publishes the wheel.
