# Getting started

1. Install (dev checkout):

   ```bash
   python -m pip install -e ".[dev]"
   sentinal-trace version
   ```

2. Scan the synthetic demo:

   ```bash
   sentinal-trace scan path examples/demo-synthetic.txt --format json
   ```

3. Preflight (this is the enforcement API):

   ```bash
   sentinal-trace preflight --text "hello"
   echo %ERRORLEVEL%
   ```

4. Optional git hook:

   ```bash
   sentinal-trace install-hook
   ```

5. Optional MCP: see [MCP.md](MCP.md).
