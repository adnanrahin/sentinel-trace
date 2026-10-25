# Getting started

1. Install the package, then register Cursor so **every Send is scanned** (one command, then restart Cursor):

   ```bash
   python -m pip install -e ".[dev]"
   sentinal-trace install
   sentinal-trace doctor
   ```

2. Automated tests:

   ```bash
   python -m pytest
   ```

3. Optional: scan a file from the CLI (not required for chat):

   ```bash
   sentinal-trace scan path examples/demo-synthetic.txt --format json
   ```

4. Optional git pre-commit:

   ```bash
   sentinal-trace install-hook
   ```
