from __future__ import annotations

from pathlib import Path

HOOK_BODY = """#!/usr/bin/env sh
# sentinal-trace pre-commit hook — abort the commit when policy blocks.
# Installed by: sentinal-trace install-hook
set -e
if command -v sentinal-trace >/dev/null 2>&1; then
  CMD="sentinal-trace"
else
  CMD="python -m sentinal_trace"
fi
files="$(git diff --cached --name-only --diff-filter=ACM)"
if [ -z "$files" ]; then
  exit 0
fi
status=0
for f in $files; do
  $CMD preflight --file "$f" --adapter git_pre_commit || status=$?
  if [ "$status" -ge 2 ]; then
    echo "sentinal-trace blocked commit due to $f" >&2
    exit 2
  fi
done
exit 0
"""


def install_pre_commit_hook(repo: Path) -> Path:
    git_dir = repo / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError("not a git repository")
    hook = git_dir / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK_BODY, encoding="utf-8")
    hook.chmod(hook.stat().st_mode | 0o111)
    return hook
