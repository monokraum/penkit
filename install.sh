#!/usr/bin/env bash
# Installs penkit on the machine, the first time (or after moving the repository):
#   1. the command ~/.local/bin/penkit → <penkit repository>/bin/penkit (the link follows the repository: git pull is enough);
#   2. the tools, with penkit install (afterwards, that is the command to run again for the tools).
# Safe to run again. --fix is passed on to penkit install.
set -euo pipefail
repo="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
bin="$HOME/.local/bin"
link="$bin/penkit"
target="$repo/bin/penkit"

python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null \
  || { echo "✘ Python 3.11 or newer required (python3)" >&2; exit 1; }
if [ -e "$link" ] && [ ! -L "$link" ]; then
  echo "✘ $link exists and is not a link: nothing changed" >&2; exit 1
fi
mkdir -p "$bin"
ln -sfn "$target" "$link"
echo "✔ command: $link → $target"
echo

rc=0
python3 "$repo/scripts/penkit.py" install "$@" || rc=$?

found="$(command -v penkit || true)"
if [ -z "$found" ]; then
  echo "! $bin is not in the PATH: add it (for example in ~/.bashrc), then open a new terminal" >&2; rc=1
elif [ "$(readlink -f "$found")" != "$(readlink -f "$target")" ]; then
  echo "! \"penkit\" resolves to $found, which comes before $link in the PATH" >&2; rc=1
fi
[ "$rc" -eq 0 ] && echo "Next, in each project to audit: penkit init"
exit "$rc"
