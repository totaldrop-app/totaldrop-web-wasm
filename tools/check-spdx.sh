#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Every hand-written source file states its copyright and license in its
# top lines. REUSE.toml covers non-source files (JSON, ARB translations,
# lockfiles, Markdown, and CI configuration), so `reuse lint` alone would
# not catch a source file missing inline SPDX headers.
set -eu
cd "$(dirname "$0")/.."
missing=$(git ls-files \
    '*.rs' '*.ts' '*.js' '*.mjs' '*.sh' '*.py' '*.css' |
  # REUSE-IgnoreStart (the patterns below are not this file's tags)
  while IFS= read -r f; do
    head -n 6 "$f" | grep -q 'SPDX-FileCopyrightText:' &&
      head -n 6 "$f" | grep -q 'SPDX-License-Identifier:' ||
      echo "$f"
  done)
# REUSE-IgnoreEnd
if [ -n "$missing" ]; then
  echo "These files have no SPDX lines in their top 6 lines:"
  echo "$missing"
  exit 1
fi
echo "SPDX lines ok"
