#!/usr/bin/env bash
# Fail if any tracked *.rs file is missing the SPDX-License-Identifier header.
# Run from the repo root.
set -euo pipefail

EXPECTED='// SPDX-License-Identifier: MIT'
missing=()

while IFS= read -r f; do
    # Header may sit on line 1 or 2 (some files lead with a shebang-style allow attr).
    if ! head -n 5 "$f" | grep -qF "$EXPECTED"; then
        missing+=("$f")
    fi
done < <(git ls-files '*.rs')

if [ ${#missing[@]} -ne 0 ]; then
    echo "error: the following .rs files are missing '$EXPECTED' in their first 5 lines:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    exit 1
fi

echo "SPDX header present on all $(git ls-files '*.rs' | wc -l | tr -d ' ') tracked .rs files."
