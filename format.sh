#!/usr/bin/env bash
# Run clang-format on all project source files (excluding vendored extern/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

DIRS=(
    "$ROOT/src"
    "$ROOT/tests"
    "$ROOT/demos"
    "$ROOT/clv-base/Core"
    "$ROOT/clv-base/NetCore"
    "$ROOT/clv-base/SslHelp"
)

# Collect all C/C++ source and header files
FILES=()
for dir in "${DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        while IFS= read -r -d '' f; do
            FILES+=("$f")
        done < <(find "$dir" -type f \( -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) -print0)
    else
        echo "Warning: directory $dir does not exist, skipping" >&2
    fi
done

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "No source files found."
    exit 0
fi

echo "Formatting ${#FILES[@]} files..."

if [[ "${1:-}" == "--check" ]]; then
    clang-format --dry-run --Werror "${FILES[@]}"
    echo "All files are correctly formatted."
else
    clang-format -i "${FILES[@]}"
    echo "Done."
fi
