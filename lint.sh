#!/usr/bin/env bash
# AST lint for project style rules that clang-tidy has no check for.
#
# Usage: ./lint.sh [--strict] [FILE...]
#   ./lint.sh                          # scan src/, tests/, demos/
#   ./lint.sh src/nft_subnet_target.cpp   # restrict findings to these files
#   ./lint.sh --strict                 # exit 1 when findings exist
#
# Report-only by default: findings are printed but the exit status stays 0 so
# this can be wired into review tooling without blocking anything.
#
# Requires clang-query and a compile database (BUILD_DIR, default build/).
# Both missing tooling and an absent database are a soft skip unless --strict.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

# clv-base is a submodule with its own review; findings there are not actionable here.
SCOPE_DIRS=(src tests demos)

STRICT=false
FILTER=()
for arg in "$@"; do
    case "$arg" in
        --strict) STRICT=true ;;
        -h|--help) sed -n '2,13p' "$0" | cut -c3-; exit 0 ;;
        *) FILTER+=("$(realpath --relative-to="$ROOT" "$arg" 2>/dev/null || echo "$arg")") ;;
    esac
done

soft_exit() {
    echo "lint: $1" >&2
    $STRICT && exit 1
    exit 0
}

CLANG_QUERY="$(command -v clang-query || true)"
if [[ -z "$CLANG_QUERY" ]]; then
    # Distros ship only versioned binaries; take the highest available.
    CLANG_QUERY="$(compgen -c 'clang-query-' 2>/dev/null | sort -t- -k3 -n -u | tail -1 || true)"
    CLANG_QUERY="$(command -v "$CLANG_QUERY" 2>/dev/null || true)"
fi
[[ -n "$CLANG_QUERY" ]] || soft_exit "clang-query not found, skipping (install clang-tools)"
[[ -f "$BUILD_DIR/compile_commands.json" ]] || soft_exit "no compile database at $BUILD_DIR, skipping"

# ── Checks ─────────────────────────────────────────────────────────────
# Each entry: <id>|<matcher>|<message>
#
# declaration-as-condition: `if (auto x = f())` reads as an accident; the
# init-statement form makes the tested expression explicit. Note that
# hasConditionVariableStatement is IfStmt-only, hence the separate whileStmt
# arm -- a declStmt parented by a while is always its condition variable
# because C++ has no while-init-statement. switch is deliberately omitted:
# its init-statement and condition variable are indistinguishable this way.
CHECKS=(
    'declaration-as-condition|stmt(anyOf(ifStmt(hasConditionVariableStatement(declStmt())), declStmt(hasParent(whileStmt()))))|declare in an init-statement with an explicit condition: if (auto x = f(); x)'
)

# ── Translation units ──────────────────────────────────────────────────
mapfile -t TUS < <(python3 - "$BUILD_DIR/compile_commands.json" "$ROOT" "${SCOPE_DIRS[@]}" <<'PY'
import json, os, sys
db, root, *dirs = sys.argv[1:]
prefixes = tuple(os.path.join(root, d) + os.sep for d in dirs)
seen = set()
for entry in json.load(open(db)):
    path = os.path.normpath(os.path.join(entry["directory"], entry["file"]))
    if path.startswith(prefixes) and path not in seen:
        seen.add(path)
        print(path)
PY
)
[[ ${#TUS[@]} -gt 0 ]] || soft_exit "no translation units in scope"

# Analysing only the named files is sound when they are all TUs; a header can be
# reported from any TU that includes it, so fall back to the full scan.
if [[ ${#FILTER[@]} -gt 0 ]]; then
    SUBSET=()
    for want in "${FILTER[@]}"; do
        for tu in "${TUS[@]}"; do
            [[ "$tu" == "$ROOT/$want" ]] && SUBSET+=("$tu")
        done
    done
    [[ ${#SUBSET[@]} -eq ${#FILTER[@]} ]] && TUS=("${SUBSET[@]}")
fi

RAW="$(mktemp)"
trap 'rm -f "$RAW"' EXIT

findings=0
for check in "${CHECKS[@]}"; do
    IFS='|' read -r id matcher message <<<"$check"

    printf '%s\n' "${TUS[@]}" |
        MATCHER="$matcher" CLANG_QUERY="$CLANG_QUERY" BUILD_DIR="$BUILD_DIR" \
        xargs -P "$JOBS" -I{} bash -c \
            '"$CLANG_QUERY" -p "$BUILD_DIR" -c "set output diag" -c "match $MATCHER" "$1" 2>/dev/null || true' \
            _ {} >"$RAW"

    mapfile -t hits < <(
        grep -oE '^[^ ]+:[0-9]+:[0-9]+: note: "root" binds here' "$RAW" |
            sed 's/: note.*//' |
            while IFS= read -r loc; do
                file="${loc%%:*}"
                rel="$(realpath --relative-to="$ROOT" "$file" 2>/dev/null || echo "$file")"
                case "$rel" in ../*|/*) continue ;; esac
                for d in "${SCOPE_DIRS[@]}"; do
                    [[ "$rel" == "$d/"* ]] && echo "$rel:${loc#*:}" && break
                done
            done | sort -u -t: -k1,1 -k2,2n
    )

    for hit in "${hits[@]}"; do
        rel="${hit%%:*}"
        rest="${hit#*:}"
        line="${rest%%:*}"
        if [[ ${#FILTER[@]} -gt 0 ]]; then
            printf '%s\n' "${FILTER[@]}" | grep -qxF "$rel" || continue
        fi
        src="$(sed -n "${line}p" "$ROOT/$rel")"
        # gtest's EXPECT_*/ASSERT_* expand to condition-variable ifs, and the
        # expansion is attributed to the call site. The AST match is genuine but
        # the source line is not ours to change, so require a visible if/while.
        [[ "$src" =~ (if|while)[[:space:]]*\( ]] || continue
        printf '%s: %s\n' "$hit" "$id"
        printf '    %s\n' "${src#"${src%%[![:space:]]*}"}"
        printf '    -> %s\n\n' "$message"
        findings=$((findings + 1))
    done
done

tu_count="${#TUS[@]} translation unit"; [[ ${#TUS[@]} -eq 1 ]] || tu_count+="s"

if [[ $findings -eq 0 ]]; then
    echo "lint: clean ($tu_count)"
    exit 0
fi

echo "lint: $findings finding(s) across $tu_count"
$STRICT && exit 1
exit 0
