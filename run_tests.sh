#!/usr/bin/env bash
# Build-and-test script that writes results to files for easy polling.
#
# Usage: ./run_tests.sh [ctest-args...]
#   ./run_tests.sh                      # unit tests only (default)
#   ./run_tests.sh -R ConfigExchange    # run only matching tests
#   ./run_tests.sh --all                # include integration tests
#
# Output files (in build/):
#   test_log.txt     – full ctest output
#   test_summary.txt – compact parseable summary (appears when done)
#
# Workflow: run in background, poll for test_summary.txt, then cat it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
LOG="$BUILD_DIR/test_log.txt"
SUMMARY="$BUILD_DIR/test_summary.txt"

# Clean previous results so presence of summary == "this run is done"
rm -f "$LOG" "$SUMMARY"

# ── Parse args ─────────────────────────────────────────────────────────
EXCLUDE_INTEGRATION=true
PASSTHROUGH_ARGS=()
for arg in "$@"; do
    if [[ "$arg" == "--all" ]]; then
        EXCLUDE_INTEGRATION=false
    else
        PASSTHROUGH_ARGS+=("$arg")
    fi
done

HAS_FILTER=false
for arg in "${PASSTHROUGH_ARGS[@]+"${PASSTHROUGH_ARGS[@]}"}"; do
    if [[ "$arg" == "-E" || "$arg" == "-R" ]]; then HAS_FILTER=true; fi
done
if $EXCLUDE_INTEGRATION && ! $HAS_FILTER; then
    PASSTHROUGH_ARGS+=(-E 'integration_')
fi

# ── Build ──────────────────────────────────────────────────────────────
echo "=== BUILD ===" | tee "$LOG"
if ! ninja -C "$BUILD_DIR" -j"$(nproc)" >> "$LOG" 2>&1; then
    {
        echo "RESULT: BUILD_FAILED"
        echo "See $LOG for details."
    } | tee "$SUMMARY"
    exit 1
fi
echo "" >> "$LOG"

# ── Test ───────────────────────────────────────────────────────────────
echo "=== TEST ===" >> "$LOG"
cd "$BUILD_DIR"
ctest --output-on-failure --no-compress-output \
    "${PASSTHROUGH_ARGS[@]+"${PASSTHROUGH_ARGS[@]}"}" >> "$LOG" 2>&1 || true

# ── Parse & write summary ─────────────────────────────────────────────
{
    SUMMARY_LINE=$(grep -P 'tests? passed.*tests? failed out of' "$LOG" || true)

    if [[ -n "$SUMMARY_LINE" ]]; then
        FAIL_COUNT=$(echo "$SUMMARY_LINE" | grep -oP '\d+(?= tests? failed)')
        TOTAL=$(echo "$SUMMARY_LINE" | grep -oP '(?<=out of )\d+')
        PASSED=$((TOTAL - FAIL_COUNT))
    else
        PASSED=0; FAIL_COUNT=0; TOTAL=0
    fi

    SKIPPED=$(grep -cP '\(Skipped\)' "$LOG" || true)

    FAILED_NAMES=$(sed -n '/^The following tests FAILED:/,$ p' "$LOG" \
        | grep -oP '(?<=- )\S+(?= \()') || true

    echo "TOTAL=$TOTAL  PASSED=$PASSED  FAILED=$FAIL_COUNT  SKIPPED=$SKIPPED"

    if [[ -n "$FAILED_NAMES" ]]; then
        echo "FAILED_TESTS:"
        echo "$FAILED_NAMES" | while read -r name; do echo "  - $name"; done

        # Include the first 40 lines of each failure's output
        echo ""
        for name in $FAILED_NAMES; do
            echo "--- $name ---"
            # ctest groups failure output between "Start test" and next "Start"
            sed -n "/Test.*: $name/,/^[[:space:]]*Start /{ /^[[:space:]]*Start.*: [^$]/!p; }" "$LOG" \
                | head -40
            echo ""
        done

        echo "RESULT: TESTS_FAILED"
    else
        echo "RESULT: ALL_PASSED"
    fi
} > "$SUMMARY"

cat "$SUMMARY"
grep -q 'RESULT: ALL_PASSED' "$SUMMARY"
