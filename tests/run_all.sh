#!/usr/bin/env bash
# Top-level test runner. Executes every test_*.sh next to it and reports
# a combined pass/fail. Exits non-zero if any suite fails.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=''; GREEN=''; RED=''; RESET=''
fi

total_suites=0
passed_suites=0
failed_suites=0
failures=()

for suite in "$HERE"/test_*.sh; do
    [[ -f "$suite" ]] || continue
    name="$(basename "$suite" .sh)"
    total_suites=$((total_suites + 1))

    printf '\n%s═══ %s ═══%s\n' "$BOLD" "$name" "$RESET"

    if bash "$suite"; then
        passed_suites=$((passed_suites + 1))
    else
        failed_suites=$((failed_suites + 1))
        failures+=("$name")
    fi
done

printf '\n%s════════════════════════════════════════════════%s\n' "$BOLD" "$RESET"
printf 'Suites: %d total · %s%d passed%s · %s%d failed%s\n' \
    "$total_suites" \
    "$GREEN" "$passed_suites" "$RESET" \
    "$RED"   "$failed_suites" "$RESET"

if (( failed_suites > 0 )); then
    printf '%sFailed suites:%s\n' "$RED" "$RESET"
    for f in "${failures[@]}"; do
        printf '  - %s\n' "$f"
    done
    exit 1
fi

exit 0
