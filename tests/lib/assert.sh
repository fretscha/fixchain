# Minimal assertion helpers for the test suite.
# Source this from each test_*.sh. Counters are file-local.

T_RUN=0
T_PASS=0
T_FAIL=0

if [[ -t 1 ]]; then
    A_GREEN=$'\033[32m'; A_RED=$'\033[31m'; A_DIM=$'\033[2m'
    A_BOLD=$'\033[1m';  A_RESET=$'\033[0m'
else
    A_GREEN=''; A_RED=''; A_DIM=''; A_BOLD=''; A_RESET=''
fi

# ──────────────────────────────────────────────────────────────────────────────
# Internal: record one pass / one fail.
# ──────────────────────────────────────────────────────────────────────────────

_t_pass() {
    T_RUN=$((T_RUN + 1)); T_PASS=$((T_PASS + 1))
    printf '  %s✓%s %s\n' "$A_GREEN" "$A_RESET" "$1"
}

_t_fail() {
    T_RUN=$((T_RUN + 1)); T_FAIL=$((T_FAIL + 1))
    printf '  %s✗%s %s\n' "$A_RED" "$A_RESET" "$1"
    [[ -n "${2:-}" ]] && printf '    %s%s%s\n' "$A_DIM" "$2" "$A_RESET"
}

# ──────────────────────────────────────────────────────────────────────────────
# Public assertions.
# ──────────────────────────────────────────────────────────────────────────────

assert_eq() {
    if [[ "$1" == "$2" ]]; then
        _t_pass "$3"
    else
        _t_fail "$3" "expected: '$1' | actual: '$2'"
    fi
}

assert_contains() {
    if [[ "$1" == *"$2"* ]]; then
        _t_pass "$3"
    else
        _t_fail "$3" "did not contain: '$2'"
    fi
}

assert_not_contains() {
    if [[ "$1" != *"$2"* ]]; then
        _t_pass "$3"
    else
        _t_fail "$3" "unexpectedly contained: '$2'"
    fi
}

assert_file_exists() {
    if [[ -f "$1" ]]; then
        _t_pass "$2"
    else
        _t_fail "$2" "file not found: $1"
    fi
}

assert_exit() {
    if [[ "$1" == "$2" ]]; then
        _t_pass "$3"
    else
        _t_fail "$3" "expected exit $1, got $2"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Test grouping & summary.
# ──────────────────────────────────────────────────────────────────────────────

describe() { printf '\n%s%s%s\n' "$A_BOLD" "$1" "$A_RESET"; }

t_summary() {
    printf '\n  %d run · %s%d passed%s · %s%d failed%s\n' \
        "$T_RUN" \
        "$A_GREEN" "$T_PASS" "$A_RESET" \
        "$A_RED"   "$T_FAIL" "$A_RESET"
    [[ $T_FAIL -eq 0 ]]
}
