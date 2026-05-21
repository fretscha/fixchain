#!/usr/bin/env bash
# Tests for fetch_chain.sh
# Spins up a local `openssl s_server` and points fetch_chain.sh at it.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# shellcheck source=tests/lib/assert.sh
source "$HERE/lib/assert.sh"
# shellcheck source=tests/lib/fixtures.sh
source "$HERE/lib/fixtures.sh"

FETCH="$ROOT/fetch_chain.sh"

WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# Use bash's /dev/tcp to probe — portable across macOS / Linux without nc.
wait_for_port() {
    local host="$1" port="$2" tries="${3:-25}"
    for _ in $(seq 1 "$tries"); do
        if (exec 3<>/dev/tcp/"$host"/"$port") 2>/dev/null; then
            exec 3<&- 3>&-
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# ──────────────────────────────────────────────────────────────────────────────

describe "fetch_chain — bad usage"

OUT=$("$FETCH" 2>&1); RC=$?
assert_contains "$OUT" "Usage:" "no args → prints usage"
if [[ "$RC" -ne 0 ]]; then
    _t_pass "exits non-zero"
else
    _t_fail "exits non-zero" "got $RC"
fi

OUT=$("$FETCH" --not-a-real-flag example.com 2>&1); RC=$?
assert_exit       1 "$RC" "unknown flag → exits 1"
assert_contains  "$OUT" "Unknown option" "unknown-flag error printed"

# ──────────────────────────────────────────────────────────────────────────────

describe "fetch_chain — pulls leaf + intermediate from a local openssl s_server"

# Build PKI + an intermediate chain file (intermediates only, sent via -cert_chain).
PKI="$WORK/pki"; mkdir -p "$PKI"
build_basic_pki "$PKI"
cp "$PKI/intermediate.crt" "$WORK/chain.pem"

# Pick a high random port. If unlucky and it's in use, the bind will fail
# fast and we'll see the test fail clearly.
PORT=$((40000 + RANDOM % 20000))

# -naccept 1 → exit after one connection; -quiet → no banner.
openssl s_server \
    -accept "$PORT" \
    -cert  "$PKI/leaf.crt" \
    -key   "$PKI/leaf.key" \
    -cert_chain "$WORK/chain.pem" \
    -quiet </dev/null >/dev/null 2>&1 &
SERVER_PID=$!

if ! wait_for_port 127.0.0.1 "$PORT"; then
    _t_fail "openssl s_server starts and listens" "port $PORT never opened"
    t_summary
    exit 1
fi
_t_pass "openssl s_server starts and listens on $PORT"

OUTPEM="$WORK/fetched.pem"
OUT=$("$FETCH" -q -s test.example -o "$OUTPEM" "127.0.0.1:$PORT" 2>&1); RC=$?

assert_exit       0 "$RC" "fetch_chain exits 0 on successful pull"
assert_file_exists "$OUTPEM" "output PEM is created"

COUNT=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$OUTPEM" 2>/dev/null || echo 0)
assert_eq        "2" "$COUNT" "output contains 2 certs (leaf + intermediate)"

# Subjects are anonymised — confirm we got our test PKI back.
SUBJECTS=$(openssl crl2pkcs7 -nocrl -certfile "$OUTPEM" 2>/dev/null \
            | openssl pkcs7 -print_certs -noout 2>/dev/null \
            | grep -i '^subject=')

assert_contains  "$SUBJECTS" "test.example"             "leaf subject is the example leaf"
assert_contains  "$SUBJECTS" "Example Intermediate CA"  "intermediate subject is the example intermediate"
assert_not_contains "$SUBJECTS" "Example Root CA"       "root NOT served by s_server"

# ──────────────────────────────────────────────────────────────────────────────

describe "fetch_chain — stdout mode"

# Stop the previous server, then launch a fresh one on a new port.
if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
fi
PORT=$((40000 + RANDOM % 20000))
openssl s_server \
    -accept "$PORT" \
    -cert  "$PKI/leaf.crt" \
    -key   "$PKI/leaf.key" \
    -cert_chain "$WORK/chain.pem" \
    -quiet </dev/null >/dev/null 2>&1 &
SERVER_PID=$!

if wait_for_port 127.0.0.1 "$PORT"; then
    _t_pass "second s_server listens on $PORT"
    STDOUT_PEM=$("$FETCH" -q -s test.example -o - "127.0.0.1:$PORT" 2>/dev/null)
    RC=$?
    assert_exit       0 "$RC" "stdout mode exits 0"
    COUNT=$(grep -c -- '-----BEGIN CERTIFICATE-----' <<<"$STDOUT_PEM")
    assert_eq        "2" "$COUNT" "stdout mode prints 2 certs"
else
    _t_fail "second s_server starts" "port $PORT never opened"
fi

# ──────────────────────────────────────────────────────────────────────────────

t_summary
