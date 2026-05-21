#!/usr/bin/env bash
# Tests for analyze_chain.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# shellcheck source=tests/lib/assert.sh
source "$HERE/lib/assert.sh"
# shellcheck source=tests/lib/fixtures.sh
source "$HERE/lib/fixtures.sh"

ANALYZE="$ROOT/analyze_chain.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Fixture: a clean two-tier PKI
# ──────────────────────────────────────────────────────────────────────────────

PKI="$WORK/pki"
mkdir -p "$PKI"
build_basic_pki "$PKI"

# ──────────────────────────────────────────────────────────────────────────────

describe "analyze_chain — valid chain (leaf + intermediate, no key)"

CHAIN="$WORK/good.pem"
cat "$PKI/leaf.crt" "$PKI/intermediate.crt" > "$CHAIN"

OUT=$("$ANALYZE" "$CHAIN" 2>&1); RC=$?

assert_exit       0    "$RC"  "exits 0"
assert_contains  "$OUT" "ALL CHECKS PASSED" "summary says ALL CHECKS PASSED"
assert_contains  "$OUT" "LEAF (end-entity)" "leaf classified as LEAF"
assert_contains  "$OUT" "INTERMEDIATE CA"    "intermediate classified as INTERMEDIATE"
assert_not_contains "$OUT" "ROOT CA"         "no ROOT CA reported"
assert_contains  "$OUT" "no root CA found"   "summary confirms no root in chain"

# ──────────────────────────────────────────────────────────────────────────────

describe "analyze_chain — chain that wrongly includes the root"

CHAIN="$WORK/with_root.pem"
cat "$PKI/leaf.crt" "$PKI/intermediate.crt" "$PKI/root.crt" > "$CHAIN"

OUT=$("$ANALYZE" "$CHAIN" 2>&1); RC=$?

assert_exit       2    "$RC"  "exits 2 when root is present"
assert_contains  "$OUT" "ROOT CA"                       "root cert detected"
assert_contains  "$OUT" "root CA must NOT be present"   "root warning printed"
assert_contains  "$OUT" "1 ERROR"                       "error count reported"

# ──────────────────────────────────────────────────────────────────────────────

describe "analyze_chain — embedded private key matching the leaf"

CHAIN="$WORK/with_key.pem"
cat "$PKI/leaf.crt" "$PKI/leaf.key" "$PKI/intermediate.crt" > "$CHAIN"

OUT=$("$ANALYZE" "$CHAIN" 2>&1); RC=$?

assert_exit       0    "$RC"  "exits 0 when key matches"
assert_contains  "$OUT" "private key matches the leaf certificate" "match reported"
assert_contains  "$OUT" "ALL CHECKS PASSED"                        "overall pass"

# ──────────────────────────────────────────────────────────────────────────────

describe "analyze_chain — embedded private key that does NOT match the leaf"

# Generate an unrelated key.
_oq genrsa -out "$WORK/wrong.key" 2048

CHAIN="$WORK/wrong_key.pem"
cat "$PKI/leaf.crt" "$WORK/wrong.key" "$PKI/intermediate.crt" > "$CHAIN"

OUT=$("$ANALYZE" "$CHAIN" 2>&1); RC=$?

assert_exit       2    "$RC"  "exits 2 on key mismatch"
assert_contains  "$OUT" "does NOT match"  "mismatch reported"

# ──────────────────────────────────────────────────────────────────────────────

describe "analyze_chain — encrypted private key in bundle"

encrypt_key "$PKI" leaf "secret"

CHAIN="$WORK/enc_key.pem"
cat "$PKI/leaf.crt" "$PKI/leaf.enc.key" "$PKI/intermediate.crt" > "$CHAIN"

OUT=$("$ANALYZE" "$CHAIN" 2>&1); RC=$?

assert_exit       0    "$RC"  "exits 0 (encrypted key is a warning, not an error)"
assert_contains  "$OUT" "could not be verified" "encrypted key surfaced as 'could not be verified'"

# ──────────────────────────────────────────────────────────────────────────────

describe "analyze_chain — broken chain linkage"

# Build a fresh, unrelated intermediate. Pairing it with our leaf produces
# a chain whose linkage cannot match.
ALT="$WORK/alt"; mkdir -p "$ALT"
make_root "$ALT" alt_root         "Example Alt Root CA"
make_ca   "$ALT" alt_intermediate "Example Alt Intermediate CA" alt_root

CHAIN="$WORK/broken.pem"
cat "$PKI/leaf.crt" "$ALT/alt_intermediate.crt" > "$CHAIN"

OUT=$("$ANALYZE" "$CHAIN" 2>&1); RC=$?

assert_exit       2    "$RC"  "exits 2 on broken linkage"
assert_contains  "$OUT" "BROKEN LINK" "broken linkage reported"

# ──────────────────────────────────────────────────────────────────────────────

t_summary
