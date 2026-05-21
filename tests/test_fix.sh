#!/usr/bin/env bash
# Tests for fix_chain.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

source "$HERE/lib/assert.sh"
source "$HERE/lib/fixtures.sh"

FIX="$ROOT/fix_chain.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — cacerts has the identical intermediate (no-op replacement)"

PKI="$WORK/p1"; mkdir -p "$PKI"
build_basic_pki "$PKI"

cat "$PKI/leaf.crt" "$PKI/intermediate.crt" > "$WORK/p1.in.pem"
cp  "$PKI/intermediate.crt"                  "$WORK/p1.ca.pem"

OUT=$("$FIX" "$WORK/p1.in.pem" "$WORK/p1.ca.pem" "$WORK/p1.out.pem" 2>&1); RC=$?

assert_exit         0 "$RC"                       "exits 0"
assert_contains    "$OUT" "match identical"       "no-op replacement reported"
assert_contains    "$OUT" "replaced            : 0" "REPLACED counter is 0"
assert_file_exists "$WORK/p1.out.pem"             "output file created"

OUT_CERTS=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$WORK/p1.out.pem")
assert_eq          "2" "$OUT_CERTS"               "output has leaf + intermediate"

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — cacerts has a different cert with the same subject (real replacement)"

# A second root that will also sign the same-subject intermediate.
PKI="$WORK/p2"; mkdir -p "$PKI"
build_basic_pki "$PKI"

# Issue an *alternate* intermediate cert under a different root, but with the
# same CN. cross-sign the original intermediate's key with a different root.
make_root        "$PKI" alt_root          "Example Alt Root CA"
make_cross_sign  "$PKI" intermediate "Example Intermediate CA" alt_root intermediate_alt

cat "$PKI/leaf.crt" "$PKI/intermediate.crt" > "$WORK/p2.in.pem"
cp  "$PKI/intermediate_alt.crt"              "$WORK/p2.ca.pem"

OUT=$("$FIX" "$WORK/p2.in.pem" "$WORK/p2.ca.pem" "$WORK/p2.out.pem" 2>&1); RC=$?

assert_exit       0 "$RC"                              "exits 0"
assert_contains  "$OUT" "replaced with preferred"      "real replacement reported"
assert_contains  "$OUT" "replaced            : 1"      "REPLACED counter is 1"

# Verify the output's intermediate is byte-equal to the cacerts version, not the input version.
ORIG_FP=$(openssl x509 -in "$PKI/intermediate.crt"     -noout -fingerprint -sha256 | cut -d= -f2)
ALT_FP=$( openssl x509 -in "$PKI/intermediate_alt.crt" -noout -fingerprint -sha256 | cut -d= -f2)

# Extract second cert from output
awk '/-----BEGIN CERTIFICATE-----/{c++} c==2' "$WORK/p2.out.pem" \
    | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' \
    > "$WORK/p2.intermediate_in_out.pem"

OUT_FP=$(openssl x509 -in "$WORK/p2.intermediate_in_out.pem" -noout -fingerprint -sha256 | cut -d= -f2)

assert_eq        "$ALT_FP"  "$OUT_FP"  "output intermediate equals cacerts version"
assert_not_contains "$ORIG_FP" "$OUT_FP" "output intermediate is NOT the original"

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — root cert in input is dropped"

PKI="$WORK/p3"; mkdir -p "$PKI"
build_basic_pki "$PKI"

cat "$PKI/leaf.crt" "$PKI/intermediate.crt" "$PKI/root.crt" > "$WORK/p3.in.pem"
cp  "$PKI/intermediate.crt"                                   "$WORK/p3.ca.pem"

OUT=$("$FIX" "$WORK/p3.in.pem" "$WORK/p3.ca.pem" "$WORK/p3.out.pem" 2>&1); RC=$?

assert_exit       0 "$RC"                              "exits 0"
assert_contains  "$OUT" "root CA dropped"              "root drop reported"
assert_contains  "$OUT" "roots removed from input            : 1" "DROPPED_ROOT=1"

OUT_CERTS=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$WORK/p3.out.pem")
assert_eq        "2" "$OUT_CERTS" "output has only 2 certs (no root)"

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — embedded private key is preserved byte-for-byte"

PKI="$WORK/p4"; mkdir -p "$PKI"
build_basic_pki "$PKI"

cat "$PKI/leaf.crt" "$PKI/leaf.key" "$PKI/intermediate.crt" > "$WORK/p4.in.pem"
cp  "$PKI/intermediate.crt"                                   "$WORK/p4.ca.pem"

OUT=$("$FIX" "$WORK/p4.in.pem" "$WORK/p4.ca.pem" "$WORK/p4.out.pem" 2>&1); RC=$?

assert_exit       0 "$RC"                            "exits 0"
assert_contains  "$OUT" "embedded private key preserved" "key preservation logged"

awk '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/' \
    "$WORK/p4.out.pem" > "$WORK/p4.key_from_out.pem"

cmp -s "$PKI/leaf.key" "$WORK/p4.key_from_out.pem"
assert_exit       0 "$?" "extracted key is byte-equal to leaf.key"

# Layout check: leaf, then key, then intermediate
LAYOUT=$(grep -E '^-----BEGIN ' "$WORK/p4.out.pem")
EXPECTED="$(printf '%s\n%s\n%s' \
    '-----BEGIN CERTIFICATE-----' \
    '-----BEGIN PRIVATE KEY-----' \
    '-----BEGIN CERTIFICATE-----')"
assert_eq        "$EXPECTED" "$LAYOUT" "output layout is leaf | key | intermediate"

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — cross-signed bridge: --drop-bridges removes it"

PKI="$WORK/p5"; mkdir -p "$PKI"
build_cross_signed_pki "$PKI"

# Input chain: leaf | intermediate | new_root_bridge (signed by legacy_root)
cat "$PKI/leaf.crt" "$PKI/intermediate.crt" "$PKI/new_root_bridge.crt" \
    > "$WORK/p5.in.pem"

# cacerts: intermediate + new_root (self-signed) — the modern trust source
cat "$PKI/intermediate.crt" "$PKI/new_root.crt" > "$WORK/p5.ca.pem"

OUT=$("$FIX" --drop-bridges "$WORK/p5.in.pem" "$WORK/p5.ca.pem" "$WORK/p5.out.pem" 2>&1); RC=$?

assert_exit       0 "$RC"                                  "exits 0"
assert_contains  "$OUT" "cross-signed bridge dropped"      "bridge drop reported"
assert_contains  "$OUT" "cross-signed bridges dropped        : 1" "DROPPED_BRIDGE=1"

OUT_CERTS=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$WORK/p5.out.pem")
assert_eq        "2" "$OUT_CERTS" "output has 2 certs (bridge removed)"

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — cross-signed bridge: without --drop-bridges, bridge is kept"

OUT=$("$FIX" "$WORK/p5.in.pem" "$WORK/p5.ca.pem" "$WORK/p5.out2.pem" 2>&1); RC=$?

assert_exit       0 "$RC"                              "exits 0"
assert_contains  "$OUT" "only self-signed match"       "kept-bridge path taken"
assert_contains  "$OUT" "--drop-bridges"               "hint about --drop-bridges shown"

OUT_CERTS=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$WORK/p5.out2.pem")
assert_eq        "3" "$OUT_CERTS" "output preserves the 3 input certs"

# ──────────────────────────────────────────────────────────────────────────────

describe "fix_chain — intermediate not present in cacerts (no match)"

PKI="$WORK/p6"; mkdir -p "$PKI"
build_basic_pki "$PKI"

# cacerts that contains only an unrelated cert
make_root "$PKI" unrelated "Example Unrelated Root CA"
cp "$PKI/unrelated.crt" "$WORK/p6.ca.pem"

cat "$PKI/leaf.crt" "$PKI/intermediate.crt" > "$WORK/p6.in.pem"

OUT=$("$FIX" "$WORK/p6.in.pem" "$WORK/p6.ca.pem" "$WORK/p6.out.pem" 2>&1); RC=$?

assert_exit       0 "$RC"                              "exits 0"
assert_contains  "$OUT" "no cacerts match"             "no-match reported"
assert_contains  "$OUT" "intermediates without cacerts entry : 1" "NO_MATCH=1"

# Original intermediate must still be present in output (we keep it).
ORIG_FP=$(openssl x509 -in "$PKI/intermediate.crt" -noout -fingerprint -sha256 | cut -d= -f2)
awk '/-----BEGIN CERTIFICATE-----/{c++} c==2' "$WORK/p6.out.pem" \
    | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' \
    > "$WORK/p6.intermediate_in_out.pem"
OUT_FP=$(openssl x509 -in "$WORK/p6.intermediate_in_out.pem" -noout -fingerprint -sha256 | cut -d= -f2)

assert_eq        "$ORIG_FP" "$OUT_FP" "original intermediate kept verbatim"

# ──────────────────────────────────────────────────────────────────────────────

t_summary
