#!/usr/bin/env bash
#
# analyze_chain.sh — inspect an Apache fullchain PEM file.
#
# Accepts a bundle in any PEM order, including the common Apache layout
# where the private key is embedded between the leaf and the intermediates:
#
#     -----BEGIN CERTIFICATE-----   (leaf)
#     -----BEGIN PRIVATE KEY-----   (optional)
#     -----BEGIN CERTIFICATE-----   (intermediate 1)
#     ...
#     -----BEGIN CERTIFICATE-----   (intermediate N)
#
# Checks performed:
#   1. Splits the file into individual PEM blocks (certs + optional key).
#   2. Prints subject, issuer, validity dates and CA flag for each cert.
#   3. Flags any expired or soon-to-expire certificate.
#   4. Verifies issuer → subject linkage between successive certs.
#   5. Reports any self-signed (root) CA found in the bundle — a fullchain
#      served by Apache MUST NOT contain root CAs.
#   6. If a private key is present, verifies that its public key matches
#      the leaf certificate.
#
# Usage: ./analyze_chain.sh <fullchain.pem>
#
# Exit codes:
#   0 — all checks passed
#   1 — usage / file error
#   2 — one or more validation errors found

set -uo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Constants & helpers
# ──────────────────────────────────────────────────────────────────────────────

readonly EXPIRY_WARN_DAYS=30

if [[ -t 1 ]]; then
    readonly C_RED=$'\033[31m'
    readonly C_GREEN=$'\033[32m'
    readonly C_YELLOW=$'\033[33m'
    readonly C_BOLD=$'\033[1m'
    readonly C_RESET=$'\033[0m'
else
    readonly C_RED='' C_GREEN='' C_YELLOW='' C_BOLD='' C_RESET=''
fi

log_ok()   { printf '  %s✓%s %s\n' "$C_GREEN"  "$C_RESET" "$1"; }
log_warn() { printf '  %s⚠%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
log_err()  { printf '  %s✗%s %s\n' "$C_RED"    "$C_RESET" "$1"; }

die() {
    printf '%sError:%s %s\n' "$C_RED" "$C_RESET" "$1" >&2
    exit "${2:-1}"
}

# Convert an openssl date string ("MMM DD HH:MM:SS YYYY GMT") to unix epoch.
# Handles both BSD (macOS) and GNU (Linux) date.
to_epoch() {
    local datestr="$1"
    date -j -f "%b %d %T %Y %Z" "$datestr" +%s 2>/dev/null \
        || date -d "$datestr" +%s 2>/dev/null \
        || echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# Argument handling
# ──────────────────────────────────────────────────────────────────────────────

[[ $# -eq 1 ]] || die "Usage: $0 <fullchain.pem>"
readonly CHAIN_FILE="$1"
[[ -f "$CHAIN_FILE" ]] || die "File not found: $CHAIN_FILE"
command -v openssl >/dev/null || die "openssl not in PATH"

# Working dir for the split certs — cleaned up on exit.
WORKDIR="$(mktemp -d)"
readonly WORKDIR
trap 'rm -rf "$WORKDIR"' EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: split the bundle into individual PEM blocks
# Writes:
#   $WORKDIR/cert_<N>.pem  — one per CERTIFICATE block
#   $WORKDIR/key_<N>.pem   — one per *PRIVATE KEY block (any algorithm)
# Prints: "<cert_count> <key_count>"
# ──────────────────────────────────────────────────────────────────────────────

split_chain() {
    local src="$1"
    local cert_idx=-1 key_idx=-1
    local buf="" kind=""

    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            "-----BEGIN CERTIFICATE-----")
                kind="cert"
                cert_idx=$((cert_idx + 1))
                buf="$line"$'\n'
                ;;
            "-----END CERTIFICATE-----")
                buf+="$line"$'\n'
                printf '%s' "$buf" > "$WORKDIR/cert_${cert_idx}.pem"
                buf=""; kind=""
                ;;
            "-----BEGIN PRIVATE KEY-----" \
            | "-----BEGIN RSA PRIVATE KEY-----" \
            | "-----BEGIN EC PRIVATE KEY-----" \
            | "-----BEGIN DSA PRIVATE KEY-----" \
            | "-----BEGIN ENCRYPTED PRIVATE KEY-----")
                kind="key"
                key_idx=$((key_idx + 1))
                buf="$line"$'\n'
                ;;
            "-----END PRIVATE KEY-----" \
            | "-----END RSA PRIVATE KEY-----" \
            | "-----END EC PRIVATE KEY-----" \
            | "-----END DSA PRIVATE KEY-----" \
            | "-----END ENCRYPTED PRIVATE KEY-----")
                buf+="$line"$'\n'
                printf '%s' "$buf" > "$WORKDIR/key_${key_idx}.pem"
                buf=""; kind=""
                ;;
            *)
                [[ -n "$kind" ]] && buf+="$line"$'\n'
                ;;
        esac
    done < "$src"

    printf '%d %d\n' $((cert_idx + 1)) $((key_idx + 1))
}

read -r CERT_COUNT KEY_COUNT < <(split_chain "$CHAIN_FILE")
(( CERT_COUNT > 0 )) || die "No PEM certificate blocks found in $CHAIN_FILE"

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: inspect each certificate
# ──────────────────────────────────────────────────────────────────────────────

printf '\n%s== Certificate chain: %s ==%s\n' "$C_BOLD" "$CHAIN_FILE" "$C_RESET"
printf '%d certificate(s) found.\n' "$CERT_COUNT"

now=$(date -u +%s)
errors=0
root_in_chain=0

for (( i = 0; i < CERT_COUNT; i++ )); do
    cert="$WORKDIR/cert_${i}.pem"

    subject=$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject= *//')
    issuer=$( openssl x509 -in "$cert" -noout -issuer  | sed 's/^issuer= *//')
    not_before=$(openssl x509 -in "$cert" -noout -startdate | sed 's/^notBefore=//')
    not_after=$( openssl x509 -in "$cert" -noout -enddate   | sed 's/^notAfter=//')

    # CA flag from basicConstraints extension.
    is_ca="no"
    if openssl x509 -in "$cert" -noout -ext basicConstraints 2>/dev/null \
            | grep -q "CA:TRUE"; then
        is_ca="yes"
    fi

    # Self-signed root: subject equals issuer.
    is_root="no"
    [[ "$subject" == "$issuer" ]] && is_root="yes"

    if [[ "$is_root" == "yes" ]]; then
        kind="ROOT CA"
    elif [[ "$is_ca" == "yes" ]]; then
        kind="INTERMEDIATE CA"
    else
        kind="LEAF (end-entity)"
    fi

    printf '\n%s--- [%d/%d] %s ---%s\n' \
        "$C_BOLD" "$((i + 1))" "$CERT_COUNT" "$kind" "$C_RESET"
    printf '  subject    : %s\n' "$subject"
    printf '  issuer     : %s\n' "$issuer"
    printf '  not before : %s\n' "$not_before"
    printf '  not after  : %s\n' "$not_after"

    # Validity window.
    start_epoch=$(to_epoch "$not_before")
    end_epoch=$(  to_epoch "$not_after")

    if [[ -z "$start_epoch" || -z "$end_epoch" ]]; then
        log_warn "could not parse validity dates"
    elif (( now < start_epoch )); then
        log_err "certificate is NOT YET VALID"
        errors=$((errors + 1))
    elif (( now > end_epoch )); then
        log_err "certificate is EXPIRED"
        errors=$((errors + 1))
    else
        days_left=$(( (end_epoch - now) / 86400 ))
        if (( days_left <= EXPIRY_WARN_DAYS )); then
            log_warn "expires in ${days_left} day(s)"
        else
            log_ok "valid — ${days_left} day(s) remaining"
        fi
    fi

    # Reject root CAs in the fullchain.
    if [[ "$is_root" == "yes" ]]; then
        log_err "root CA must NOT be present in a fullchain served by Apache"
        root_in_chain=$((root_in_chain + 1))
        errors=$((errors + 1))
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: verify issuer → subject linkage between successive certs
# ──────────────────────────────────────────────────────────────────────────────

printf '\n%s== Chain linkage ==%s\n' "$C_BOLD" "$C_RESET"

if (( CERT_COUNT < 2 )); then
    log_warn "only one certificate in file — nothing to link"
else
    for (( i = 0; i < CERT_COUNT - 1; i++ )); do
        child="$WORKDIR/cert_${i}.pem"
        parent="$WORKDIR/cert_$((i + 1)).pem"

        child_issuer=$( openssl x509 -in "$child"  -noout -issuer  | sed 's/^issuer= *//')
        parent_subject=$(openssl x509 -in "$parent" -noout -subject | sed 's/^subject= *//')

        if [[ "$child_issuer" == "$parent_subject" ]]; then
            log_ok "cert $((i + 1)) → cert $((i + 2)): issuer matches subject"
        else
            log_err "cert $((i + 1)) → cert $((i + 2)): BROKEN LINK"
            printf '       cert %d issuer  : %s\n' "$((i + 1))" "$child_issuer"
            printf '       cert %d subject : %s\n' "$((i + 2))" "$parent_subject"
            errors=$((errors + 1))
        fi
    done
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: cryptographic chain verification via `openssl verify`
# ──────────────────────────────────────────────────────────────────────────────

printf '\n%s== openssl verify ==%s\n' "$C_BOLD" "$C_RESET"

if (( CERT_COUNT < 2 )); then
    log_warn "skipped — no intermediates in file"
else
    intermediates="$WORKDIR/intermediates.pem"
    : > "$intermediates"
    for (( i = 1; i < CERT_COUNT; i++ )); do
        cat "$WORKDIR/cert_${i}.pem" >> "$intermediates"
    done

    verify_out=$(openssl verify -untrusted "$intermediates" "$WORKDIR/cert_0.pem" 2>&1) || true

    if grep -q ': OK$' <<<"$verify_out"; then
        log_ok "leaf verifies against the system trust store using the bundled chain"
    else
        log_warn "openssl verify did not return OK:"
        sed 's/^/      /' <<<"$verify_out"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 5: private key match (only if a key is embedded in the bundle)
# ──────────────────────────────────────────────────────────────────────────────

key_matched="n/a"

if (( KEY_COUNT > 0 )); then
    printf '\n%s== Private key ==%s\n' "$C_BOLD" "$C_RESET"

    if (( KEY_COUNT > 1 )); then
        log_warn "found ${KEY_COUNT} private key blocks — only one is expected"
        errors=$((errors + 1))
    fi

    leaf_pub_fp=$(openssl x509 -in "$WORKDIR/cert_0.pem" -noout -pubkey \
                      | openssl pkey -pubin -outform DER 2>/dev/null \
                      | openssl dgst -sha256 | awk '{print $NF}')

    for (( i = 0; i < KEY_COUNT; i++ )); do
        keyf="$WORKDIR/key_${i}.pem"
        header=$(head -1 "$keyf")

        printf '  key block %d : %s\n' "$((i + 1))" "$header"

        if [[ "$header" == *ENCRYPTED* ]]; then
            log_warn "encrypted private key — cannot verify without passphrase"
            key_matched="unknown"
            continue
        fi

        # `openssl pkey -pubout` works for RSA, EC, Ed25519, DSA, etc.
        key_pub_fp=$(openssl pkey -in "$keyf" -pubout -outform DER 2>/dev/null \
                         | openssl dgst -sha256 | awk '{print $NF}')

        if [[ -z "$key_pub_fp" ]]; then
            log_err "could not extract public key from block $((i + 1))"
            errors=$((errors + 1))
            key_matched="unknown"
            continue
        fi

        if [[ "$key_pub_fp" == "$leaf_pub_fp" ]]; then
            log_ok "private key matches the leaf certificate"
            key_matched="yes"
        else
            log_err "private key does NOT match the leaf certificate"
            errors=$((errors + 1))
            key_matched="no"
        fi
    done
fi

# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────

printf '\n%s== Summary ==%s\n' "$C_BOLD" "$C_RESET"
if (( root_in_chain == 0 )); then
    log_ok "no root CA found in the fullchain"
else
    log_err "${root_in_chain} root CA cert(s) found in fullchain — remove them"
fi

case "$key_matched" in
    yes)     log_ok   "embedded private key matches the leaf certificate" ;;
    no)      log_err  "embedded private key does NOT match the leaf certificate" ;;
    unknown) log_warn "embedded private key could not be verified (encrypted or unreadable)" ;;
    n/a)     log_ok   "no embedded private key (key is in a separate file)" ;;
esac

if (( errors == 0 )); then
    printf '\n%sResult: ALL CHECKS PASSED%s\n\n' "$C_GREEN" "$C_RESET"
    exit 0
else
    printf '\n%sResult: %d ERROR(S) FOUND%s\n\n' "$C_RED" "$errors" "$C_RESET"
    exit 2
fi
