#!/usr/bin/env bash
#
# fetch_chain.sh — pull a TLS server's certificate chain via `openssl s_client`
#                  and save it as a PEM bundle (leaf + intermediates, no root).
#
# Usage:
#   ./fetch_chain.sh [options] <host[:port]>
#
# Options:
#   -o, --output FILE      Output file (default: ./<host>.fullchain.pem).
#                          Use "-" to write to stdout.
#   -s, --servername NAME  SNI hostname to send (default: same as host).
#   -t, --timeout SECS     Connect timeout in seconds (default: 10).
#       --starttls PROTO   Use STARTTLS for the named protocol
#                          (smtp, imap, pop3, ftp, ldap, xmpp, postgres, ...).
#   -a, --analyze          After fetching, run analyze_chain.sh on the result.
#   -q, --quiet            Suppress progress messages (PEM still written).
#   -h, --help             Show this help and exit.
#
# Examples:
#   ./fetch_chain.sh example.com
#   ./fetch_chain.sh example.com:8443 -o example.pem -a
#   ./fetch_chain.sh smtp.example.com:587 --starttls smtp

set -uo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Defaults & helpers
# ──────────────────────────────────────────────────────────────────────────────

PORT_DEFAULT=443
TIMEOUT_DEFAULT=10
ANALYZER="$(dirname "$0")/analyze_chain.sh"

if [[ -t 2 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_BOLD=''; C_RESET=''
fi

say()   { [[ "${QUIET:-0}" -eq 1 ]] || printf '%s\n' "$*" >&2; }
ok()    { [[ "${QUIET:-0}" -eq 1 ]] || printf '  %s✓%s %s\n' "$C_GREEN"  "$C_RESET" "$1" >&2; }
warn()  { printf '  %s⚠%s %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; }
die()   { printf '%sError:%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; exit "${2:-1}"; }

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ──────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT=""
SERVERNAME=""
STARTTLS=""
ANALYZE=0
QUIET=0
TIMEOUT="$TIMEOUT_DEFAULT"
HOST_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)     OUTPUT="$2"; shift 2 ;;
        -s|--servername) SERVERNAME="$2"; shift 2 ;;
        -t|--timeout)    TIMEOUT="$2"; shift 2 ;;
        --starttls)      STARTTLS="$2"; shift 2 ;;
        -a|--analyze)    ANALYZE=1; shift ;;
        -q|--quiet)      QUIET=1; shift ;;
        -h|--help)       usage 0 ;;
        --)              shift; HOST_ARG="${1:-}"; break ;;
        -*)              die "Unknown option: $1" ;;
        *)               HOST_ARG="$1"; shift ;;
    esac
done

[[ -n "$HOST_ARG" ]] || usage 1
command -v openssl >/dev/null || die "openssl not in PATH"

# Split host:port
if [[ "$HOST_ARG" == *:* ]]; then
    HOST="${HOST_ARG%:*}"
    PORT="${HOST_ARG##*:}"
else
    HOST="$HOST_ARG"
    PORT="$PORT_DEFAULT"
fi

[[ -n "$HOST" ]] || die "Empty hostname"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "Invalid port: $PORT"

[[ -z "$SERVERNAME" ]] && SERVERNAME="$HOST"

# Default output filename
if [[ -z "$OUTPUT" ]]; then
    OUTPUT="./${HOST}.fullchain.pem"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Fetch the chain
# ──────────────────────────────────────────────────────────────────────────────

say "${C_BOLD}Fetching certificate chain${C_RESET}"
say "  host       : $HOST"
say "  port       : $PORT"
say "  servername : $SERVERNAME"
[[ -n "$STARTTLS" ]] && say "  starttls   : $STARTTLS"
say "  output     : $OUTPUT"
say "  timeout    : ${TIMEOUT}s"
say ""

# Build openssl args. Use -showcerts to dump the full chain the server sends.
OPENSSL_ARGS=(
    s_client
    -showcerts
    -connect "${HOST}:${PORT}"
    -servername "$SERVERNAME"
)
[[ -n "$STARTTLS" ]] && OPENSSL_ARGS+=(-starttls "$STARTTLS")

# Capture both raw output (for chain extraction) and stderr (for diagnostics).
RAW=$(mktemp)
ERR=$(mktemp)
trap 'rm -f "$RAW" "$ERR"' EXIT

# `</dev/null` ends the session immediately after TLS handshake.
# Some openssl builds need a small grace period for STARTTLS to settle; the
# kernel-level connect itself is bounded by the chosen timeout helper below.
if command -v timeout >/dev/null; then
    TIMEOUT_CMD=(timeout "$TIMEOUT")
elif command -v gtimeout >/dev/null; then
    TIMEOUT_CMD=(gtimeout "$TIMEOUT")
else
    # Fallback: no portable timeout. openssl s_client will rely on TCP timeouts.
    TIMEOUT_CMD=()
    warn "no 'timeout' command found — connection may hang on unreachable hosts"
fi

"${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"}" openssl "${OPENSSL_ARGS[@]}" </dev/null > "$RAW" 2> "$ERR"
RC=$?

# openssl s_client exits non-zero on verification errors but still prints the
# chain — so we only bail out when there is no chain to extract.
PEM=$(awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$RAW")

if [[ -z "$PEM" ]]; then
    warn "openssl s_client exited with code $RC and produced no certificates"
    say  "--- stderr ---"
    sed 's/^/  /' "$ERR" >&2
    die  "could not retrieve any certificates from ${HOST}:${PORT}"
fi

# Count blocks
COUNT=$(grep -c -- '-----BEGIN CERTIFICATE-----' <<<"$PEM")

# Write output
if [[ "$OUTPUT" == "-" ]]; then
    printf '%s\n' "$PEM"
else
    printf '%s\n' "$PEM" > "$OUTPUT"
    ok "saved ${COUNT} certificate(s) to $OUTPUT"
fi

# Surface useful s_client diagnostics that show up in stderr / stdout.
if [[ "${QUIET:-0}" -ne 1 ]]; then
    say ""
    say "${C_BOLD}Handshake summary${C_RESET}"
    # The session block lives in $RAW after the chain.
    grep -E '^(Protocol|Cipher|Server certificate|Verify return code|verify return)' "$RAW" \
        | sed 's/^/  /' >&2 || true

    if grep -q 'Verification error:' "$RAW"; then
        warn "$(grep 'Verification error:' "$RAW" | head -1)"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Optional: hand off to analyze_chain.sh
# ──────────────────────────────────────────────────────────────────────────────

if (( ANALYZE == 1 )) && [[ "$OUTPUT" != "-" ]]; then
    if [[ -x "$ANALYZER" ]]; then
        say ""
        "$ANALYZER" "$OUTPUT"
        exit $?
    else
        warn "analyzer not found or not executable: $ANALYZER"
    fi
fi

exit 0
