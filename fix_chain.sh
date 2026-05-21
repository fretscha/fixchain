#!/usr/bin/env bash
#
# fix_chain.sh — rewrite a fullchain bundle so that each intermediate is the
#                "preferred" version found in a curated cacerts file.
#
# Matching rule:
#   * Match candidates by Subject DN (RFC2253 normalised).
#   * Prefer a non-self-signed candidate. If only self-signed matches exist,
#     the original is kept — we never inject a root into the fullchain.
#   * If multiple non-self-signed candidates match, the first one wins and
#     a warning is emitted so you can curate the cacerts file.
#
# Behaviour:
#   * The leaf certificate (first cert in input) is always preserved.
#   * Any embedded private key is preserved and placed directly after the leaf.
#   * Any self-signed root present in the input chain is DROPPED — a proper
#     Apache fullchain must not contain roots.
#
# Usage:
#   ./fix_chain.sh [--drop-bridges] <input.pem> <cacerts.pem> [output.pem]
#       output.pem default: <input>.fixed.pem
#       use "-" to write to stdout
#
#   --drop-bridges   Remove any input intermediate whose subject matches a
#                    self-signed root in cacerts. Use this when modern clients
#                    trust that root directly and the cross-signed bridge to
#                    a legacy root is no longer needed (and may even break
#                    path-building if the legacy root has been removed from
#                    browser trust stores).

set -uo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Colours / logging helpers
# ──────────────────────────────────────────────────────────────────────────────

if [[ -t 2 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_BOLD=''; C_RESET=''
fi

log_ok()   { printf '  %s✓%s %s\n' "$C_GREEN"  "$C_RESET" "$1" >&2; }
log_warn() { printf '  %s⚠%s %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; }
say()      { printf '%s\n' "$*" >&2; }
die()      { printf '%sError:%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; exit "${2:-1}"; }

# ──────────────────────────────────────────────────────────────────────────────
# Argument handling
# ──────────────────────────────────────────────────────────────────────────────

DROP_BRIDGES=0
INPUT=""
CACERTS=""
OUTPUT=""
pos=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --drop-bridges) DROP_BRIDGES=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --) shift; break ;;
        -*) die "Unknown option: $1" ;;
        *)
            case "$pos" in
                0) INPUT="$1" ;;
                1) CACERTS="$1" ;;
                2) OUTPUT="$1" ;;
                *) die "Too many positional arguments" ;;
            esac
            pos=$((pos + 1))
            shift
            ;;
    esac
done

[[ -n "$INPUT" && -n "$CACERTS" ]] \
    || die "Usage: $0 [--drop-bridges] <input.pem> <cacerts.pem> [output.pem]"

[[ -f "$INPUT"   ]] || die "Input file not found: $INPUT"
[[ -f "$CACERTS" ]] || die "Cacerts file not found: $CACERTS"
command -v openssl >/dev/null || die "openssl not in PATH"

if [[ -z "$OUTPUT" ]]; then
    if [[ "$INPUT" == *.pem ]]; then
        OUTPUT="${INPUT%.pem}.fixed.pem"
    else
        OUTPUT="${INPUT}.fixed.pem"
    fi
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ──────────────────────────────────────────────────────────────────────────────
# PEM helpers
# ──────────────────────────────────────────────────────────────────────────────

# Stable RFC2253 representation of subject / issuer DN.
subject_dn() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 | sed 's/^subject= *//'; }
issuer_dn()  { openssl x509 -in "$1" -noout -issuer  -nameopt RFC2253 | sed 's/^issuer= *//'; }

# SHA-256 fingerprint of the DER form — used to detect "identical replacement".
fingerprint() {
    openssl x509 -in "$1" -outform DER 2>/dev/null \
        | openssl dgst -sha256 | awk '{print $NF}'
}

is_self_signed() {
    [[ "$(subject_dn "$1")" == "$(issuer_dn "$1")" ]]
}

# Map an arbitrary string (a DN) to a filename-safe key.
dn_key() {
    printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'
}

# ──────────────────────────────────────────────────────────────────────────────
# Splitters
# ──────────────────────────────────────────────────────────────────────────────

# Split cacerts: only certificates, written as ca_<N>.pem. Prints count.
split_cacerts() {
    local src="$1"
    local idx=-1 buf="" kind=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            "-----BEGIN CERTIFICATE-----")
                kind="cert"; idx=$((idx + 1)); buf="$line"$'\n' ;;
            "-----END CERTIFICATE-----")
                buf+="$line"$'\n'
                printf '%s' "$buf" > "$WORK/ca_${idx}.pem"
                buf=""; kind="" ;;
            *)
                [[ "$kind" == "cert" ]] && buf+="$line"$'\n' ;;
        esac
    done < "$src"
    echo $((idx + 1))
}

# Split input: certificates as in_cert_<N>.pem, keys as in_key_<N>.pem.
# Prints "<cert_count> <key_count>".
split_input() {
    local src="$1"
    local c=-1 k=-1 buf="" kind=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            "-----BEGIN CERTIFICATE-----")
                kind="cert"; c=$((c + 1)); buf="$line"$'\n' ;;
            "-----END CERTIFICATE-----")
                buf+="$line"$'\n'
                printf '%s' "$buf" > "$WORK/in_cert_${c}.pem"
                buf=""; kind="" ;;
            "-----BEGIN PRIVATE KEY-----" \
            | "-----BEGIN RSA PRIVATE KEY-----" \
            | "-----BEGIN EC PRIVATE KEY-----" \
            | "-----BEGIN DSA PRIVATE KEY-----" \
            | "-----BEGIN ENCRYPTED PRIVATE KEY-----")
                kind="key"; k=$((k + 1)); buf="$line"$'\n' ;;
            "-----END PRIVATE KEY-----" \
            | "-----END RSA PRIVATE KEY-----" \
            | "-----END EC PRIVATE KEY-----" \
            | "-----END DSA PRIVATE KEY-----" \
            | "-----END ENCRYPTED PRIVATE KEY-----")
                buf+="$line"$'\n'
                printf '%s' "$buf" > "$WORK/in_key_${k}.pem"
                buf=""; kind="" ;;
            *)
                [[ -n "$kind" ]] && buf+="$line"$'\n' ;;
        esac
    done < "$src"
    printf '%d %d\n' $((c + 1)) $((k + 1))
}

# ──────────────────────────────────────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────────────────────────────────────

say ""
say "${C_BOLD}fix_chain.sh${C_RESET}"
say "  input   : ${C_CYAN}${INPUT}${C_RESET}"
say "  cacerts : ${C_CYAN}${CACERTS}${C_RESET}"
say "  output  : ${C_CYAN}${OUTPUT}${C_RESET}"
say ""

# ──────────────────────────────────────────────────────────────────────────────
# Index cacerts by subject DN
# ──────────────────────────────────────────────────────────────────────────────

say "${C_BOLD}Indexing cacerts...${C_RESET}"
mkdir -p "$WORK/index"

CACERT_COUNT=$(split_cacerts "$CACERTS")
(( CACERT_COUNT > 0 )) || die "No certificates found in $CACERTS"

for (( i = 0; i < CACERT_COUNT; i++ )); do
    f="$WORK/ca_${i}.pem"
    key=$(dn_key "$(subject_dn "$f")")
    echo "$f" >> "$WORK/index/$key"
done

log_ok "${CACERT_COUNT} cert(s) indexed"

# Returns 0-or-more file paths for cacerts certs that share the given subject DN.
lookup_subject() {
    local key
    key=$(dn_key "$1")
    [[ -f "$WORK/index/$key" ]] && cat "$WORK/index/$key"
}

# ──────────────────────────────────────────────────────────────────────────────
# Parse input bundle
# ──────────────────────────────────────────────────────────────────────────────

say ""
say "${C_BOLD}Parsing input bundle...${C_RESET}"

read -r IN_CERT_COUNT IN_KEY_COUNT < <(split_input "$INPUT")
(( IN_CERT_COUNT > 0 )) || die "No certificates in $INPUT"

log_ok "${IN_CERT_COUNT} cert(s), ${IN_KEY_COUNT} key block(s)"

# ──────────────────────────────────────────────────────────────────────────────
# Rebuild
# ──────────────────────────────────────────────────────────────────────────────

say ""
say "${C_BOLD}Rebuilding chain...${C_RESET}"

: > "$WORK/output.pem"

REPLACED=0
KEPT=0
DROPPED_ROOT=0
DROPPED_BRIDGE=0
NO_MATCH=0
MULTI_CANDIDATE=0

for (( i = 0; i < IN_CERT_COUNT; i++ )); do
    cert="$WORK/in_cert_${i}.pem"
    subj=$(subject_dn "$cert")

    # ── Leaf: always preserved as the first block. Key follows it. ────────────
    if (( i == 0 )); then
        cat "$cert" >> "$WORK/output.pem"
        log_ok "[1] leaf kept — $subj"

        for (( k = 0; k < IN_KEY_COUNT; k++ )); do
            cat "$WORK/in_key_${k}.pem" >> "$WORK/output.pem"
        done
        (( IN_KEY_COUNT > 0 )) && log_ok "    embedded private key preserved (${IN_KEY_COUNT} block(s))"
        continue
    fi

    # ── Drop roots from the bundle. ───────────────────────────────────────────
    if is_self_signed "$cert"; then
        log_warn "[$((i+1))] root CA dropped — $subj"
        DROPPED_ROOT=$((DROPPED_ROOT + 1))
        continue
    fi

    # ── Intermediate — search cacerts by subject DN. ──────────────────────────
    # Portable read-into-array (macOS ships bash 3.2 without mapfile).
    candidates=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && candidates+=("$line")
    done < <(lookup_subject "$subj")

    if (( ${#candidates[@]} == 0 )); then
        log_warn "[$((i+1))] no cacerts match — keeping original: $subj"
        cat "$cert" >> "$WORK/output.pem"
        NO_MATCH=$((NO_MATCH + 1))
        continue
    fi

    # From the candidates, ignore self-signed (roots) — we don't inject them.
    chosen=""
    intermediate_candidates=0
    for cand in "${candidates[@]}"; do
        if ! is_self_signed "$cand"; then
            intermediate_candidates=$((intermediate_candidates + 1))
            [[ -z "$chosen" ]] && chosen="$cand"
        fi
    done

    if [[ -z "$chosen" ]]; then
        if (( DROP_BRIDGES == 1 )); then
            log_warn "[$((i+1))] cross-signed bridge dropped — root with same subject is in cacerts: $subj"
            DROPPED_BRIDGE=$((DROPPED_BRIDGE + 1))
            continue
        fi
        log_warn "[$((i+1))] only self-signed match in cacerts — keeping original: $subj"
        log_warn "         (use --drop-bridges to remove it if clients trust the root directly)"
        cat "$cert" >> "$WORK/output.pem"
        KEPT=$((KEPT + 1))
        continue
    fi

    cat "$chosen" >> "$WORK/output.pem"

    if [[ "$(fingerprint "$cert")" == "$(fingerprint "$chosen")" ]]; then
        log_ok "[$((i+1))] match identical — kept: $subj"
        KEPT=$((KEPT + 1))
    else
        log_ok "[$((i+1))] replaced with preferred version — $subj"
        printf '         orig issuer : %s\n' "$(issuer_dn "$cert")"   >&2
        printf '         new  issuer : %s\n' "$(issuer_dn "$chosen")" >&2
        REPLACED=$((REPLACED + 1))
    fi

    if (( intermediate_candidates > 1 )); then
        log_warn "         ${intermediate_candidates} non-self-signed candidates matched this subject — first one used"
        MULTI_CANDIDATE=$((MULTI_CANDIDATE + 1))
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
# Write output
# ──────────────────────────────────────────────────────────────────────────────

if [[ "$OUTPUT" == "-" ]]; then
    cat "$WORK/output.pem"
else
    cp "$WORK/output.pem" "$OUTPUT"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────

say ""
say "${C_BOLD}Summary${C_RESET}"
say "  replaced            : $REPLACED"
say "  kept (identical or no usable match) : $KEPT"
say "  intermediates without cacerts entry : $NO_MATCH"
say "  roots removed from input            : $DROPPED_ROOT"
say "  cross-signed bridges dropped        : $DROPPED_BRIDGE"
(( MULTI_CANDIDATE > 0 )) && say "  subjects with >1 cacerts intermediates: $MULTI_CANDIDATE (curate cacerts to disambiguate)"
[[ "$OUTPUT" != "-" ]] && say "  output                              : $OUTPUT"

exit 0
