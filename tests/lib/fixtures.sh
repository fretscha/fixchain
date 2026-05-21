# shellcheck shell=bash
# PKI fixture builders for the test suite.
# All identifiers come from RFC 2606 reserved names (`example`, `test`)
# and a fictional "Example Org" — never any real-world organisation.

# Silence openssl unless TEST_VERBOSE=1.
_oq() {
    if [[ "${TEST_VERBOSE:-0}" -eq 1 ]]; then
        openssl "$@"
    else
        openssl "$@" 2>/dev/null
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Building blocks
# ──────────────────────────────────────────────────────────────────────────────

# make_root <dir> <name> <CN> [<days>]
# Self-signed root with CA:TRUE.
make_root() {
    local dir="$1" name="$2" cn="$3" days="${4:-3650}"
    _oq req -x509 -newkey rsa:2048 \
        -keyout "$dir/${name}.key" -out "$dir/${name}.crt" \
        -days "$days" -nodes \
        -subj "/CN=${cn}/O=Example Org/C=XX" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
}

# make_ca <dir> <name> <CN> <signer> [<days>]
# Subordinate CA cert signed by <signer>.crt / <signer>.key.
make_ca() {
    local dir="$1" name="$2" cn="$3" signer="$4" days="${5:-1825}"
    _oq req -newkey rsa:2048 \
        -keyout "$dir/${name}.key" -out "$dir/${name}.csr" \
        -nodes -subj "/CN=${cn}/O=Example Org/C=XX"
    _oq x509 -req -in "$dir/${name}.csr" \
        -CA "$dir/${signer}.crt" -CAkey "$dir/${signer}.key" -CAcreateserial \
        -out "$dir/${name}.crt" -days "$days" \
        -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
}

# make_leaf <dir> <name> <CN> <signer> [<days>]
make_leaf() {
    local dir="$1" name="$2" cn="$3" signer="$4" days="${5:-365}"
    _oq req -newkey rsa:2048 \
        -keyout "$dir/${name}.key" -out "$dir/${name}.csr" \
        -nodes -subj "/CN=${cn}/O=Example Org/C=XX"
    _oq x509 -req -in "$dir/${name}.csr" \
        -CA "$dir/${signer}.crt" -CAkey "$dir/${signer}.key" -CAcreateserial \
        -out "$dir/${name}.crt" -days "$days"
}

# make_cross_sign <dir> <existing_root_name> <CN> <new_signer> <out_name>
# Produce a cross-signed bridge: subject + public key come from
# <existing_root_name>, signature comes from <new_signer>. This mirrors the
# real-world pattern where a modern root is also issued by a legacy root for
# clients that don't yet trust the modern one.
make_cross_sign() {
    local dir="$1" sub="$2" cn="$3" signer="$4" out="$5" days="${6:-1825}"
    _oq req -new -key "$dir/${sub}.key" -out "$dir/${out}.csr" \
        -subj "/CN=${cn}/O=Example Org/C=XX"
    _oq x509 -req -in "$dir/${out}.csr" \
        -CA "$dir/${signer}.crt" -CAkey "$dir/${signer}.key" -CAcreateserial \
        -out "$dir/${out}.crt" -days "$days" \
        -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
}

# encrypt_key <dir> <name> <passphrase>
# PKCS#8-encrypt <name>.key in place into <name>.enc.key
encrypt_key() {
    local dir="$1" name="$2" pass="$3"
    _oq pkcs8 -topk8 \
        -in "$dir/${name}.key" \
        -out "$dir/${name}.enc.key" \
        -passout "pass:${pass}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Composite scenarios
# ──────────────────────────────────────────────────────────────────────────────

# build_basic_pki <dir>
# Creates:
#   root.crt / root.key           — self-signed root
#   intermediate.crt / .key       — intermediate signed by root
#   leaf.crt / leaf.key           — leaf signed by intermediate
build_basic_pki() {
    local dir="$1"
    make_root "$dir" root            "Example Root CA"
    make_ca   "$dir" intermediate    "Example Intermediate CA" root
    make_leaf "$dir" leaf            "test.example"            intermediate
}

# build_cross_signed_pki <dir>
# Creates:
#   legacy_root.crt / .key            — old, deprecated trust anchor
#   new_root.crt / .key               — modern self-signed root
#   new_root_bridge.crt               — new_root's subject+pubkey signed by legacy_root
#   intermediate.crt / .key           — signed by new_root
#   leaf.crt / leaf.key               — signed by intermediate
build_cross_signed_pki() {
    local dir="$1"
    make_root "$dir" legacy_root  "Example Legacy Root CA"
    make_root "$dir" new_root     "Example New Root CA"
    make_cross_sign "$dir" new_root "Example New Root CA" legacy_root new_root_bridge
    make_ca   "$dir" intermediate "Example Intermediate CA" new_root
    make_leaf "$dir" leaf         "api.example.com"         intermediate
}
