# fixchain

[![tests](https://github.com/fretscha/fixchain/actions/workflows/tests.yml/badge.svg)](https://github.com/fretscha/fixchain/actions/workflows/tests.yml)

A small set of POSIX-friendly bash + OpenSSL tools for inspecting,
fetching, and rewriting TLS certificate chains — primarily aimed at
Apache `SSLCertificateFile` bundles, but useful for any server that
serves a PEM chain.

No external dependencies beyond `bash`, `openssl`, and standard Unix
utilities (`awk`, `sed`, `grep`, `cmp`). Tested on macOS (bash 3.2) and
Linux (bash 5).

## Scripts

| Script | Purpose |
|--------|---------|
| [`analyze_chain.sh`](analyze_chain.sh) | Inspect a fullchain PEM file: classify each cert (leaf / intermediate / root), check validity dates, verify linkage, run `openssl verify`, and optionally validate an embedded private key against the leaf. Flags roots that should not be present in a fullchain. |
| [`fetch_chain.sh`](fetch_chain.sh)     | Pull a remote server's chain via `openssl s_client -showcerts` and save it as a PEM bundle. Supports SNI, custom ports, STARTTLS protocols, and an `--analyze` shortcut to pipe the result into `analyze_chain.sh`. |
| [`fix_chain.sh`](fix_chain.sh)         | Rewrite a fullchain so that every intermediate is the "preferred" version from a curated `cacerts.pem`. Matches by Subject DN. Drops self-signed roots from the input. Optional `--drop-bridges` removes cross-signed intermediates whose self-signed twin already lives in `cacerts.pem` (e.g. modern roots whose legacy cross-signer has been removed from browser trust stores). Preserves an embedded private key byte-for-byte. |

## Quick start

```bash
# 1. Pull the chain a server is currently sending
./fetch_chain.sh example.com -o example.fullchain.pem

# 2. Inspect it
./analyze_chain.sh example.fullchain.pem

# 3. Rewrite intermediates from a trusted source, dropping any dead bridges
./fix_chain.sh --drop-bridges example.fullchain.pem cacerts.pem example.deploy.pem

# 4. Verify the result
./analyze_chain.sh example.deploy.pem
```

## `analyze_chain.sh`

```
analyze_chain.sh <fullchain.pem>
```

Performs:

1. Splits the file into individual PEM blocks (certificates + optional embedded
   private key).
2. For each certificate, prints subject, issuer, validity window, signature
   algorithm, and serial.
3. Classifies as **LEAF**, **INTERMEDIATE CA**, or **ROOT CA** (the last is an
   error in a fullchain).
4. Warns when a certificate expires within 30 days; errors on expired or
   not-yet-valid certificates.
5. Verifies `issuer → subject` linkage between successive certificates.
6. Runs `openssl verify -untrusted <bundled intermediates> <leaf>` for full
   cryptographic verification against the system trust store.
7. If a private key is embedded in the bundle, verifies that its public key
   matches the leaf certificate. Encrypted keys are reported as a warning
   rather than an error.

Exit codes: `0` clean · `1` usage/file error · `2` validation errors found.

## `fetch_chain.sh`

```
fetch_chain.sh [options] <host[:port]>

Options:
  -o, --output FILE      Output file (default: ./<host>.fullchain.pem; "-" for stdout)
  -s, --servername NAME  SNI hostname (default: same as host)
  -t, --timeout SECS     Connect timeout in seconds (default: 10)
      --starttls PROTO   Use STARTTLS for smtp, imap, pop3, ftp, ldap, xmpp, …
  -a, --analyze          Pipe the saved chain into analyze_chain.sh
  -q, --quiet            Suppress progress messages
```

Examples:

```bash
./fetch_chain.sh example.com
./fetch_chain.sh example.com:8443 -o example.pem -a
./fetch_chain.sh smtp.example.com:587 --starttls smtp
./fetch_chain.sh 1.2.3.4:443 -s api.example.com   # custom SNI
```

The script uses `awk` to extract `BEGIN/END CERTIFICATE` blocks from
`openssl s_client -showcerts`, so only what the server actually presents
is saved — never a system-store root. The handshake summary
(`Protocol`, `Verify return code`, …) is surfaced after the fetch.

## `fix_chain.sh`

```
fix_chain.sh [--drop-bridges] <input.pem> <cacerts.pem> [output.pem]
```

Rewrites the input chain using `cacerts.pem` as the source of preferred
intermediates. Matching rule:

* Match candidates by **Subject DN** (normalised to RFC 2253).
* Prefer a non-self-signed candidate. If only self-signed matches exist,
  the original cert is kept — the script never injects a root into the
  fullchain.
* If multiple non-self-signed candidates share the same subject, the
  first one wins and a warning is printed so you can curate `cacerts.pem`.

Behaviour:

* The leaf (first cert) is always preserved.
* An embedded private key is preserved at its original position
  (directly after the leaf in the output).
* Any self-signed root present in the input is **dropped**.
* `--drop-bridges`: also drop input intermediates whose subject matches a
  self-signed root in `cacerts.pem`. Use this when modern clients trust
  that root directly and the cross-signed bridge to a now-untrusted
  legacy root would only confuse path-building (e.g. an intermediate
  cross-signed by a CA that has been removed from browser trust stores).

The output filename defaults to `<input>.fixed.pem`; pass `-` to write
to stdout.

## Tests

```bash
./tests/run_all.sh
```

Three test suites build a fresh disposable PKI on the fly (RFC 2606
reserved names only — `example.com`, `test.example`, `Example Org`) and
exercise:

* `test_analyze` — valid chain, chain with root, key match / mismatch /
  encrypted, broken linkage.
* `test_fix` — identical match, real replacement, root drop, key
  preservation, cross-signed bridge with and without `--drop-bridges`,
  no-match-in-cacerts.
* `test_fetch` — usage errors, unknown flags, full round-trip against a
  local `openssl s_server`, stdout mode.

Set `TEST_VERBOSE=1` to surface raw OpenSSL output during fixture
builds.

## Requirements

* `bash` (3.2 or newer; works on macOS's stock shell)
* `openssl` (1.1 or newer)
* Standard POSIX utilities: `awk`, `sed`, `grep`, `cmp`, `mktemp`

Optional:

* `timeout` / `gtimeout` — used by `fetch_chain.sh` to bound hung
  connects. Install GNU coreutils on macOS (`brew install coreutils`)
  to get `gtimeout`.

## Contributing

Patches, bug reports, and ideas are welcome — open an
[issue](https://github.com/fretscha/fixchain/issues) or a pull request.

A few project-specific conventions:

* **Tests must pass on both macOS and Linux.** The scripts target
  bash 3.2 (macOS's stock shell) as well as bash 5; avoid bash 4+ only
  features (`mapfile`/`readarray`, associative arrays, `${var@Q}`,
  etc.) unless you also add a fallback. The CI matrix runs
  `ubuntu-latest` and `macos-latest` for every push and PR.
* **Run the test suite before submitting.**
  ```bash
  ./tests/run_all.sh
  ```
  If you're adding a new behaviour, add a test for it. Test fixtures
  build a disposable PKI on the fly — see
  [`tests/lib/fixtures.sh`](tests/lib/fixtures.sh) for the building
  blocks.
* **Keep test identifiers anonymised.** Use only RFC 2606 reserved
  names (`example.com`, `example.org`, `test.example`, `*.invalid`,
  `*.localhost`) and the fictional `Example Org` for fixture
  organisations. Do not commit certificates, keys, or hostnames from
  real-world systems.
* **`shellcheck` is encouraged.** If you have it installed, run it
  against changed files before committing:
  ```bash
  shellcheck *.sh tests/*.sh tests/lib/*.sh
  ```
* **Don't add external runtime dependencies.** The point of this
  project is to work with stock `bash` + `openssl`; any new helper
  should fall back gracefully if a tool isn't present (see how
  `fetch_chain.sh` handles a missing `timeout` / `gtimeout`).

## License

MIT.
