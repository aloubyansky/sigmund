# Signing Guide

This guide covers artifact signing with Sigmund's three OpenPGP backends: GPG (simplest, existing keys), Bouncy Castle (zero external dependencies), and Sequoia sq (post-quantum hybrid signing).

## Contents

- [Overview](#overview)
- [Checking the Signing Setup](#checking-the-signing-setup)
- [Signing with Existing GPG Keys](#signing-with-existing-gpg-keys)
- [Signing with Bouncy Castle](#signing-with-bouncy-castle)
  - [Key Generation](#key-generation)
  - [Passphrase Protection](#passphrase-protection)
  - [Passphrase Resolution Order](#passphrase-resolution-order)
- [Ephemeral CI Signing](#ephemeral-ci-signing)
- [Hybrid PQC Signing](#hybrid-pqc-signing)
  - [Prerequisites](#prerequisites)
  - [Installing Sequoia sq](#installing-sequoia-sq)
  - [Generating a PQC Key](#generating-a-pqc-key)
  - [Signing with PQC](#signing-with-pqc)
  - [PQC Signature Sizes](#pqc-signature-sizes)
- [Signing Profiles](#signing-profiles)
- [Signing Pipeline](#signing-pipeline)
- [Backward Compatibility](#backward-compatibility)
- [Maven Central Compatibility](#maven-central-compatibility)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:sign`). This requires adding the plugin to your project's `pluginManagement`:
>
> ```xml
> <pluginManagement>
>   <plugins>
>     <plugin>
>       <groupId>dev.cyberstamp.sigmund</groupId>
>       <artifactId>sigmund-maven-plugin</artifactId>
>       <version>0.0.1-SNAPSHOT</version>
>     </plugin>
>   </plugins>
> </pluginManagement>
> ```
>
> Alternatively, replace `sigmund` with the full plugin coordinates, e.g.:
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.1-SNAPSHOT:sign`

## Overview

Sigmund signs artifacts using one or more OpenPGP backends. The signing pipeline produces a detached `.asc` signature file. When multiple tools sign, their signatures are combined into a single `.asc` as separate armored blocks:

```
-----BEGIN PGP SIGNATURE-----
(classic signature — GPG or BC)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(PQC signature — Sequoia sq)
-----END PGP SIGNATURE-----
```

Existing tools (GPG, Maven Central) see only the first block and work as before. PQC-aware tools can verify all blocks.

## Checking the Signing Setup

Use `signing-info` to display the effective signing configuration — which tools are active, what keys they will use, and which credential types they produce — without signing anything.

**CLI:**

```bash
sigmund signing-info
```

**Maven:**

```bash
mvn sigmund:signing-info
```

Example output:

```
bc: Ed25519 D62AAB339E45E5EA2FD036872B01D46A517A2991... (Alice <alice@example.com>)
sq: ML-DSA-87+Ed448 A1B2C3D4E5F6... (Alice <alice@example.com>)
```

Each line shows the tool name, algorithm, key fingerprint, and user ID.

**Options:**

| | CLI | Maven |
|---|---|---|
| Select profile | `--profile hybrid` | `-Dsigmund.profile=hybrid` |
| Explicit config | `--config path/to/sigmund.yaml` | `-Dsigmund.trustConfig=path/to/sigmund.yaml` |

When `--profile` is specified, only the tools matching that profile are shown. Without it, the default profile is used (or all configured tools if no default profile is set).

This is useful for verifying your setup before a release, debugging CI signing configuration, or confirming that a config file is being loaded correctly.

## Signing with Existing GPG Keys

The simplest path if you already have GPG keys. If you have a single GPG secret key (or a `default-key` set in `gpg.conf`), no configuration is needed — Sigmund uses it automatically:

```bash
mvn sigmund:sign
```

```bash
sigmund sign --file artifact.jar
```

**Key resolution order:**

1. `key-name` in `sigmund.yaml` (explicit override)
2. `default-key` in `gpg.conf` (`$GNUPGHOME/gpg.conf` or `~/.gnupg/gpg.conf`)
3. First secret key in the GPG keyring

To override the default, set `key-name` in `sigmund.yaml`:

```yaml
signing:
  tools:
    gpg:
      key-name: your@email.com
```

## Signing with Bouncy Castle

The BC backend requires no external tools and works on any JVM.

### Key Generation

Generate a signing key using BC:

```bash
sigmund keygen \
  --tool bc \
  --userid "Your Name <you@example.com>" \
  --cipher-suite ed25519
```

Output:

```
BC key generated successfully!

Fingerprint: D62AAB339E45E5EA2FD036872B01D46A517A2991ABCDEF1234567890ABCDEF12
Key is passphrase-protected (from SIGMUND_BC_PASSPHRASE).

Use this fingerprint with the 'sign' command.
```

**Supported cipher suites:**

Classic algorithms:

- `ed25519` — EdDSA with Ed25519 curve (default)
- `ed448` — EdDSA with Ed448 curve
- `rsa4096` — RSA with 4096-bit modulus
- `nistp256` — ECDSA with P-256 curve
- `nistp384` — ECDSA with P-384 curve
- `nistp521` — ECDSA with P-521 curve

Note: BC generates v6 keys for Ed25519, Ed448, and RSA using Bouncy Castle 1.85's `BcOpenPGPApi`. ECDSA keys (P-256, P-384, P-521) use a JCA-based fallback and produce v4 keys.

### Passphrase Protection

BC private keys can be encrypted at rest using AES-256 AEAD (OCB mode) with Argon2 S2K key derivation. This protects against filesystem-level exposure (stolen disk, backup leak, compromised server). It does not protect key material in memory — once decrypted for signing, the private key lives on the Java heap and cannot be pinned or zeroed by the JVM.

**Generating a passphrase-protected key:**

```bash
# Interactive — prompts for passphrase with confirmation
sigmund keygen --tool bc \
  --userid "Alice <alice@example.com>" \
  --cipher-suite ed25519

# Non-interactive — reads from SIGMUND_BC_PASSPHRASE by default
SIGMUND_BC_PASSPHRASE=mysecret sigmund keygen --tool bc \
  --userid "Alice <alice@example.com>"

# Non-interactive — custom env var
MY_PASSPHRASE=mysecret sigmund keygen --tool bc \
  --userid "Alice <alice@example.com>" \
  --passphrase-env MY_PASSPHRASE
```

**Signing with a passphrase-protected key:**

Set the `SIGMUND_BC_PASSPHRASE` environment variable before signing:

```bash
export SIGMUND_BC_PASSPHRASE=mysecret
mvn sigmund:sign
```

If the environment variable is not set, Sigmund prompts interactively when a terminal is available. If neither is available, signing fails for encrypted keys.

To use a different environment variable name (e.g., to reuse an existing CI secret), set `passphrase-env` in `sigmund.yaml`:

```yaml
signing:
  tools:
    bc:
      signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
      passphrase-env: MY_KEY_PASSPHRASE
```

### Passphrase Resolution Order

When signing with BC, the passphrase is resolved in this order:

1. **Programmatic `PassphraseProvider`** via `Sigmund.Builder.bcPassphraseProvider()` (API use only)
2. **Environment variable** — `SIGMUND_BC_PASSPHRASE` by default, or the variable named in the `passphrase-env` setting
3. **Interactive console prompt** — if a terminal is available
4. **No passphrase** — works only for unencrypted keys

Unencrypted keys continue to work without a passphrase. Private key files in `bc-private/` are created with owner-only (600) file permissions on POSIX systems.

## Ephemeral CI Signing

For ephemeral CI runners (containers, VMs that are destroyed after each build), you can inject the BC signing key directly from a CI secret — no key files on disk, no `keygen` step on the runner.

**One-time setup:** Export your signing key in ASCII-armored format and store it as a CI secret:

```bash
sigmund keygen --tool bc --userid "CI <ci@example.com>"
# Copy the key file from ~/.local/share/openpgp-cert-d/bc-private/<fingerprint>
# Or export with GPG: gpg --export-secret-keys --armor <fingerprint>
# Store the armored content as a CI secret named SIGMUND_BC_SIGNING_KEY
```

**On each CI run:** Set the environment variable and sign:

```bash
export SIGMUND_BC_SIGNING_KEY="$CI_SECRET"
export SIGMUND_BC_PASSPHRASE="$CI_PASSPHRASE"
mvn sigmund:sign
```

Sigmund checks `SIGMUND_BC_SIGNING_KEY` by default. The key is parsed in memory and never written to disk. No `sigmund.yaml` configuration is needed for this to work.

To use a different env var name, set `signing-key-env` in `sigmund.yaml`:

```yaml
signing:
  tools:
    bc:
      signing-key-env: MY_SIGNING_KEY
```

**Priority:** `tsk-file` takes precedence over `signing-key-env` if both are configured.

## Hybrid PQC Signing

Hybrid signing combines a classic signature (GPG or BC) with a post-quantum signature (Sequoia sq) in one `.asc` file. This provides quantum resistance while maintaining backward compatibility.

### Prerequisites

**Sequoia sq 1.4.0+ with PQC support** is required for hybrid signing.

Verify your installation:

```bash
sq version
# Must show 1.4.0 or later

sq key generate --help | grep mldsa
# Must show mldsa87-ed448 in the cipher-suite options
```

### Installing Sequoia sq

**From crates.io (recommended):**

```bash
# 1. Install build dependencies

# Fedora / RHEL:
sudo dnf install \
  cargo rust gcc clang-devel openssl-devel sqlite-devel \
  pkg-config nettle-devel capnproto

# Debian / Ubuntu:
sudo apt install \
  cargo rustc gcc clang libssl-dev libsqlite3-dev \
  pkg-config libnettle-dev capnproto
```

Required packages and why:

- `openssl-devel` / `libssl-dev` — the build links against OpenSSL and needs `openssl.pc` for pkg-config
- `sqlite-devel` / `libsqlite3-dev` — required for the Sequoia keystore (`libsqlite3` linkage)
- `gcc` — the C compiler (`cc`) is needed to compile bundled C dependencies like `bzip2-sys`

```bash
# 2. Install sq 1.4.0 with PQC support
cargo install sequoia-sq@1.4.0 --features crypto-openssl --no-default-features
```

**Troubleshooting:**

- **`Disk quota exceeded` during build** — The build produces ~2 GB of intermediate artifacts. If `/tmp` has a quota, redirect the temp and target directories:
  ```bash
  mkdir -p ~/tmp-build
  TMPDIR=~/tmp-build CARGO_TARGET_DIR=~/cargo-sq-build \
    cargo install sequoia-sq@1.4.0 --features crypto-openssl --no-default-features
  ```
  Clean up after installation: `rm -rf ~/tmp-build ~/cargo-sq-build`

- **`Could not find directory of OpenSSL installation`** — Install `openssl-devel` (Fedora) or `libssl-dev` (Debian).

- **`cannot find -lsqlite3`** — Install `sqlite-devel` (Fedora) or `libsqlite3-dev` (Debian).

- **`cc failed with exit status 1`** — Check that `gcc` is installed (`which cc`).

**On RHEL 10.1+**, a PQC-enabled Sequoia package is available as a system package.

### Generating a PQC Key

```bash
sigmund keygen --userid "Your Name <you@example.com>"
# Uses default cipher suite: mldsa87-ed448
```

The default cipher suite `mldsa87-ed448` is a hybrid composite of ML-DSA-87 (post-quantum) and Ed448 (classical). This provides quantum resistance while maintaining classical security.

Output:

```
Key generated successfully!

Fingerprint: D62AAB339E45E5EA2FD036872B01D46A517A2991ABCDEF1234567890ABCDEF12
Stored in:   /home/user/.local/share/sequoia

Use this fingerprint with the 'sign' command.
```

### Signing with PQC

Configure the PQC key fingerprint in `sigmund.yaml`:

```yaml
signing:
  tools:
    sq:
      signing-fingerprint: "D62AAB339E45E5EA2FD036872B01D46A517A2991..."
```

Then sign with the CLI or Maven plugin:

```bash
sigmund sign --file artifact.jar
```

```bash
mvn sigmund:sign
```

This produces a hybrid `.asc` file containing both a classic signature (from GPG or BC) and a PQC signature (from sq).

### PQC Signature Sizes

With the default `mldsa87-ed448` cipher suite, the PQC signature adds approximately:

| Component | ML-DSA-87 (default) | ML-DSA-65 | Ed25519/Ed448 (comparison) |
|-----------|---------------------|-----------|----------------------------|
| Public key | ~2,592 bytes | ~1,952 bytes | 114 bytes (Ed448) / 64 bytes (Ed25519) |
| Private key | ~4,896 bytes | ~4,032 bytes | N/A |
| Signature | ~4,627 bytes | ~3,309 bytes | 114 bytes (Ed448) / 64 bytes (Ed25519) |

**Per artifact:** ~4.6 KB for ML-DSA-87, ~3.3 KB for ML-DSA-65

**Typical Maven module** (JAR, POM, sources, javadoc): ~18 KB for ML-DSA-87, ~13 KB for ML-DSA-65

## Signing Profiles

Profiles select which signature types to include in the `.asc` file. Configure profiles in `sigmund.yaml`:

```yaml
signing:
  profiles:
    classic:
      - openpgp4
    v6-only:
      - openpgp6
    hybrid:
      - openpgp4
      - openpgp6
  default-profile: hybrid
```

**Available profiles:**

- **`classic`** — OpenPGP v4 signatures only (GPG-compatible, no PQC)
- **`v6-only`** — OpenPGP v6 signatures only (BC v6 or sq, may not be GPG-compatible)
- **`hybrid`** — Both OpenPGP v4 and v6 signatures (maximum compatibility + PQC)

The `default-profile` setting determines which profile is used when no profile is explicitly specified. If omitted, all available credential types are used.

Use `sigmund:signing-info` (Maven) or `sigmund signing-info` (CLI) to see which tools and keys are active for a given profile:

```bash
mvn sigmund:signing-info -Dsigmund.profile=hybrid
```

## Signing Pipeline

The signing pipeline combines signatures from multiple tools into a single `.asc` file:

```
artifact.jar
    |
    +-- Classic tool (BC or GPG)
    |   |
    |   +-- bc / gpg --detach-sign --> classic.asc
    |       (v4 or v6 signature packet)
    |
    +-- PQC tool (sq, if configured)
    |   |
    |   +-- sq sign --signature-file --> pqc.sig
    |       (v6 PQC signature packet)
    |
    +-- OpenPgpSignatureFormat.combine()
        |
        +-- artifact.jar.asc (combined signatures)
```

**Stage 1 — Classic signature:**

The signing tool (BC by default, or GPG if configured) produces a detached ASCII-armored signature. BC uses Bouncy Castle's `PGPSignatureGenerator` to create the signature in pure Java. GPG invokes the external `gpg` process:

```bash
gpg --batch --yes --armor --detach-sign \
  [--local-user <keyId>] \
  --output <sig> <artifact>
```

The signature version (v4 or v6) is determined by the key version. BC generates v6 signatures for v6 keys and v4 signatures for v4 keys. GPG always produces v4 signatures.

**Stage 2 — PQC signature (optional):**

If PQC signing is configured and `sq` is available, `SqRunner` invokes Sequoia `sq`:

```bash
sq --overwrite sign \
  --signer <fingerprint> \
  --signature-file <sig> <artifact>
```

Sequoia produces a detached ASCII-armored signature containing a v6 OpenPGP signature packet with the configured PQC hybrid cipher suite (ML-DSA-87+Ed448 by default) per RFC 9980.

**Stage 3 — Combine:**

`OpenPgpSignatureFormat` concatenates the signatures into a single `.asc` file as separate armored blocks, classic first. Neither signature is re-armored — each is preserved byte-for-byte as its respective tool produced it. Verifiers that parse only the first armored block (including Maven Central) see only the classic signature and succeed. PQC-aware tools process all blocks.

## Backward Compatibility

Standard GPG can verify hybrid `.asc` files — it reads the classic v4 packet and ignores the PQC v6 packet:

```bash
gpg --verify artifact.jar.asc artifact.jar
```

GPG will print a warning about the unknown v6 packet but still report "Good signature" and exit successfully:

```
gpg: packet(2) with unknown version 6
gpg: Signature made Wed 15 Apr 2026 10:44:00 AM CEST
gpg:                using RSA key 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
gpg: Good signature from "Your Name <you@example.com>" [ultimate]
```

**Note:** GnuPG returns exit code 2 (rather than 0) when it encounters the v6 packet. Tools that strictly check exit codes may interpret this as a failure, but GPG itself reports the signature as valid.

## Maven Central Compatibility

Maven Central's upload validation parses the first armored block in the `.asc` file, verifies the classic signature against public keyservers, and ignores subsequent blocks. The PQC signature is silently skipped. No changes to Maven Central are required.

**Requirements for Maven Central:**

1. The first armored block must be a valid v4 signature (GPG-compatible)
2. The signing key must be available on a public keyserver (e.g., `hkps://keys.openpgp.org`)
3. The signature must be detached (separate `.asc` file, not inline)

Hybrid `.asc` files meet all these requirements — the classic signature is v4 and appears first.
