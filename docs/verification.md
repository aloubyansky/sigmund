# Signature Verification

This guide covers how to verify artifact signatures using Sigmund. Signature verification confirms that an artifact hasn't been tampered with and was signed by a specific key.

**Note:** This is distinct from trust verification, which additionally checks whether the signing key belongs to someone you trust. For trust verification, see [Trust Verification](trust-verification.md).

## Contents

- [Overview](#overview)
- [Verifying with the CLI](#verifying-with-the-cli)
  - [Example Output](#example-output)
  - [CLI Options](#cli-options)
- [Verifying with the Maven Plugin](#verifying-with-the-maven-plugin)
  - [Maven Plugin Properties](#maven-plugin-properties)
- [Verification Modes](#verification-modes)
  - [Strict Mode (Default)](#strict-mode-default)
  - [Lenient Mode](#lenient-mode)
- [Tool Routing](#tool-routing)
  - [How Routing Works](#how-routing-works)
  - [Tool Capabilities](#tool-capabilities)
  - [Verdicts](#verdicts)
- [Sigstore Verification](#sigstore-verification)
  - [Auto-Detection](#auto-detection)
  - [Identity Extraction](#identity-extraction)
  - [Cross-Backend Identity Matching](#cross-backend-identity-matching)
- [Toolchain Configuration](#toolchain-configuration)
  - [Example: Prefer Sequoia](#example-prefer-sequoia)
  - [Example: GPG Only](#example-gpg-only)
- [Key Discovery](#key-discovery)
  - [Key Fetching Configuration](#key-fetching-configuration)
  - [How Key Fetching Works](#how-key-fetching-works)
  - [Keyserver Default](#keyserver-default)
  - [Ephemeral vs Persistent Import](#ephemeral-vs-persistent-import)
  - [Key Fetching Limitations](#key-fetching-limitations)
- [Verification Report Format](#verification-report-format)
  - [Example: All Signatures Pass](#example-all-signatures-pass)
  - [Example: Missing Key](#example-missing-key)
  - [Example: Failed Signature](#example-failed-signature)
- [Troubleshooting](#troubleshooting)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:verify-signature`). This requires adding the plugin to your project's `pluginManagement`:
>
> ```xml
> <pluginManagement>
>   <plugins>
>     <plugin>
>       <groupId>dev.cyberstamp.sigmund</groupId>
>       <artifactId>sigmund-maven-plugin</artifactId>
>       <version>0.0.2</version>
>     </plugin>
>   </plugins>
> </pluginManagement>
> ```
>
> Alternatively, replace `sigmund` with the full plugin coordinates, e.g.:
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:verify-signature`

## Overview

Sigmund verifies signatures by:

1. Detecting the signature format from the file extension (`.asc` for OpenPGP, `.sigstore.json` for Sigstore)
2. Parsing the signature file into verification units
3. Routing each unit to an appropriate verification tool (BC, Sequoia, GPG, or Sigstore)
4. Verifying each signature against the artifact
5. Reporting the results with an overall verdict

For OpenPGP, a single `.asc` file may contain multiple signature blocks — for example, a classical v4 signature followed by a PQC v6 signature. Each block is verified independently.

For Sigstore, the `.sigstore.json` bundle is self-contained with the certificate and transparency log entry.

## Verifying with the CLI

Use the `verify-signature` command to verify a signature file:

```bash
sigmund verify-signature --file artifact.jar --signature artifact.jar.asc
```

### Example Output

```
Signature Verification Report:
  [1] PASS (RSA) [key: 41A21977...]
  [2] PASS (ML-DSA-87+Ed448) [key: D62AAB33...]
  Overall: ALL_PASS
```

Each line shows:
- **Index** — signature block number
- **Verdict** — `PASS`, `FAIL`, `NO_KEY`, or `SKIPPED`
- **Algorithm** — the signature algorithm (e.g., `RSA`, `ML-DSA-87+Ed448`, `Ed25519`)
- **Key ID** — the signing key's fingerprint (when available)
- **Signer** — the signer's display name (when available)

The **Overall** verdict is one of:
- `ALL_PASS` — all signatures passed
- `PASS_WITH_SKIPS` — at least one signature passed, none failed, some were skipped or missing keys
- `PASS_WITH_FAILURES` — at least one signature passed, but some failed
- `NONE_PASSED` — no signatures passed

### CLI Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to verify |
| `--signature` | Yes | — | Signature `.asc` file |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--lenient` | No | `false` | Pass if at least one signature is valid and none failed |

## Verifying with the Maven Plugin

Use the `sigmund:verify-signature` goal to verify a single artifact:

```bash
mvn sigmund:verify-signature \
  -Dfile=artifact.jar \
  -Dsignature=artifact.jar.asc
```

This goal does not require a Maven project — it can be run standalone.

### Maven Plugin Properties

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `file` | Yes | — | Artifact file to verify |
| `signature` | Yes | — | Signature `.asc` file |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.lenient` | No | `false` | Pass if at least one signature is valid and none failed |

## Verification Modes

Sigmund supports two verification modes:

### Strict Mode (Default)

All signature blocks in the `.asc` file must pass for the overall result to be `PASS`. Any `FAIL`, `NO_KEY`, or `SKIPPED` result causes the overall verification to fail.

```bash
sigmund verify-signature --file artifact.jar --signature artifact.jar.asc
```

Use strict mode when you require all signatures to be valid — for example, when verifying a hybrid signature where both classical and PQC signatures must succeed.

### Lenient Mode

At least one signature block must pass, and none may fail. `NO_KEY` and `SKIPPED` results are tolerated as long as at least one signature passed.

```bash
sigmund verify-signature --file artifact.jar --signature artifact.jar.asc --lenient
```

Use lenient mode when you want verification to succeed if any valid signature exists, even if some blocks cannot be verified (e.g., missing keys or unsupported algorithms).

**Maven plugin:**

```bash
mvn sigmund:verify-signature -Dfile=... -Dsignature=... -Dsigmund.lenient=true
```

## Tool Routing

Sigmund supports four verification backends:

| Tool | Availability | Format | v4 Support | v6 Support | PQC Support |
|------|--------------|--------|------------|------------|-------------|
| **BC** | Always (pure Java) | OpenPGP | Yes | Yes (classic algorithms) | Planned |
| **sq** | Optional (requires Sequoia CLI) | OpenPGP | Yes | Yes | Yes (RFC 9980) |
| **gpg** | Optional (requires GnuPG) | OpenPGP | Yes | No | No |
| **sigstore** | Optional (`sigmund-sigstore` module) | Sigstore | N/A | N/A | N/A |

### How Routing Works

When verifying a signature file:

1. **Parse the `.asc` file** into armored blocks
2. **Inspect each block** to extract packet version, algorithm ID, and issuer fingerprint
3. **Try each tool** in priority order
   - Each tool's `canVerify()` method checks whether it can handle the signature
   - If a tool returns `PASS`, it is used immediately
   - If a tool returns `NO_KEY` or `FAIL`, the next tool is tried — a different tool may have the key in its local keyring or support the algorithm
   - If no tool returns `PASS`, the best non-PASS result is kept
4. **Retry with key fetching** if the final result is `NO_KEY` (see [Key Discovery](#key-discovery))

This fallthrough is important because each tool has access to different key stores. For example, BC checks its ephemeral cache and cert-d, GPG reads `pubring.kbx`, and Sequoia reads its own cert store. A key missing from one tool's store may be present in another's.

### Tool Capabilities

**BC (Bouncy Castle)** handles any OpenPGP signature with classical algorithms (RSA, EdDSA, ECDSA). It searches for the signing key in:
- GnuPG pubring (`~/.gnupg/pubring.kbx`)
- Shared certificate directory (`~/.local/share/pgp.cert.d`)
- BC private keystore (in-memory)

BC returns `NO_KEY` if the signing key is not found in any of these locations.

**Sequoia (sq)** handles v5 and v6 signatures, including PQC hybrid signatures (ML-DSA). It looks up the signer's certificate in the Sequoia cert store (`~/.local/share/sequoia/certs`) and verifies using `sq verify --signer-file`.

**GPG** runs `gpg --verify` against the local keyring. It handles v1-v4 signatures. When verifying hybrid signatures containing v6 PQC packets, GPG prints a warning about unknown packets but still reports "Good signature" if the v4 classical signature is valid.

### Verdicts

Each verification tool returns one of these verdicts:

- **`PASS`** — signature is valid
- **`FAIL`** — signature is invalid (tampered artifact or incorrect signature)
- **`NO_KEY`** — signing key not found in any keyring
- **`SKIPPED`** — tool cannot handle this signature (wrong version, unsupported algorithm, or tool unavailable)

## Sigstore Verification

The Sigstore backend verifies `.sigstore.json` bundles using `sigstore-java`'s `KeylessVerifier`. Verification is fully offline after the initial TUF trusted root fetch.

### Auto-Detection

Sigstore signature files are detected by the `.sigstore.json` extension. When verifying dependencies, Sigmund checks for both `.asc` (OpenPGP) and `.sigstore.json` (Sigstore) files alongside each artifact. No configuration is needed to enable Sigstore verification — if the `sigmund-sigstore` module is on the classpath, `.sigstore.json` files are handled automatically.

### Identity Extraction

After a successful Sigstore verification, the tool extracts identity credentials from the Fulcio certificate embedded in the bundle:

- **`SigstoreCredential`** — produced when the certificate contains any Sigstore extension fields (issuer, subject, source-repository-uri, etc.). Matches against `sigstore` credentials in the signer definition.
- **`EmailCredential`** — produced when the certificate subject is an RFC 822 email address (SAN type `rfc822Name`). Matches against `email` credentials in the signer definition.

### Cross-Backend Identity Matching

The `EmailCredential` extracted from Sigstore bundles uses the same matching logic as email credentials from OpenPGP user IDs. This means a signer with an `email` credential can be matched by both OpenPGP and Sigstore evidence:

```yaml
signers:
  release-lead:
    email: "release@example.com"
    openpgp4: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"

trust:
  "com.example.*": release-lead
```

An artifact signed with either OpenPGP (matched via fingerprint or email in the user ID) or Sigstore (matched via email in the Fulcio certificate) will satisfy the trust policy for `release-lead`.

## Toolchain Configuration

You can configure which tools are used and their order in `sigmund.yaml`:

```yaml
discovery:
  toolchain: [bc, sq, gpg]
```

The default toolchain is `[bc, sq, gpg]`:
- BC attempts verification first (zero external dependencies)
- Sequoia is tried if BC cannot verify
- GPG is tried last

**Important:** When `toolchain` is set, only the listed tools are used. Omitted tools are excluded entirely. When `toolchain` is not set, all available tools are initialized in the default order.

### Example: Prefer Sequoia

To prioritize Sequoia for PQC verification:

```yaml
discovery:
  toolchain: [sq, bc, gpg]
```

### Example: GPG Only

To use only GPG:

```yaml
discovery:
  toolchain: [gpg]
```

## Key Discovery

When a signature verification fails with `NO_KEY`, Sigmund can automatically fetch the missing key from a keyserver.

### Key Fetching Configuration

Key fetching is controlled by the `discovery` section in `sigmund.yaml`:

```yaml
discovery:
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

| Setting | Default | Description |
|---------|---------|-------------|
| `resolve-signers` | `true` | Fetch missing keys from keyservers during verification |
| `import-to-keyring` | `false` | Persist fetched keys to tool keyrings. When `false`, BC caches keys in memory for the session only. |
| `keyservers` | `hkps://keys.openpgp.org` | List of keyserver URLs to query |

### How Key Fetching Works

1. All tools return `NO_KEY` for a signature (key not in any local keyring)
2. Sigmund extracts the issuer fingerprint from the signature packet
3. Sigmund queries each keyserver in order until a key is found
4. The key is imported (persistently if `import-to-keyring: true`, or in-memory if `false`)
5. Verification is retried with the newly available key

### Keyserver Default

The default keyserver is `hkps://keys.openpgp.org` because it is the only major keyserver that verifies email addresses before publishing keys. This prevents impersonation via unverified key uploads.

Other keyservers (e.g., `keyserver.ubuntu.com`) accept uploads without identity verification and can be added explicitly if needed.

### Ephemeral vs Persistent Import

**Ephemeral (default):** `import-to-keyring: false`

BC caches fetched keys in memory for the current session. Keys are not written to disk. This is useful for one-off verification without polluting your keyring.

**Note:** GPG cannot import keys ephemerally. When GPG is the primary tool and `import-to-keyring: false`, key fetching is skipped for GPG entirely. Use `import-to-keyring: true` if you want GPG to auto-fetch keys.

**Persistent:** `import-to-keyring: true`

Fetched keys are imported into the tool's keyring and persisted to disk:
- BC imports to `~/.gnupg/pubring.kbx` or shared cert-d
- Sequoia imports to `~/.local/share/sequoia/certs`
- GPG imports to `~/.gnupg/pubring.kbx`

Keys remain available for future verifications.

### Key Fetching Limitations

**keys.openpgp.org** may serve keys without user IDs attached (for privacy). BC can use these keys for verification, but GPG cannot import them. If you rely on GPG and encounter import failures, consider:

1. Using BC as the primary tool (`toolchain: [bc, ...]`)
2. Manually importing the key with `gpg --recv-keys <FINGERPRINT>` from a different keyserver
3. Setting `import-to-keyring: true` and ensuring BC handles the import

## Verification Report Format

The verification report shows the result of each signature block and an overall verdict.

### Example: All Signatures Pass

```
Signature Verification Report:
  [1] PASS (RSA) [key: 41A21977...]
  [2] PASS (ML-DSA-87+Ed448) [key: D62AAB33...]
  Overall: ALL_PASS
```

### Example: Missing Key

```
Signature Verification Report:
  [1] PASS (RSA) [key: 41A21977...]
  [2] NO_KEY (ML-DSA-87+Ed448) [key: D62AAB33...]
  Overall: PASS_WITH_SKIPS
```

In strict mode (default), this fails. In lenient mode (`--lenient`), it passes because at least one signature is valid.

### Example: Failed Signature

```
Signature Verification Report:
  [1] FAIL (RSA) [key: 41A21977...]
  Overall: NONE_PASSED
```

This fails in both strict and lenient modes. Lenient mode requires at least one `PASS` and no `FAIL` results.

## Troubleshooting

### "No signatures found in signature file"

The `.asc` file contains no valid OpenPGP armored blocks. Check that the file:
- Contains `-----BEGIN PGP SIGNATURE-----` and `-----END PGP SIGNATURE-----`
- Was not corrupted during transfer
- Is an actual signature file (not a public key or encrypted message)

### "No public key"

The signing key is not in any keyring. Solutions:

1. **Enable automatic key fetching** (default):
   ```yaml
   discovery:
     resolve-signers: true
   ```

2. **Import the key manually:**
   ```bash
   gpg --recv-keys <FINGERPRINT>
   # or
   sq cert import --cert-file signer-cert.asc
   ```

3. **Use lenient mode** if other signatures are valid:
   ```bash
   sigmund verify-signature --file ... --signature ... --lenient
   ```

### GPG prints "packet with unknown version 6" but succeeds

This is expected when verifying hybrid signatures. GPG processes the v4 classical signature and ignores the v6 PQC signature it doesn't understand. The verification succeeds because the classical signature is valid.

To verify the PQC signature, ensure Sequoia is installed and appears in the toolchain:

```yaml
discovery:
  toolchain: [bc, sq, gpg]
```

### "Bad signature"

The signature is invalid. Possible causes:
- The artifact was modified after signing
- The wrong artifact or signature file was provided
- The signature file is corrupted

Ensure you are verifying the correct artifact against the correct signature file.
