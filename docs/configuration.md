# Configuration Reference

Sigmund uses a `sigmund.yaml` file for configuration. This reference documents every section and setting.

## Contents

- [File Location](#file-location)
- [Complete Example](#complete-example)
- [Section Reference](#section-reference)
  - [version](#version)
  - [issuers](#issuers)
  - [signers](#signers)
  - [signing](#signing)
  - [artifacts](#artifacts)
  - [trust](#trust)
  - [signature-optional](#signature-optional)
  - [policy](#policy)
  - [verification](#verification)
  - [tools](#tools)
- [Tool Settings Tables](#tool-settings-tables)
  - [BC (BouncyCastle)](#bc-bouncycastle)
  - [SQ (Sequoia)](#sq-sequoia)
  - [GPG (GnuPG)](#gpg-gnupg)
  - [Sigstore](#sigstore)
- [Common Configuration Patterns](#common-configuration-patterns)
  - [Minimal Verification-Only Config](#minimal-verification-only-config)
  - [CI/CD Signing Config](#cicd-signing-config)
  - [Multi-Tool Hybrid Signing](#multi-tool-hybrid-signing)
  - [Sigstore-Only Signing](#sigstore-only-signing)
  - [Mixed OpenPGP + Sigstore Signing](#mixed-openpgp--sigstore-signing)
  - [Strict Trust Policy](#strict-trust-policy)
  - [Permissive Development Config](#permissive-development-config)

## File Location

Sigmund locates configuration files using the following search order:

1. **Explicit path** — specified via `--config` flag (CLI) or `-Dsigmund.trustConfig` (Maven)
2. **Local config** — `./sigmund.yaml` (current working directory for CLI, `${project.basedir}` for Maven)
3. **User config** — `~/.config/sigmund/sigmund.yaml`

The **first file found wins**. Configuration files are not merged.

## Complete Example

```yaml
# Schema version (optional, defaults to 1)
version: 1

# Issuers trusted to vouch for identities in entries that name none
issuers:
  - keys.openpgp.org
  - https://token.actions.githubusercontent.com

# Identity registry — define all trusted signers
signers:
  # Full form: organization with multiple members
  apache:
    members:
      - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
  
  # Keys already seen, plus an address for keys to come
  jane:
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    pgp6: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    email: "jane@example.com"
  
  # CI/CD identity, attested by a Sigstore certificate
  github-bot:
    identities:
      - source-repository-uri: "https://github.com/myorg/myrepo"
        build-config-uri: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"
  
  # Minimal form: an address, vouched for by a listed issuer
  jackson-dev: "tatu@fasterxml.com"

# Artifact-to-signer trust mappings
trust:
  # Map artifact patterns to signers
  "org.apache.maven.*": apache
  "org.apache.commons.*": apache
  "com.fasterxml.jackson.*": jackson-dev
  "com.example:mylib": jane
  
  # Multiple signers for one pattern
  "io.quarkus.*": [redhat, jboss-community]

# Artifacts that do not require a signature
signature-optional:
  - "com.internal.*"
  - "com.example:test-utils"

# Policy enforcement rules
policy:
  # Action on untrusted artifacts: "fail" or "warn"
  on-untrusted: fail
  
  # Evidence matching for artifacts with multiple signatures
  listed-evidence: all      # 'all' or 'any' - default: all
  unlisted-evidence: ignore # 'ignore', 'warn', or 'require' - default: ignore

# Signing configuration
signing:
  # Which signer identity to sign as (references signers section)
  signer: jane
  
  # Toolchain order for signing operations
  toolchain: [bc, sq, gpg]
  
  # Default credential types to produce (filters which tools are used)
  credential-types: [pgp4, pgp6]
  
  # Named profiles for explicit switching (e.g., --profile classic)
  profiles:
    classic:
      - pgp4

# Verification settings
verification:
  # Toolchain order for verification operations
  toolchain: [bc, sq, gpg]
  
  # Fetch missing keys from keyservers during verification
  resolve-signers: true
  
  # Persist fetched keys to tool keyrings (vs. in-memory cache)
  import-to-keyring: false
  
  # Keyserver URLs for key discovery
  keyservers:
    - hkps://keys.openpgp.org

# Tool-specific settings (used by both signing and discovery)
tools:
  bc:
    # Signing settings
    signing-fingerprint: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    passphrase-env: SIGMUND_BC_PASSPHRASE
    cipher-suite: ed25519
    
    # Verification settings
    gnupg-home: ~/.gnupg
    cert-d-home: ~/.local/share/openpgp-cert-d
    bc-private-home: ~/.local/share/openpgp-cert-d/bc-private
  
  sq:
    # Signing settings
    signing-fingerprint: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    
    # Common settings
    home: ~/.local/share/sequoia
    executable: sq
  
  gpg:
    # Signing settings
    key-name: "0xDEADBEEF"
    
    # Common settings
    executable: gpg
    home: ~/.gnupg
  
  sigstore:
    # Use the Sigstore staging instance (for testing)
    staging: false
    # Custom trusted root file (optional, defaults to TUF-fetched root)
    trusted-root: /path/to/trusted_root.json
    # Allow interactive OIDC browser login (for desktop use)
    interactive: true
```

## Section Reference

### `version`

**Type:** Integer  
**Default:** `1`

The schema version for this configuration file. Currently, only version `1` is defined.

```yaml
version: 1
```

### `issuers`

**Type:** Array of issuer names  
**Default:** `[]` (empty)

The issuers trusted to vouch for identities in signer entries that do not name their own. This is the default grant for identities: a fingerprint needs no issuer, because the signature proves the key, but an email address or a CI workflow is only as good as whoever vouched for it.

```yaml
issuers:
  - keys.openpgp.org
  - https://token.actions.githubusercontent.com
```

Every issuer is an `https://` URL, and its kind is known from it, so it needs no configuration:

- **`https://keys.openpgp.org`** — a directory that publishes an address on a key only after the address owner confirms it. It vouches for `email`. As a known directory it may be written without the scheme, `keys.openpgp.org`.
- **Any other `https://` URL** — an OIDC issuer, proven through a Sigstore (Fulcio) certificate. It vouches for the certificate `subject`, `email` when the subject is an address, and the Fulcio certificate extensions listed under [`identities`](#object-form).

Any other name without `https://` is a config error. Results always record the URL. The list is policy: it cannot be set from the command line, because it decides whether an identity is accepted at all.

An entry may name its own `issuer` instead, which trusts that issuer for that entry only — it does not have to be listed. Listing an issuer makes it vouch for every entry that names none, so trusting an OIDC provider for one bot is better done inline.

### `signers`

**Type:** Map of signer ID → signer definition  
**Default:** `{}` (empty)

Defines the identity registry of trusted signers. Each signer can be specified in multiple forms:

#### Minimal Form (Email Only)

A simple string value: an email address, vouched for by one of the listed [`issuers`](#issuers).

```yaml
signers:
  jackson-dev: "tatu@fasterxml.com"
```

#### Object Form

An object with credential fields. At least one credential must be specified, and unknown keys are errors — an ignored key would silently drop a credential.

```yaml
signers:
  jane:
    pgp4: "ABCD...EF12"                 # OpenPGP v4 fingerprint (40 hex chars)
    pgp6: "1234...CDEF"                 # OpenPGP v6 fingerprint (64 hex chars)
    email: "jane@example.com"           # Address vouched for by a listed issuer
    identities:
      - issuer: "https://token.actions.githubusercontent.com"   # optional; else the list
        source-repository-uri: "https://github.com/org/repo"
```

**Credential types:**

- **`pgp4`** — OpenPGP v4 fingerprint, the full 40 hexadecimal characters. Alias: `openpgp4`.
- **`pgp6`** — OpenPGP v6 fingerprint, the full 64 hexadecimal characters. Alias: `openpgp6`.

  Fingerprints match exactly, ignoring case, against the key that made the signature or the primary key it belongs to. A 64-bit key ID is rejected at load: colliding key IDs can be generated, so a key ID would accept any key that shares it.

- **`email`** — An address, accepted only as vouched for by one of the listed [`issuers`](#issuers). To name the issuer, write it under `identities` instead.

  It matches, ignoring case, an address that a directory served for the signing key, or the address in a Sigstore certificate from that issuer. A user ID on an OpenPGP key is **never** matched on its own: anyone can put any address on a key they generate. When a key is not already pinned by a fingerprint, the directory is asked for the addresses it has verified for that key; if it cannot be reached, the artifact is `INDETERMINATE` (`key-unavailable`), never accepted.

  An address is what lets a policy accept a key the publisher generates later. Its limit is that directory bindings are current state: after a publisher verifies the address for a new key, the directory serves the old key without it, so old signatures can no longer be tied to the address by a verifier that never saw them. Pair addresses with fingerprints — fingerprints for the keys already seen, the address for keys to come. What an address trusts is the directory's verification and the security of the email account.

- **`identities`** — A list of complete identities, each an `issuer` (optional; otherwise the listed [`issuers`](#issuers)) and the attributes that issuer must have attested. Only the attributes you name need to match, and at least one besides `issuer` is required. One signer may carry several, for example the same address from two issuers:

  ```yaml
  identities:
    - issuer: keys.openpgp.org
      email: "alice@example.com"
    - issuer: "https://accounts.google.com"
      email: "alice@example.com"
  ```

  What an entry may name depends on its issuer's kind. A directory attests `email` only. An OIDC issuer attests the certificate `subject`, `email` when the subject is an address, and the Fulcio certificate extensions:
  - `subject` — SAN subject (exact workflow+ref match, changes per release)
  - `source-repository-uri`, `source-repository-ref`, `source-repository-digest`, `source-repository-identifier` — the source repository
  - `source-repository-owner-uri`, `source-repository-owner-identifier` — its owner
  - `source-repository-visibility-at-signing`
  - `build-config-uri`, `build-config-digest` — the build configuration, e.g. the workflow file
  - `build-signer-uri`, `build-signer-digest` — the workflow that signed, when it differs
  - `build-trigger` — build trigger event (e.g., `release`, `push`)
  - `runner-environment` — runner environment (e.g., `github-hosted`)
  - `run-invocation-uri`, `deployment-environment`, `token-subject`

  A misspelled attribute is an error with the nearest known name suggested, never ignored: an ignored attribute would widen the match. So is an attribute the entry's issuers cannot attest, such as `source-repository-uri` from a directory.

  > **Stability versus precision:** `subject` carries the git ref, so it changes with every release. `source-repository-uri` is stable but alone accepts any workflow in the repository, including ones that are not the release pipeline; pair it with `build-config-uri`, and where it matters `build-trigger` and `runner-environment`.

  > **Signing-time vs verification-time matching:** When both `issuer` and `subject` are set and the signer is used for signing (`signing.signer`), the OIDC token is validated at signing time — mismatched identities are rejected before requesting a Fulcio certificate. The other attributes are matched at verification time only.

**Aliases:** `openpgp4` and `openpgp6` are accepted aliases for `pgp4` and `pgp6` respectively.

#### Organization with Multiple Members

When a signer represents an organization, use the `members` array to list individual signing keys.

```yaml
signers:
  apache:
    members:
      - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
```

### `signing`

**Type:** Object  
**Default:** No signer, no toolchain configured

Configures which identity to sign as and the signing toolchain.

```yaml
signing:
  signer: my-identity             # References a signer from the signers section
  toolchain: [bc, sq, gpg]        # Tools to use for signing, in priority order
  credential-types: [pgp4, pgp6]  # Default credential types to produce
  profiles:                       # Named profiles for explicit switching
    classic:
      - pgp4
```

#### Fields

- **`signer`** (string, optional) — References a signer ID from the `signers` section. This identity will be used for signing operations.
- **`toolchain`** (array of strings, optional) — Lists which tools to use for signing and in what order. Only the listed tools are initialized. Tool names: `bc`, `sq`, `gpg`, `sigstore`. Per-tool settings are configured in the top-level `tools` section.
- **`credential-types`** (array of strings, optional) — The default set of credential types to produce. Only tools whose supported credential types intersect this list are used. When omitted, all available signing tools are used. Values: `pgp4`, `pgp6`, `sigstore`.
- **`profiles`** (map, optional) — Named profiles for explicit switching (e.g., `--profile classic`). Each profile maps a name to a list of credential type strings. When a profile is requested by name, it takes precedence over `credential-types`.

### `signature-optional`

**Type:** Array of strings
**Default:** `[]` (empty)

Lists artifact patterns for which a signature is not required. Artifacts matching these patterns will not fail verification when unsigned. If a matching artifact happens to be signed, normal trust policy evaluation applies.

```yaml
signature-optional:
  - "com.internal.*"
  - "com.example:test-utils"
```

Pattern syntax is the same as the `trust` section. Named artifact groups from the `artifacts` section can also be referenced here.

### `artifacts`

**Type:** Map of group name → array of artifact patterns  
**Default:** `{}` (empty)

Defines named groups of artifact patterns that can be referenced by name in the `trust` and `signature-optional` sections. This avoids repeating the same long list of patterns when multiple signers or policies share the same set of artifacts.

```yaml
artifacts:
  apache-stack:
    - "org.apache.maven.*"
    - "org.apache.commons.*"
    - "org.apache.httpcomponents.*"
  internal-libs:
    - "com.internal.platform.*"
    - "com.internal.shared.*"

trust:
  apache-stack: apache          # Expands to all three org.apache.* patterns
  internal-libs: release-team

signature-optional:
  - internal-libs               # Expands to both com.internal.* patterns
```

When a key in `trust` or an entry in `signature-optional` matches a group name, it is expanded into the group's patterns. If no group matches, the key is treated as a literal artifact pattern.

### `trust`

**Type:** Map of artifact pattern → signer reference(s)  
**Default:** `{}` (empty)

Maps artifact coordinate patterns to trusted signer IDs. Patterns support wildcards and Maven coordinate syntax.

```yaml
trust:
  "org.apache.maven.*": apache              # Single signer
  "io.quarkus.*": [redhat, jboss-community] # Multiple signers (array)
  "com.example:mylib": jane                 # Specific artifact
  "com.example:*:1.0.*": jane               # Version wildcards
```

#### Pattern Format

Patterns use Maven coordinate syntax with wildcard support:

- `groupId` — matches all artifacts in the group
- `groupId.*` — matches group and all subgroups (prefix match)
- `groupId:artifactId` — matches specific artifact, all versions
- `groupId:artifactId:version` — matches specific version
- `groupId:artifactId:type:classifier:version` — full coordinates

**Wildcards:** Use `*` to match any value in a coordinate segment.

**Precedence:** When multiple patterns match an artifact, the most specific pattern wins.

#### Signer References

Values can be:
- A single signer ID (string)
- An array of signer IDs (for artifacts signed by multiple parties)

Signer IDs must reference entries from the `signers` section.

### `policy`

**Type:** Object  
**Default:** `on-untrusted: fail`, `listed-evidence: all`, `unlisted-evidence: ignore`

Configures trust policy enforcement rules.

```yaml
policy:
  on-untrusted: fail
  listed-evidence: all
  unlisted-evidence: ignore
```

#### Fields

- **`on-untrusted`** (string, default: `fail`)
  - `fail` — Reject artifacts that are not trusted or unsigned
  - `warn` — Log a warning but allow the build to continue

- **`listed-evidence`** (string, default: `all`)
  
  Controls how to handle signatures from signers listed in the trust configuration:
  - `all` — All signatures must match the expected signer(s) for the artifact
  - `any` — At least one signature must match an expected signer

- **`unlisted-evidence`** (string, default: `ignore`)
  
  Controls how to handle signatures from signers NOT listed in the trust configuration:
  - `ignore` — Unlisted signatures are ignored (trust decision based only on listed signers)
  - `warn` — Log a warning when unlisted signatures are found, but don't fail
  - `require` — Fail if any unlisted signatures are found on the artifact

### `verification`

**Type:** Object
**Default:** See fields below

Configures the verification toolchain, key fetching, and verification behavior.

```yaml
verification:
  toolchain: [bc, sq, gpg]
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

#### Fields

- **`toolchain`** (array of strings, default: `[bc, sq, gpg]`)
  
  Lists which tools to use for verification and in what order. When specified, **only** the listed tools are initialized. When omitted, all available tools are initialized in the default order (`bc`, `sq`, `gpg`). Tool-specific settings are configured in the top-level `tools` section.
  
  ```yaml
  toolchain: [bc, sq]  # Use only BC and Sequoia
  ```

- **`resolve-signers`** (boolean, default: `true`)
  
  Whether to fetch missing keys from keyservers, and to ask directories named in `issuers` for the verified addresses of keys a policy entry needs. When `false`, a signature whose signer can only be established through a directory is `INDETERMINATE` (`key-unavailable`). When `true` and a key is not found locally, tools attempt to fetch it from the configured keyservers. The behavior depends on the tool and `import-to-keyring`:

  | `resolve-signers` | `import-to-keyring` | BC | GPG |
  |---|---|---|---|
  | `false` | any | no fetch | no fetch |
  | `true` | `false` (default) | fetch ephemerally (in-memory, discarded after build) | skip (GPG cannot do ephemeral imports) |
  | `true` | `true` | fetch + persist to cert-d | fetch + persist to GPG keyring |

  When `resolve-signers: true` but no tool in the configured toolchain can fetch keys (e.g., only GPG with `import-to-keyring: false`), Sigmund logs a warning.

  A per-keyserver circuit breaker prevents slow builds when offline — after the first connection failure to a keyserver, all subsequent fetch attempts to that server are skipped. A per-key negative cache prevents re-querying the same missing key across artifacts.

- **`import-to-keyring`** (boolean, default: `false`)
  
  Controls how fetched keys are stored. Only meaningful when `resolve-signers` is `true`:
  
  - `false` (default) — Keys are cached in memory for the session. BC supports ephemeral key storage; GPG does not, so key fetch is skipped entirely for GPG when this is `false`.
  - `true` — Keys are permanently imported into the tool's keyring (BC cert-d or GPG keyring).
  
  **Note:** `keys.openpgp.org` may serve keys without user IDs. BC can use these for verification, but GPG cannot import them.

- **`keyservers`** (array of strings, default: `[hkps://keys.openpgp.org]`)
  
  Keyserver URLs for fetching missing keys. The first keyserver that has a key supplies it, and the result records which one did. Keyservers supply key material only: the signature proves the key whoever served it, and a user ID a keyserver serves never becomes an identity — identities come only from [`issuers`](#issuers). That is why this is safe to change from the command line.
  
  ```yaml
  keyservers:
    - hkps://keys.openpgp.org
    - hkps://keyserver.ubuntu.com
  ```

### `tools`

**Type:** Map of tool name → tool settings  
**Default:** `{}` (empty)

Configures per-tool settings used by both signing and discovery operations. All tool-specific configuration lives here, avoiding duplication between `signing` and `discovery` sections.

```yaml
tools:
  bc:
    signing-fingerprint: "ABCD...EF12"
    passphrase-env: MY_BC_PASSPHRASE
    gnupg-home: ~/.gnupg
    cert-d-home: ~/.local/share/openpgp-cert-d
  
  sq:
    home: ~/.local/share/sequoia
    signing-fingerprint: "1234...CDEF"
    executable: sq
  
  gpg:
    key-name: "0xDEADBEEF"
    home: ~/.gnupg
    executable: gpg
```

#### Fields

Keys are tool names (`bc`, `sq`, `gpg`, `sigstore`). Values are tool-specific settings documented in the [Tool Settings Tables](#tool-settings-tables) below.

Settings configured here are available to both signing and verification operations. For example, `tools.bc.signing-fingerprint` is used by signing operations, while `tools.bc.gnupg-home` is used by verification.

## Tool Settings Tables

### BC (BouncyCastle)

Configured in the top-level `tools.bc` section.

| Setting | Default | Description |
|---------|---------|-------------|
| `gnupg-home` | `~/.gnupg` | GnuPG home directory for reading `pubring.kbx` (or legacy `pubring.gpg`) |
| `cert-d-home` | `~/.local/share/openpgp-cert-d` | Shared OpenPGP cert-d directory for public certificates |
| `bc-private-home` | `<cert-d-home>/bc-private` | BC private key store directory |
| `signing-fingerprint` | (none) | Fingerprint of the key to sign with (40 or 64 hex chars) |
| `tsk-file` | (none) | Path to an exported Transferable Secret Key (TSK) file for signing |
| `signing-key-env` | `SIGMUND_BC_SIGNING_KEY` | Environment variable name containing the ASCII-armored private key. For ephemeral CI runners. |
| `passphrase-env` | `SIGMUND_BC_PASSPHRASE` | Environment variable name containing the passphrase. If not set, falls back to interactive prompt. |
| `cipher-suite` | `ed25519` | Algorithm for key generation (see supported values below) |

**Supported cipher suites (BC):**

Classic algorithms:
- `ed25519` — EdDSA with Curve25519 (default)
- `ed448` — EdDSA with Curve448
- `rsa4096` — RSA with 4096-bit modulus
- `nistp256` — ECDSA with NIST P-256 curve
- `nistp384` — ECDSA with NIST P-384 curve
- `nistp521` — ECDSA with NIST P-521 curve

PQC composite (experimental):
- `mldsa87-ed448` — ML-DSA-87 + Ed448 hybrid
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519 hybrid

**Passphrase resolution order:**

1. Explicit `PassphraseProvider` via API (`Sigmund.Builder.bcPassphraseProvider()`)
2. Environment variable specified by `passphrase-env` setting
3. Interactive console prompt (if a terminal is available)
4. No passphrase (works only for unencrypted keys)

**Example:**

```yaml
tools:
  bc:
    signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    passphrase-env: MY_BC_KEY_PASSPHRASE
    cipher-suite: ed448
    gnupg-home: /custom/gnupg
    cert-d-home: /custom/cert-d
```

### SQ (Sequoia)

Configured in the top-level `tools.sq` section.

| Setting | Default | Description |
|---------|---------|-------------|
| `home` | `~/.local/share/sequoia` | Sequoia home directory for keys and certificates |
| `executable` | `sq` | Path to the `sq` executable (if not on `PATH`) |
| `signing-fingerprint` | (none) | Fingerprint of the key to sign with (64 hex chars for v6 keys) |
| `cipher-suite` | `mldsa87-ed448` | Algorithm for key generation (PQC hybrid suites) |

**Supported cipher suites (SQ):**

Sequoia supports post-quantum cryptography hybrid cipher suites as defined in RFC 9580:
- `mldsa87-ed448` — ML-DSA-87 + Ed448 (default)
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519
- Additional suites supported by `sq key generate --cipher-suite`

**Example:**

```yaml
tools:
  sq:
    home: ~/.local/share/sequoia
    signing-fingerprint: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    executable: /usr/local/bin/sq
```

### GPG (GnuPG)

Configured in the top-level `tools.gpg` section.

| Setting | Default | Description |
|---------|---------|-------------|
| `executable` | `gpg` | Path to the `gpg` executable (if not on `PATH`) |
| `key-name` | (none) | Key identifier for signing (fingerprint, key ID, or email) |
| `home` | (system default) | GnuPG home directory (`--homedir` option) |
| `passphrase-env` | `SIGMUND_GPG_PASSPHRASE` | Environment variable name containing the passphrase. If not set, falls back to `gpg-agent`. |

**Note:** GPG only supports OpenPGP v4 keys. OpenPGP v6 keys cannot be used with GPG.

**Example:**

```yaml
tools:
  gpg:
    key-name: "0xDEADBEEF"
    home: ~/.gnupg
    executable: /usr/bin/gpg2
```

### Sigstore

Configured in the top-level `tools.sigstore` section. Sigstore uses OIDC-based keyless signing via `sigstore-java` — no long-lived keys to manage.

| Setting | Default | Description |
|---------|---------|-------------|
| `staging` | `false` | Use the Sigstore staging instance instead of production. For testing only. |
| `trusted-root` | (none) | Path to a custom `trusted_root.json` file. When omitted, the root is fetched via TUF from the Sigstore public-good instance. |
| `interactive` | `false` | Allow interactive OIDC browser login. When `false`, only ambient credentials are used: the `SIGSTORE_JAVA_ID_TOKEN` environment variable (if set), then GitHub Actions OIDC. Set to `true` for desktop signing. |

The Sigstore tool is pure Java (provided by the `sigmund-sigstore` module) and does not require any external CLI binary. It is ServiceLoader-discovered — adding the module to the classpath is sufficient.

**Credential type:** `sigstore`  
**File extension:** `.sigstore.json`

**Example:**

```yaml
tools:
  sigstore:
    interactive: true
```

## Common Configuration Patterns

### Minimal Verification-Only Config

```yaml
version: 1

signers:
  apache: "dev@apache.org"

trust:
  "org.apache.*": apache
```

### CI/CD Signing Config

```yaml
version: 1

signing:
  toolchain: [bc]

tools:
  bc:
    signing-fingerprint: "ABCD...EF12"
    passphrase-env: CI_SIGNING_KEY_PASSPHRASE
```

### Multi-Tool Hybrid Signing

```yaml
version: 1

signers:
  release-team:
    pgp4: "ABCD...EF12"  # v4 fingerprint for GPG compatibility
    pgp6: "1234...CDEF"  # v6 fingerprint for PQC

signing:
  signer: release-team
  toolchain: [bc, sq, gpg]
  credential-types: [pgp4, pgp6]

verification:
  toolchain: [bc, sq, gpg]

tools:
  bc:
    signing-fingerprint: "1234...CDEF"  # Use v6 key
    cipher-suite: ed448
  
  sq:
    signing-fingerprint: "1234...CDEF"
  
  gpg:
    key-name: "0xABCDEF12"  # Use v4 key
```

### Sigstore-Only Signing

```yaml
version: 1

signing:
  toolchain: [sigstore]
```

No tool settings needed — ambient OIDC credentials from GitHub Actions are used automatically.

To match signed artifacts against a specific Sigstore identity at verification time, add a signer with that identity:

```yaml
version: 1

signers:
  ci-bot:
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/myorg/myrepo"

signing:
  signer: ci-bot
  toolchain: [sigstore]
```

### Mixed OpenPGP + Sigstore Signing

```yaml
version: 1

signers:
  release-lead:
    pgp4: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/myorg/myrepo"

signing:
  signer: release-lead
  toolchain: [bc, sigstore]

verification:
  toolchain: [bc, sigstore]

tools:
  bc:
    signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    passphrase-env: BC_PASSPHRASE
  sigstore:
    trusted-root: /etc/sigmund/trusted_root.json
```

This produces both a `.asc` (OpenPGP) and a `.sigstore.json` (Sigstore bundle) for each artifact. Verifiers accept the `.asc` by the fingerprint and the bundle by the workflow identity.

### Strict Trust Policy

```yaml
version: 1

policy:
  on-untrusted: fail
  listed-evidence: all       # All listed signatures must match
  unlisted-evidence: require # Fail on any unlisted signatures

verification:
  resolve-signers: false     # Don't auto-fetch keys
  import-to-keyring: false   # Don't persist fetched keys
```

### Permissive Development Config

```yaml
version: 1

policy:
  on-untrusted: warn           # Warn but don't fail
  listed-evidence: any         # Any matching signature is sufficient
  unlisted-evidence: ignore    # Ignore unlisted signatures

signature-optional:
  - "com.internal.*"           # Internal artifacts don't need signatures
  - "com.example:*:*-SNAPSHOT" # Snapshots don't need signatures

verification:
  resolve-signers: true        # Auto-fetch missing keys
  import-to-keyring: true      # Cache keys permanently
```
