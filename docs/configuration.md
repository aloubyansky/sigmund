# Configuration Reference

Sigmund uses a `sigmund.yaml` file for configuration. This reference documents every section and setting.

## Contents

- [File Location](#file-location)
- [Complete Example](#complete-example)
- [Section Reference](#section-reference)
  - [version](#version)
  - [signers](#signers)
  - [signing](#signing)
  - [artifacts](#artifacts)
  - [trust](#trust)
  - [unsigned](#unsigned)
  - [policy](#policy)
  - [discovery](#discovery)
- [Tool Settings Tables](#tool-settings-tables)
  - [BC (BouncyCastle)](#bc-bouncycastle)
  - [SQ (Sequoia)](#sq-sequoia)
  - [GPG (GnuPG)](#gpg-gnupg)
- [Common Configuration Patterns](#common-configuration-patterns)
  - [Minimal Verification-Only Config](#minimal-verification-only-config)
  - [CI/CD Signing Config](#cicd-signing-config)
  - [Multi-Tool Hybrid Signing](#multi-tool-hybrid-signing)
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

# Identity registry — define all trusted signers
signers:
  # Full form: organization with multiple members
  apache:
    name: "Apache Software Foundation"
    members:
      - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
  
  # Single-key signer with multiple credential types
  jane:
    name: "Jane Doe"
    openpgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    openpgp6: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    email: "jane@example.com"
  
  # CI/CD identity using OIDC credentials
  github-bot:
    name: "GitHub Actions Bot"
    oidc:
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"
    email: "bot@example.com"
  
  # Minimal form: email-only signer
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

# Artifacts expected to be unsigned
unsigned:
  - "com.internal.*"
  - "com.example:test-utils"

# Policy enforcement rules
policy:
  # Action on untrusted artifacts: "fail" or "warn"
  on-untrusted: fail
  
  # Require all signature types to match the same trusted signer
  require-all-evidence-match: true

# Signing configuration
signing:
  # Which signer identity to sign as (references signers section)
  signer: jane
  
  # Per-tool signing settings
  tools:
    bc:
      signing-fingerprint: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
      passphrase-env: SIGMUND_BC_PASSPHRASE
      cipher-suite: ed25519
    
    sq:
      home: ~/.local/share/sequoia
      signing-fingerprint: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    
    gpg:
      key-name: "0xDEADBEEF"
      home: ~/.gnupg
  
  # Named profiles for different signing scenarios
  profiles:
    classic:
      - openpgp4
    v6-only:
      - openpgp6
    hybrid:
      - openpgp4
      - openpgp6
  
  # Default profile to use when none specified
  default-profile: hybrid

# Discovery and verification settings
discovery:
  # Tool priority order (only listed tools are used if specified)
  tool-priority: [bc, sq, gpg]
  
  # Fetch missing keys from keyservers during verification
  resolve-signers: true
  
  # Persist fetched keys to tool keyrings (vs. in-memory cache)
  import-to-keyring: false
  
  # Keyserver URLs for key discovery
  keyservers:
    - hkps://keys.openpgp.org
  
  # Per-tool verification settings
  tools:
    bc:
      gnupg-home: ~/.gnupg
      cert-d-home: ~/.local/share/openpgp-cert-d
      bc-private-home: ~/.local/share/openpgp-cert-d/bc-private
    
    sq:
      home: ~/.local/share/sequoia
      executable: sq
    
    gpg:
      executable: gpg
      home: ~/.gnupg
```

## Section Reference

### `version`

**Type:** Integer  
**Default:** `1`

The schema version for this configuration file. Currently, only version `1` is defined.

```yaml
version: 1
```

### `signers`

**Type:** Map of signer ID → signer definition  
**Default:** `{}` (empty)

Defines the identity registry of trusted signers. Each signer can be specified in multiple forms:

#### Minimal Form (Email Only)

A simple string value representing an email address.

```yaml
signers:
  jackson-dev: "tatu@fasterxml.com"
```

#### Single-Key Signer

An object with credential fields. At least one credential type must be specified.

```yaml
signers:
  jane:
    name: "Jane Doe"                    # Optional display name
    openpgp4: "ABCD...EF12"              # OpenPGP v4 fingerprint (40 hex chars)
    pgp4: "ABCD...EF12"                  # Alias for openpgp4
    openpgp6: "1234...CDEF"              # OpenPGP v6 fingerprint (64 hex chars)
    pgp6: "1234...CDEF"                  # Alias for openpgp6
    email: "jane@example.com"            # Email address
    oidc:                                # OIDC credential (issuer + subject)
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"
```

**Credential types:**

- **`openpgp4` / `pgp4`** — OpenPGP v4 fingerprint (40 hexadecimal characters). Matched against PGP and Sigstore signatures.
- **`openpgp6` / `pgp6`** — OpenPGP v6 fingerprint (64 hexadecimal characters). Matched against PGP signatures only (v6 keys).
- **`email`** — Email address. Matched case-insensitively against PGP user IDs and Sigstore OIDC subjects (when subject is an email).
- **`oidc`** — OIDC credential with `issuer` and `subject` fields. Both must match exactly (case-sensitive). Required for CI/CD pipelines and service accounts where issuer verification is critical.

**Shorthand aliases:**
- `pgp4` is an alias for `openpgp4`
- `pgp6` is an alias for `openpgp6`

#### Organization with Multiple Members

When a signer represents an organization, use the `members` array to list individual signing keys.

```yaml
signers:
  apache:
    name: "Apache Software Foundation"
    members:
      - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
```

### `signing`

**Type:** Object  
**Default:** No signer, no tools configured

Configures which identity to sign as and per-tool signing settings.

```yaml
signing:
  signer: my-identity        # References a signer from the signers section
  tools:                      # Per-tool settings (see tool tables below)
    bc:
      signing-fingerprint: "ABCD...EF12"
  profiles:                   # Named credential type profiles
    classic:
      - openpgp4
  default-profile: classic    # Default profile to use
```

#### Fields

- **`signer`** (string, optional) — References a signer ID from the `signers` section. This identity will be used for signing operations.
- **`tools`** (map, optional) — Per-tool configuration. Keys are tool names (`bc`, `sq`, `gpg`). Values are tool-specific settings (see tables below).
- **`profiles`** (map, optional) — Named profiles that specify which credential types to use. Keys are profile names, values are arrays of credential type strings (`openpgp4`, `openpgp6`, etc.).
- **`default-profile`** (string, optional) — The default profile to use when none is explicitly specified.

#### Per-Tool Settings

See [Tool Settings Tables](#tool-settings-tables) below.

### `artifacts`

**Type:** Map of group name → array of artifact patterns  
**Default:** `{}` (empty)

Defines named groups of artifact patterns that can be referenced by name in the `trust` and `unsigned` sections. This avoids repeating the same long list of patterns when multiple signers or policies share the same set of artifacts.

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

unsigned:
  - internal-libs               # Expands to both com.internal.* patterns
```

When a key in `trust` or an entry in `unsigned` matches a group name, it is expanded into the group's patterns. If no group matches, the key is treated as a literal artifact pattern.

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

### `unsigned`

**Type:** Array of strings  
**Default:** `[]` (empty)

Lists artifact patterns that are expected to be unsigned. Artifacts matching these patterns will not trigger trust policy violations.

```yaml
unsigned:
  - "com.internal.*"
  - "com.example:test-utils"
```

Pattern syntax is the same as the `trust` section.

### `policy`

**Type:** Object  
**Default:** `on-untrusted: fail`, `require-all-evidence-match: true`

Configures trust policy enforcement rules.

```yaml
policy:
  on-untrusted: fail
  require-all-evidence-match: true
```

#### Fields

- **`on-untrusted`** (string, default: `fail`)
  - `fail` — Reject artifacts that are not trusted or unsigned
  - `warn` — Log a warning but allow the build to continue

- **`require-all-evidence-match`** (boolean, default: `true`)
  - `true` — All signature types on an artifact must match the same trusted signer
  - `false` — Accept the artifact if any signature matches a trusted signer

### `discovery`

**Type:** Object  
**Default:** See fields below

Configures tool initialization, key fetching, and verification behavior.

```yaml
discovery:
  tool-priority: [bc, sq, gpg]
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
  tools:
    bc:
      cert-d-home: /custom/cert-d
```

#### Fields

- **`tool-priority`** (array of strings, default: `[bc, sq, gpg]`)
  
  Lists which tools to use and in what order. When specified, **only** the listed tools are initialized. When omitted, all available tools are initialized in the default order (`bc`, `sq`, `gpg`).
  
  ```yaml
  tool-priority: [bc, sq]  # Use only BC and Sequoia
  ```

- **`resolve-signers`** (boolean, default: `true`)
  
  Whether to fetch missing keys from keyservers to resolve signer identities (names and emails). When `true` and a key is not found locally, tools attempt to fetch it from the configured keyservers. The behavior depends on the tool and `import-to-keyring`:

  | `resolve-signers` | `import-to-keyring` | BC | GPG |
  |---|---|---|---|
  | `false` | any | no fetch | no fetch |
  | `true` | `false` (default) | fetch ephemerally (in-memory, discarded after build) | skip (GPG cannot do ephemeral imports) |
  | `true` | `true` | fetch + persist to cert-d | fetch + persist to GPG keyring |

  When `resolve-signers: true` but no tool in the configured priority can fetch keys (e.g., only GPG with `import-to-keyring: false`), Sigmund logs a warning.

  A per-keyserver circuit breaker prevents slow builds when offline — after the first connection failure to a keyserver, all subsequent fetch attempts to that server are skipped. A per-key negative cache prevents re-querying the same missing key across artifacts.

- **`import-to-keyring`** (boolean, default: `false`)
  
  Controls how fetched keys are stored. Only meaningful when `resolve-signers` is `true`:
  
  - `false` (default) — Keys are cached in memory for the session. BC supports ephemeral key storage; GPG does not, so key fetch is skipped entirely for GPG when this is `false`.
  - `true` — Keys are permanently imported into the tool's keyring (BC cert-d or GPG keyring).
  
  **Note:** `keys.openpgp.org` may serve keys without user IDs. BC can use these for verification, but GPG cannot import them.

- **`keyservers`** (array of strings, default: `[hkps://keys.openpgp.org]`)
  
  Keyserver URLs for fetching missing keys. Defaults to `hkps://keys.openpgp.org` because it verifies email addresses before publishing, preventing impersonation.
  
  ```yaml
  keyservers:
    - hkps://keys.openpgp.org
    - hkps://keyserver.ubuntu.com
  ```

- **`tools`** (map, optional)
  
  Per-tool settings for verification. Keys are tool names (`bc`, `sq`, `gpg`). See [Tool Settings Tables](#tool-settings-tables) below.

## Tool Settings Tables

### BC (BouncyCastle)

Used in both `signing.tools.bc` and `discovery.tools.bc` sections.

| Setting | Default | Description |
|---------|---------|-------------|
| `gnupg-home` | `~/.gnupg` | GnuPG home directory for reading `pubring.gpg` |
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
signing:
  tools:
    bc:
      signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
      passphrase-env: MY_BC_KEY_PASSPHRASE
      cipher-suite: ed448

discovery:
  tools:
    bc:
      gnupg-home: /custom/gnupg
      cert-d-home: /custom/cert-d
```

### SQ (Sequoia)

Used in both `signing.tools.sq` and `discovery.tools.sq` sections.

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
signing:
  tools:
    sq:
      home: ~/.local/share/sequoia
      signing-fingerprint: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"

discovery:
  tools:
    sq:
      executable: /usr/local/bin/sq
```

### GPG (GnuPG)

Used in both `signing.tools.gpg` and `discovery.tools.gpg` sections.

| Setting | Default | Description |
|---------|---------|-------------|
| `executable` | `gpg` | Path to the `gpg` executable (if not on `PATH`) |
| `key-name` | (none) | Key identifier for signing (fingerprint, key ID, or email) |
| `home` | (system default) | GnuPG home directory (`--homedir` option) |
| `passphrase-env` | `SIGMUND_GPG_PASSPHRASE` | Environment variable name containing the passphrase. If not set, falls back to `gpg-agent`. |

**Note:** GPG only supports OpenPGP v4 keys. OpenPGP v6 keys cannot be used with GPG.

**Example:**

```yaml
signing:
  tools:
    gpg:
      key-name: "0xDEADBEEF"
      home: ~/.gnupg

discovery:
  tools:
    gpg:
      executable: /usr/bin/gpg2
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

signers:
  ci-bot:
    oidc:
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"

signing:
  signer: ci-bot
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
    name: "Release Engineering"
    openpgp4: "ABCD...EF12"  # v4 fingerprint for GPG compatibility
    openpgp6: "1234...CDEF"  # v6 fingerprint for PQC

signing:
  signer: release-team
  tools:
    bc:
      signing-fingerprint: "1234...CDEF"  # Use v6 key
      cipher-suite: ed448
    sq:
      signing-fingerprint: "1234...CDEF"
    gpg:
      key-name: "0xABCDEF12"  # Use v4 key
  
  profiles:
    hybrid:
      - openpgp4
      - openpgp6
  
  default-profile: hybrid

discovery:
  tool-priority: [bc, sq, gpg]
```

### Strict Trust Policy

```yaml
version: 1

policy:
  on-untrusted: fail
  require-all-evidence-match: true

discovery:
  resolve-signers: false      # Don't auto-fetch keys
  import-to-keyring: false       # Don't persist fetched keys
```

### Permissive Development Config

```yaml
version: 1

policy:
  on-untrusted: warn             # Warn but don't fail
  require-all-evidence-match: false

unsigned:
  - "com.internal.*"             # Internal artifacts don't need signatures
  - "com.example:*:*-SNAPSHOT"   # Snapshots don't need signatures

discovery:
  resolve-signers: true        # Auto-fetch missing keys
  import-to-keyring: true        # Cache keys permanently
```
