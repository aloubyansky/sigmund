# Sigstore Integration Design

Implements Sigstore as a first-class signing/verification backend in sigmund, including a configuration restructuring to support multi-format signing cleanly.

## Phasing

**Phase 1: Configuration restructuring** — refactor config model, parser, builder, and all consumers to the new centralized config schema. No new features — same behavior, new structure.

**Phase 2: Sigstore module** — add `sigmund-sigstore` module with `SigstoreSignatureFormat`, `SigstoreTool`, `SigstoreToolFactory`, and integrate into Maven plugin and CLI.

## Phase 1: Configuration Restructuring

### Config schema (YAML)

Each top-level YAML section maps 1:1 to a Java type:

| YAML section | Java type | Role |
|---|---|---|
| `tools` | `ToolsConfig` | Read-only sorted map of tool name → `ToolConfig` |
| `signers` | `SignersConfig` | Read-only map of signer name → `SignerIdentity` |
| `artifacts` | `ArtifactsConfig` | Read-only map of group name → pattern list |
| `signing` | `SigningConfig` | Signer reference, toolchain list, profiles |
| `discovery` | `DiscoveryConfig` | Key-fetching settings, verification toolchain |
| `trust` / `unsigned` / `policy` | `TrustPolicy` | Trust mappings, unsigned patterns, evidence policy |

### New YAML structure

```yaml
version: 1

signers:
  alice:
    name: "Alice"
    openpgp4: "ABCD..."
    email: "alice@example.com"
    oidc:
      issuer: "https://accounts.google.com"
      subject: "alice@example.com"

tools:
  bc:
    credentials: [openpgp4]
    signing-fingerprint: "ABCD..."
    gnupg-home: ~/.gnupg
  sq:
    credentials: [openpgp6]
    cipher-suite: mldsa87-ed448
  sigstore:
    staging: false
    trusted-root: "/path/to/root.json"
    interactive: true

signing:
  signer: alice
  toolchain: [bc, sq, sigstore]
  profiles:
    full: [openpgp4, openpgp6, oidc]
    pgp-only: [openpgp4, openpgp6]
  default-profile: full

discovery:
  toolchain: [bc, sq]
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org

artifacts:
  apache-stack:
    - "org.apache.maven.*"
    - "org.apache.commons.*"

trust:
  apache-stack: apache
  "com.example:mylib": alice

unsigned:
  - "com.internal.*"

policy:
  on-untrusted: fail
  listed-evidence: all
  unlisted-evidence: ignore
```

### Config types

**`SigmundConfig`** — top-level record:

```java
public record SigmundConfig(
    int version,
    SignersConfig signers,
    ArtifactsConfig artifacts,
    TrustPolicy trustPolicy,
    SigningConfig signingConfig,
    ToolsConfig toolsConfig,
    DiscoveryConfig discoveryConfig) { ... }
```

**`ToolsConfig`** — read-only sorted map of tool name → `ToolConfig`. Not `Iterable` or `Map`. Provides `get(String name)`, `toolNames()`, and similar minimal accessors as needed.

**`SignersConfig`** — read-only map of signer name → `SignerIdentity`. Owns `resolve(String name)` lookup (currently in `DefaultTrustPolicy.resolveTrustMappings()`).

**`ArtifactsConfig`** — read-only map of group name → pattern list. Owns group expansion logic (currently scattered in the parser).

**`SigningConfig`** — restructured:

```java
public record SigningConfig(
    String signer,
    List<String> toolchain,
    Map<String, List<String>> profiles,
    String defaultProfile) { ... }
```

`tools: Map<String, ToolConfig>` replaced by `toolchain: List<String>` (simple name list).

**`DiscoveryConfig`** — extracted from current `ToolsConfig`:

```java
public record DiscoveryConfig(
    boolean resolveSigners,
    boolean importToKeyring,
    List<String> keyservers,
    List<String> toolchain) { ... }
```

Contains key-fetching operational concerns and verification toolchain. No per-tool settings (those live in `ToolsConfig`).

**`ToolConfig`** — unchanged: `List<String> credentials` + `Map<String, String> settings`.

### Evidence policy

`TrustPolicy.requireAllEvidenceMatch()` replaced by two methods:

- `listedEvidence()` — returns `ListedEvidencePolicy.ALL` or `ListedEvidencePolicy.ANY`
- `unlistedEvidence()` — returns `UnlistedEvidencePolicy.IGNORE`, `WARN`, or `REQUIRE`

`DefaultTrustPolicy` updated accordingly. Enums are new types.

**`listed-evidence: all`** (default) — all evidence for formats listed in the signer's credentials must match. **`any`** — at least one match is sufficient.

**`unlisted-evidence: ignore`** (default) — don't probe for unlisted format extensions (unless no listed evidence found). **`warn`** — probe all, log warnings. **`require`** — probe all, require matches.

### Builder changes

`Sigmund.Builder` updated to:

1. Read tool settings from `ToolsConfig` (top-level `tools` map) instead of `SigningConfig.tools()` and the old `ToolsConfig.tools()`
2. Read signing toolchain from `SigningConfig.toolchain()` instead of `SigningConfig.tools().keySet()`
3. Read discovery toolchain from `DiscoveryConfig.toolchain()` instead of old `ToolsConfig.toolPriority()`
4. Make `injectFetchSettings()` conditional — only inject OpenPGP-specific settings (`resolve-signers`, `import-to-keyring`, `keyservers`) for OpenPGP tool factories, not for Sigstore
5. Keep `isDefaultExclusiveSigner()` mechanism for zero-config CI

### Signing tool routing (first-successful)

When a signer is configured:

1. For each credential type in the signer's bag, iterate factories in toolchain order
2. Skip factories whose `supportedCredentialTypes()` doesn't include the type (fast pre-filter)
3. Check if the tool has explicit `credentials` in `ToolsConfig` — those tools get first shot at their claimed types
4. Call `createSigning(credential, settings)` — returns the tool if the key is available, `null` if not
5. First factory that returns a non-null tool claims the credential type
6. If no factory succeeds, fail with a diagnostic error

### Parser changes

`SigmundConfigParser` updated to:

- Parse top-level `tools` section into `ToolsConfig`
- Parse `discovery` section into `DiscoveryConfig` (no `tools` subsection)
- Parse `signing.toolchain` as a string list (not a map)
- Parse `signers` section into `SignersConfig`
- Parse `artifacts` section into `ArtifactsConfig`
- Parse `policy.listed-evidence` and `policy.unlisted-evidence`
- Drop `policy.require-all-evidence-match`
- Drop `signing.tools` (map with per-tool config)
- Drop `discovery.tools` (per-tool verification settings)
- Drop `discovery.tool-priority` (replaced by `discovery.toolchain`)

## Phase 2: Sigstore Module

### Module structure

New Maven module `sigmund-sigstore`:

- Compile dependency: `dev.sigstore:sigstore-java`
- Registers `SigstoreToolFactory` via `META-INF/services/dev.cyberstamp.sigmund.core.SignatureToolFactory`

Dependency graph:

- `sigmund-cli` → `sigmund-sigstore` → `sigmund-core` (CLI bundles Sigstore)
- `sigmund-maven-plugin` → `sigmund-core` (users add `sigmund-sigstore` as optional plugin dependency)

### SignatureToolFactory becomes public + ServiceLoader-discoverable

```java
public interface SignatureToolFactory { ... }
```

Builder changes:

```java
private static final List<SignatureToolFactory> BUILTIN_FACTORIES = List.of(
    new BcToolFactory(), new GpgToolFactory(), new SqToolFactory());

private List<SignatureToolFactory> allFactories() {
    List<SignatureToolFactory> all = new ArrayList<>(BUILTIN_FACTORIES);
    ServiceLoader.load(SignatureToolFactory.class).forEach(all::add);
    return all;
}
```

All five references to the old `FACTORIES` field use `allFactories()`.

Overlap detection: when a discovered factory's `supportedCredentialTypes()` overlaps with a built-in and no toolchain is configured, the builder fails with a clear error.

### Factory API change

`create(Credential, Map)` renamed to `createSigning(Credential, Map)`. Default implementation throws (not all tools support signing). Returns `null` when the key/credential is not available.

### SignatureFormat changes

`canHandle(Path)` becomes a default method with extension-first fast path:

```java
default boolean canHandle(Path signatureFile) {
    if (signatureFile.getFileName().toString().endsWith(fileExtension())) {
        return true;
    }
    return canHandleByContent(signatureFile);
}

boolean canHandleByContent(Path signatureFile);
```

`OpenPgpSignatureFormat.canHandle()` renamed to `canHandleByContent()`.

### SignedFile gains fileExtension

```java
public record SignedFile(
    Path path,
    String toolName,
    String format,
    String algorithm,
    String fileExtension) { ... }
```

Populated by `Signer` from `SignatureFormat.fileExtension()`.

### Sigmund gains signatureFileExtensions()

Returns the set of file extensions from registered formats (e.g., `[".asc", ".sigstore.json"]`). Used by the Maven plugin for exclusion filters.

### SigstoreSignatureFormat

```
name()          → "sigstore"
fileExtension() → ".sigstore.json"
canHandleByContent(Path) → checks for "mediaType" field starting with
                           "application/vnd.dev.sigstore.bundle"
parse(Path)     → single SigstoreVerificationUnit wrapping the JSON text
supportsCombining() → false
```

### SigstoreTool

Wraps sigstore-java's `KeylessSigner` (nullable) and `KeylessVerifier`. Implements `SignatureTool` and `AutoCloseable`.

```
name()                      → "sigstore"
isAvailable()               → true (pure Java)
canSign()                   → signer != null
signatureFormat()           → SigstoreSignatureFormat instance
supportedCredentialTypes()  → Set.of("oidc")
canVerify(unit)             → unit instanceof SigstoreVerificationUnit
```

**sign()** — calls `KeylessSigner.signFile()`, writes bundle JSON, returns `SignResult` with the certificate's public key algorithm.

**verify()** — calls `KeylessVerifier.verify()`, extracts OIDC issuer from Fulcio certificate extensions (V2 OID first, V1 fallback), subject from SAN, returns `SigstoreVerifyResult` with `subjectType` (GeneralName tag).

**extractCredentials()** — produces `OidcCredential` (issuer + subject) and optionally `EmailCredential` (when subject is rfc822Name). Enables cross-backend identity matching.

**close()** — delegates to `KeylessSigner.close()`.

### SigstoreVerifyResult update

Gains `int subjectType` field (RFC 5280 GeneralName tag: 1 = rfc822Name, 6 = URI). Overrides `signerIdentifier()` to return the OIDC subject.

### SigstoreToolFactory

ServiceLoader-discovered. Settings:

| Setting | Default | Description |
|---|---|---|
| `staging` | `false` | Use sigstage.dev instead of production |
| `trusted-root` | TUF-managed | Path to custom trusted root JSON |
| `interactive` | `false` | Enable browser-based OIDC flow |

`createSigning(credential, settings)` — builds `KeylessSigner`. Configures `allowedOidcIdentities` when an `OidcCredential` is passed. Accepts ambient identity when `null`.

`createVerifyOnly(settings)` — builds only `KeylessVerifier`.

### Sigmund becomes AutoCloseable

```java
public void close() {
    for (SignatureTool tool : tools) {
        if (tool instanceof AutoCloseable ac) {
            try { ac.close(); } catch (Exception ignored) {}
        }
    }
}
```

`Sigmund.Builder.build()` wraps tool initialization in try-catch — closes any `AutoCloseable` tools if construction fails partway.

Maven mojos and CLI commands wrap `Sigmund` in try-with-resources.

### OIDC authentication

Fully delegated to sigstore-java's `OidcClients`:

1. Environment token (`SIGSTORE_ID_TOKEN`)
2. GitHub Actions ambient OIDC
3. Browser flow (only when `interactive: true`)

Default (`interactive: false`) uses only ambient providers. Signing fails with a clear error if none supply a token.

### Maven plugin changes

**SignMojo:**
1. `collectFilesToSign()` — exclusion filter uses `sigmund.signatureFileExtensions()` instead of hardcoded `.asc`
2. `signAndAttach()` — iterates all `SigningOutput.files()`, attaches each with `SignedFile.fileExtension()`
3. No more hardcoded `.asc` in attachment extension

**ArtifactFileResolver:**
- Probes for all signature extensions from registered formats, not just `.asc`
- Evidence resolution is policy-driven based on `listedEvidence`/`unlistedEvidence` settings

**AbstractSigmundMojo / AbstractSigningMojo:**
- Refactored for `Sigmund` as `AutoCloseable` (try-with-resources)
- Builder receives both `ToolsConfig` and `DiscoveryConfig`

### CLI changes

**SignCommand:**
- When signing produces multiple files, all are listed in output
- `--output` flag errors when multiple files are produced

**VerifySignatureCommand:**
- Auto-detects `.sigstore.json` via `SigstoreSignatureFormat.canHandle()` — no flag needed since `sigmund-sigstore` is bundled in the CLI

## What does NOT change

These types are used as-is with no modifications (except `SigstoreVerifyResult` gaining `subjectType`):

- `SigstoreVerificationUnit`
- `OidcCredential`
- `EmailCredential`
- `VerificationUnit` sealed interface (already permits `SigstoreVerificationUnit`)
- `VerifyResult` sealed class (already permits `SigstoreVerifyResult`)
- `SignatureTool` interface
- `Signer` (format grouping and `supportsCombining()` handles Sigstore naturally)
- `TrustVerifier` (credential matching works through `Credential.matches()`)

## Deferred

- `SignerInspection` for Sigstore (Rekor-based identity lookup)
- Pre-flight OIDC identity check (catch mismatches before browser flow)
- Timeout/retry configuration for sigstore-java
- JPMS compatibility
