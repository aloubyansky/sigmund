# Getting Started

This guide walks you through your first experience with Sigmund — discovering who signed your dependencies and enforcing trust policies based on signer identity.

## Contents

- [Prerequisites](#prerequisites)
- [See Who Signed Your Dependencies](#see-who-signed-your-dependencies)
- [Add the Plugin](#add-the-plugin)
- [Generate a Trust Policy](#generate-a-trust-policy)
- [Enforce the Policy](#enforce-the-policy)
- [Update When Dependencies Change](#update-when-dependencies-change)
- [Next Steps](#next-steps)

## Prerequisites

Sigmund requires:

- **JDK 17 or later** — Check with `java -version`
- **Maven 3.9 or later** — Check with `mvn -version`

No external tools are required for this walkthrough. Sigmund includes a pure-Java Bouncy Castle backend that handles classic OpenPGP signature verification without needing `gpg` or `sq` installed.

## See Who Signed Your Dependencies

Run the `dependency-signers` goal on any Maven project to inspect signatures on all its dependencies — no POM changes required:

```bash
mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.1-SNAPSHOT:dependency-signers
```

Sample output:

```
Signer: Alice Developer <alice@example.com>
   PGP4 (RSA): 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
   PGP6 (ML-DSA-65+Ed25519): D62AAB339E45E5EA2FD036872B01D46A517A2991...
     com.example:lib-a:1.0
     com.example:lib-b:2.0

Signer: UNKNOWN (key not in keyring)
   PGP4 (RSA): DEADBEEFDEADBEEFDEADBEEF
     com.other:tool:3.0

UNSIGNED
  com.internal:util:1.0

Summary: All clear: 4 dependencies, 3 PGP4 signature(s), 1 PGP6 signature(s), 2 unique key(s)
PQ coverage: 1/4 dependencies have a post-quantum signature
```

The output groups artifacts by signer. Each signer shows their name/email (if known) and key fingerprints. Classical v4 signatures (RSA, EdDSA) and post-quantum v6 signatures (ML-DSA) are reported separately. Unsigned artifacts appear in their own section.

Sigmund fetches unknown keys from `keys.openpgp.org` by default to resolve signer names and emails. The fetched keys are only kept in memory for the duration of the build and are not persisted to disk.

## Add the Plugin

To use the shorthand `mvn sigmund:<goal>` syntax for the remaining steps, add the plugin to your project's `pom.xml`:

```xml
<pluginManagement>
  <plugins>
    <plugin>
      <groupId>dev.cyberstamp.sigmund</groupId>
      <artifactId>sigmund-maven-plugin</artifactId>
      <version>0.0.1-SNAPSHOT</version>
    </plugin>
  </plugins>
</pluginManagement>
```

## Generate a Trust Policy

Once you've reviewed who signed your dependencies, generate an initial `sigmund.yaml` trust configuration:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.generateTrustConfig=true
```

This creates a `sigmund.yaml` file in your project root based on actual dependency signatures. The generated file contains three sections:

**signers** — Declares known signers with their key fingerprints and email addresses:

```yaml
signers:
  alice-developer:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    pgp6: "D62AAB339E45E5EA2FD036872B01D46A517A2991..."
    email: "alice@example.com"
```

**trust** — Maps artifact patterns to trusted signers:

```yaml
trust:
  com.example:*: alice-developer
  com.other:tool: [signer-2, signer-3]
```

**unsigned** — Lists artifacts allowed to be unsigned:

```yaml
unsigned:
  - com.internal:util
```

Wildcard patterns like `com.example:*` trust all artifacts from a group. Multiple signers can be specified as a YAML array when an artifact is co-signed.

## Enforce the Policy

Run the `verify` goal to enforce the trust policy:

```bash
mvn sigmund:verify
```

**On success**, you'll see output like:

```
Signer: Alice Developer <alice@example.com>
   PGP4: 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
     com.example:lib-a:1.0
     com.example:lib-b:2.0

TRUSTED UNSIGNED
     com.internal:util:1.0

Summary: 3 passed, 1 skipped
```

**When untrusted artifacts are found**, the default behavior is to fail the build:

```
UNTRUSTED
Signer: Bob Malicious <bob@evil.com>
     com.sketchy:malware:1.0

Summary: 2 passed, 1 failed
[ERROR] 1 artifact(s) failed signer verification:
com.sketchy:malware:1.0: untrusted signer
```

The `on-untrusted` setting controls failure behavior. The default is `fail`. Set it to `warn` in `sigmund.yaml` to report issues without failing the build:

```yaml
settings:
  on-untrusted: warn
```

Or override it per-build with `-Dsigmund.onUntrusted=warn`.

## Update When Dependencies Change

When you add or upgrade dependencies, update `sigmund.yaml` to include new signers and artifacts:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.updateTrustConfig=true
```

This appends new entries to the existing `sigmund.yaml` file, preserving all existing content including comments and formatting. New signers are added to the `signers` section, new trust patterns to the `trust` section, and new unsigned artifacts to the `unsigned` section.

Review changes before committing:

```bash
git diff sigmund.yaml
```

This workflow lets you incrementally maintain trust policies as your dependency graph evolves.

## Next Steps

- **[Trust Verification](trust-verification.md)** — Deep dive into trust configuration, wildcard patterns, and policy customization
- **[Signing Guide](signing.md)** — Sign your own artifacts with GPG, Bouncy Castle, or hybrid post-quantum keys
- **[Migrating from maven-gpg-plugin](migrating-from-gpg-plugin.md)** — Drop-in replacement guide for existing GPG workflows
