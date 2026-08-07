ex# Migrating from pgpverify-maven-plugin

This guide helps you migrate from `pgpverify-maven-plugin` (org.simplify4u.plugins) to Sigmund's Maven plugin. Both plugins verify PGP signatures on dependencies and support key-to-artifact mapping, but Sigmund adds identity-based trust policies, Sigstore bundle verification, artifact signing, and post-quantum cryptography.

## Contents

- [Why migrate](#why-migrate)
- [Feature comparison](#feature-comparison)
- [Step-by-step migration](#step-by-step-migration)
  - [1. Replace the plugin](#1-replace-the-plugin)
  - [2. Configuration mapping](#2-configuration-mapping)
  - [3. Migrate the keysMap to sigmund.yaml](#3-migrate-the-keysmap-to-sigmundyaml)
  - [4. Keyserver configuration](#4-keyserver-configuration)
  - [5. Verify the migration](#5-verify-the-migration)
- [What you gain](#what-you-gain)
- [What changes](#what-changes)
- [Next steps](#next-steps)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:verify`). This requires adding the plugin to your project's `pluginManagement`:
>
> ```xml
> <pluginManagement>
>   <plugins>
>     <plugin>
>       <groupId>dev.cyberstamp.sigmund</groupId>
>       <artifactId>sigmund-maven-plugin</artifactId>
>       <version>0.0.1</version>
>     </plugin>
>   </plugins>
> </pluginManagement>
> ```
>
> Alternatively, replace `sigmund` with the full plugin coordinates, e.g.:
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.1:verify`

## Why migrate

Sigmund offers everything `pgpverify-maven-plugin` does for dependency verification, plus:

- **Identity-based trust policies** — trust signers by name, email, and fingerprint rather than mapping raw fingerprints to artifact patterns
- **Sigstore bundle verification** — verify `.sigstore.json` alongside `.asc` signatures
- **Cross-backend identity matching** — a signer's email matches across both OpenPGP UIDs and Sigstore OIDC subjects
- **Artifact signing** — sign your own artifacts with OpenPGP, Sigstore, or both
- **Post-quantum cryptography** — verify and produce ML-DSA hybrid signatures (RFC 9980)
- **Auto-generated trust config** — bootstrap `sigmund.yaml` from your project's actual dependency signatures instead of writing keysMap entries by hand

## Feature comparison

| Feature | pgpverify-maven-plugin | sigmund-maven-plugin |
|---------|----------------------|----------------------|
| PGP signature verification | Yes | Yes |
| Key-to-artifact mapping | Yes (keysMap file) | Yes (sigmund.yaml trust section) |
| Signer identity resolution | By fingerprint only | By name, email, fingerprint, and OIDC identity |
| Sigstore verification | No | Yes (with `sigmund-sigstore` dependency) |
| Artifact signing | No | Yes (OpenPGP + Sigstore) |
| PQC signature verification | No | Yes (v6 ML-DSA) |
| Plugin verification | Yes (`verifyPlugins`) | No |
| Wildcard patterns | Yes (`groupId.*`) | Yes (`groupId.*`, `groupId:*`) |
| Auto-generate trust config | No | Yes (`dependency-signers -DgenerateTrustConfig`) |
| Update trust config | No | Yes (`dependency-signers -DupdateTrustConfig`) |
| Allow unsigned artifacts | Yes (`noSig` in keysMap) | Yes (`unsigned` section in sigmund.yaml) |
| Allow bad signatures | Yes (`badSig` in keysMap) | No |
| Pure Java (no GPG required) | Yes (Bouncy Castle) | Yes (Bouncy Castle) |
| Key caching to disk | Yes (`pgpkeys-cache`) | No (in-memory only, fetched per build) |
| Verification report | Yes (JSON report file) | No |

## Step-by-step migration

### 1. Replace the plugin

**Before (pgpverify-maven-plugin):**

```xml
<plugin>
  <groupId>org.simplify4u.plugins</groupId>
  <artifactId>pgpverify-maven-plugin</artifactId>
  <version>1.19.1</version>
  <executions>
    <execution>
      <goals>
        <goal>check</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

**After (sigmund-maven-plugin):**

```xml
<plugin>
  <groupId>dev.cyberstamp.sigmund</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <version>0.0.1</version>
  <executions>
    <execution>
      <goals>
        <goal>verify</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

The goal name changes from `check` to `verify`.

### 2. Configuration mapping

| pgpverify-maven-plugin | Sigmund equivalent | Notes |
|------------------------|-------------------|-------|
| `keysMapLocation` | `sigmund.yaml` → `trust` section | See [keysMap migration](#3-migrate-the-keysmap-to-sigmundyaml) |
| `pgpKeyServer` | `sigmund.yaml` → `discovery.keyservers` | Default: `hkps://keys.openpgp.org` (verified identities only) |
| `scope` | `-Dsigmund.scope` | Default: `test` in both |
| `skip` | `-Dsigmund.skip` | Same behavior |
| `verifyPomFiles` | `-Dsigmund.verifyPomFiles` | Default: `true` in both |
| `verifySnapshots` | Not configurable | Sigmund verifies all resolved dependencies |
| `verifyPlugins` | Not supported | Sigmund verifies project dependencies, not build plugins |
| `failNoSignature` | `sigmund.yaml` → `policy.on-untrusted: fail` | Default behavior |
| `quiet` | No equivalent | Use Maven's `-q` flag |
| `noSig` (in keysMap) | `sigmund.yaml` → `unsigned` section | Lists artifact patterns allowed to be unsigned |
| `badSig` (in keysMap) | No equivalent | Sigmund does not allow accepting invalid signatures |

### 3. Migrate the keysMap to sigmund.yaml

The keysMap file maps artifact patterns directly to PGP fingerprints. Sigmund introduces a layer of indirection: signers are declared once with their credentials, then referenced by name in trust mappings.

**Before (keysMap):**

```properties
com.example.* = 0x4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
com.other:tool = 0xB2A3CF1E8D4F5A6B7C9D0E1F2A3B4C5D6E7F8A9B, \
                 0xC3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2
org.internal:* = noSig
```

**After (sigmund.yaml):**

```yaml
signers:
  example-team:
    name: "Example Team"
    openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "team@example.com"
  other-signer-1:
    openpgp4: "B2A3CF1E8D4F5A6B7C9D0E1F2A3B4C5D6E7F8A9B"
  other-signer-2:
    openpgp4: "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2"

trust:
  "com.example.*": example-team
  "com.other:tool": [other-signer-1, other-signer-2]

unsigned:
  - "org.internal:*"
```

The signers section lets you attach human-readable names and emails to fingerprints, making trust policies easier to audit and maintain.

**Shortcut: auto-generate from existing signatures.** Instead of manually translating keysMap entries, let Sigmund inspect your dependencies and generate the initial config:

```bash
mvn sigmund:dependency-signers -Dsigmund.generateTrustConfig=true
```

This creates a `sigmund.yaml` based on actual signatures found in your dependencies. Review and commit it.

### 4. Keyserver configuration

`pgpverify-maven-plugin` defaults to three keyservers: `keyserver.ubuntu.com`, `keys.openpgp.org`, and `pgp.mit.edu`.

Sigmund defaults to `keys.openpgp.org` only, which is a verifying keyserver — it only publishes identity information for keys whose owners confirmed their email. This means fewer signer names are visible, but the names you see are verified.

To match the pgpverify-maven-plugin behavior:

```yaml
discovery:
  keyservers:
    - hkps://keys.openpgp.org
    - hkps://keyserver.ubuntu.com
    - hkps://pgp.mit.edu
```

See the [getting started guide](getting-started.md#why-many-signers-appear-as-not-verified) for details on keyserver identity verification.

### 5. Verify the migration

Run verification and compare the results:

```bash
# With pgpverify-maven-plugin (before removing it)
mvn org.simplify4u.plugins:pgpverify-maven-plugin:check

# With sigmund-maven-plugin
mvn sigmund:verify
```

Both should pass for the same set of dependencies. If Sigmund reports untrusted artifacts that pgpverify-maven-plugin accepted, check for:

- **`badSig` entries in your keysMap** — Sigmund does not support accepting invalid signatures
- **Missing signers in sigmund.yaml** — fingerprints in the keysMap that weren't translated to the `signers` section
- **Keyserver differences** — Sigmund's default keyserver may not resolve keys that others do

## What you gain

After migrating, you can:

- **Add Sigstore verification** — add the `sigmund-sigstore` plugin dependency and verify `.sigstore.json` bundles alongside `.asc` signatures
- **Sign your own artifacts** — `mvn sigmund:sign` with GPG, Bouncy Castle, Sigstore, or hybrid PQC
- **Inspect signers** — `mvn sigmund:dependency-signers` shows who signed each dependency with resolved identities
- **Update trust config incrementally** — `mvn sigmund:dependency-signers -Dsigmund.updateTrustConfig=true` appends new entries when dependencies change

## What changes

- **No disk-based key cache** — `pgpverify-maven-plugin` caches keys in `pgpkeys-cache` under the local repository. Sigmund fetches keys per build and holds them in memory only. Builds with many dependencies may see slightly longer verification times on the first run.
- **No plugin verification** — `pgpverify-maven-plugin` can verify build plugins (`verifyPlugins`). Sigmund verifies project dependencies only.
- **No `badSig` equivalent** — `pgpverify-maven-plugin` allows accepting artifacts with invalid signatures. Sigmund treats invalid signatures as verification failures.
- **Different default keyserver** — Sigmund defaults to `keys.openpgp.org` (verified identities only) vs. pgpverify-maven-plugin's three-server default.

## Next steps

- [Getting Started](getting-started.md) — Dependency trust verification walkthrough
- [Trust Verification](trust-verification.md) — Deep dive into trust configuration and policy customization
- [Signing Guide](signing.md) — Sign your own artifacts
- [Migrating from maven-gpg-plugin](migrating-from-gpg-plugin.md) — If you also use maven-gpg-plugin for signing
