# Sigstore Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Sigstore as a first-class signing/verification backend, including configuration restructuring.

**Architecture:** Two-phase approach. Phase 1 restructures the config model (top-level `tools`, `DiscoveryConfig`, `SignersConfig`, `ArtifactsConfig`, evidence policy split) and updates all consumers. Phase 2 adds the `sigmund-sigstore` module (`SigstoreSignatureFormat`, `SigstoreTool`, `SigstoreToolFactory`) with ServiceLoader discovery and Maven/CLI integration.

**Tech Stack:** Java 17, Maven multi-module, BouncyCastle 1.85, Jackson YAML, sigstore-java, picocli/Quarkus (CLI), JUnit 6.1.2

## Global Constraints

- Java 17 target. No JPMS module-info.
- Use package imports, never FQN in code.
- Add detailed javadoc on all public types and methods.
- Prefer smaller descriptive methods — extract logical steps into named private methods.
- Tests for every change. TDD where practical.
- Update docs in `docs/` when behavior or config schema changes.
- No backward compatibility concerns — break freely.
- Existing test suite must pass after each task (`mvn verify -pl core` / `mvn verify`).

---

### Task 1: New config types — `SignersConfig`, `ArtifactsConfig`, `DiscoveryConfig`

Create the three new config wrapper types. These are standalone — no existing code changes yet.

**Files:**
- Create: `core/src/main/java/dev/cyberstamp/sigmund/core/SignersConfig.java`
- Create: `core/src/main/java/dev/cyberstamp/sigmund/core/ArtifactsConfig.java`
- Create: `core/src/main/java/dev/cyberstamp/sigmund/core/DiscoveryConfig.java`
- Create: `core/src/test/java/dev/cyberstamp/sigmund/core/SignersConfigTest.java`
- Create: `core/src/test/java/dev/cyberstamp/sigmund/core/ArtifactsConfigTest.java`
- Create: `core/src/test/java/dev/cyberstamp/sigmund/core/DiscoveryConfigTest.java`

**Interfaces:**
- Consumes: `SignerIdentity` (existing record in core)
- Produces:
  - `SignersConfig` — `get(String name): SignerIdentity`, `resolve(String name): SignerIdentity` (throws on missing), `names(): Set<String>`, `isEmpty(): boolean`
  - `ArtifactsConfig` — `get(String groupName): List<String>`, `expandPatterns(List<String>): List<String>`, `expandTrustMappings(Map<String, List<String>>): Map<String, List<String>>`, `isEmpty(): boolean`
  - `DiscoveryConfig` — record with `resolveSigners: boolean`, `importToKeyring: boolean`, `keyservers: List<String>`, `toolchain: List<String>`. Static `DEFAULT` constant. `effectiveToolchain(): List<String>` that falls back to `ToolsConfig.DEFAULT_TOOL_PRIORITY` when `toolchain` is null.

- [ ] **Step 1: Write `SignersConfig` tests**

```java
package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SignersConfigTest {

    private static SignerIdentity signer(String id) {
        return new SignerIdentity(id, id, List.of(new EmailCredential(id + "@example.com")));
    }

    @Nested
    class Lookup {
        @Test
        void getReturnsSignerByName() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertNotNull(config.get("alice"));
            assertEquals("alice", config.get("alice").id());
        }

        @Test
        void getReturnsNullForUnknown() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertNull(config.get("bob"));
        }

        @Test
        void resolveReturnsSignerByName() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertEquals("alice", config.resolve("alice").id());
        }

        @Test
        void resolveThrowsForUnknown() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertThrows(PolicyConfigException.class, () -> config.resolve("bob"));
        }

        @Test
        void namesReturnsAllKeys() {
            var config = new SignersConfig(Map.of("alice", signer("alice"), "bob", signer("bob")));
            assertEquals(2, config.names().size());
            assertTrue(config.names().contains("alice"));
        }

        @Test
        void emptyConfig() {
            var config = SignersConfig.EMPTY;
            assertTrue(config.isEmpty());
            assertTrue(config.names().isEmpty());
        }
    }
}
```

- [ ] **Step 2: Implement `SignersConfig`**

```java
package dev.cyberstamp.sigmund.core;

import java.util.Map;
import java.util.Set;

/**
 * Read-only registry of signer identities, parsed from the {@code signers}
 * section of {@code sigmund.yaml}.
 * <p>
 * Provides name-based lookup and a strict {@link #resolve(String)} that
 * throws when a referenced signer is not defined — used by trust policy
 * resolution to fail fast on typos.
 *
 * @see SignerIdentity
 * @see SigmundConfig
 */
public class SignersConfig {

    /** Empty signer registry. */
    public static final SignersConfig EMPTY = new SignersConfig(Map.of());

    private final Map<String, SignerIdentity> signers;

    /**
     * Creates a signer registry from the given map.
     *
     * @param signers signer identities keyed by signer id
     */
    public SignersConfig(Map<String, SignerIdentity> signers) {
        this.signers = signers != null ? Map.copyOf(signers) : Map.of();
    }

    /**
     * Returns the signer with the given name, or {@code null} if not found.
     *
     * @param name the signer name
     * @return the signer identity, or {@code null}
     */
    public SignerIdentity get(String name) {
        return signers.get(name);
    }

    /**
     * Returns the signer with the given name, throwing if not found.
     * <p>
     * Used by trust policy resolution to fail fast on undefined signer references.
     *
     * @param name the signer name
     * @return the signer identity
     * @throws PolicyConfigException if the signer is not defined
     */
    public SignerIdentity resolve(String name) {
        SignerIdentity signer = signers.get(name);
        if (signer == null) {
            throw new PolicyConfigException("Undefined signer: '" + name + "'");
        }
        return signer;
    }

    /**
     * Returns all signer names in this registry.
     *
     * @return an unmodifiable set of signer names
     */
    public Set<String> names() {
        return signers.keySet();
    }

    /**
     * Returns whether this registry is empty.
     *
     * @return {@code true} if no signers are defined
     */
    public boolean isEmpty() {
        return signers.isEmpty();
    }
}
```

- [ ] **Step 3: Write `ArtifactsConfig` tests**

```java
package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ArtifactsConfigTest {

    @Nested
    class GroupExpansion {
        @Test
        void expandsTrustMappingGroupNames() {
            var config = new ArtifactsConfig(Map.of(
                    "apache-stack", List.of("org.apache.maven.*", "org.apache.commons.*")));
            var raw = Map.of("apache-stack", List.of("apache"));
            var expanded = config.expandTrustMappings(raw);
            assertTrue(expanded.containsKey("org.apache.maven.*"));
            assertTrue(expanded.containsKey("org.apache.commons.*"));
            assertFalse(expanded.containsKey("apache-stack"));
        }

        @Test
        void preservesLiteralPatternsWhenNoGroupMatch() {
            var config = new ArtifactsConfig(Map.of());
            var raw = Map.of("com.example:mylib", List.of("alice"));
            var expanded = config.expandTrustMappings(raw);
            assertTrue(expanded.containsKey("com.example:mylib"));
        }

        @Test
        void expandsPatternList() {
            var config = new ArtifactsConfig(Map.of(
                    "internal", List.of("com.internal.*", "com.internal2.*")));
            var expanded = config.expandPatterns(List.of("internal", "com.other.*"));
            assertEquals(3, expanded.size());
            assertTrue(expanded.contains("com.internal.*"));
            assertTrue(expanded.contains("com.other.*"));
        }

        @Test
        void emptyConfig() {
            assertTrue(ArtifactsConfig.EMPTY.isEmpty());
        }
    }
}
```

- [ ] **Step 4: Implement `ArtifactsConfig`**

Encapsulate the group expansion logic currently in `SigmundConfigParser.expandArtifactGroups()` and `expandUnsignedGroups()`.

```java
package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only registry of named artifact pattern groups, parsed from the
 * {@code artifacts} section of {@code sigmund.yaml}.
 * <p>
 * Provides group expansion for the {@code trust} and {@code unsigned} sections —
 * when a key matches a group name, it is expanded into the group's patterns.
 *
 * @see SigmundConfig
 */
public class ArtifactsConfig {

    /** Empty artifact groups. */
    public static final ArtifactsConfig EMPTY = new ArtifactsConfig(Map.of());

    private final Map<String, List<String>> groups;

    /**
     * Creates an artifact group registry from the given map.
     *
     * @param groups group names mapped to lists of artifact patterns
     */
    public ArtifactsConfig(Map<String, List<String>> groups) {
        this.groups = groups != null ? Map.copyOf(groups) : Map.of();
    }

    /**
     * Returns the patterns for the given group name, or {@code null} if not found.
     *
     * @param groupName the group name
     * @return the list of patterns, or {@code null}
     */
    public List<String> get(String groupName) {
        return groups.get(groupName);
    }

    /**
     * Returns whether this registry is empty.
     *
     * @return {@code true} if no groups are defined
     */
    public boolean isEmpty() {
        return groups.isEmpty();
    }

    /**
     * Expands a trust mappings map, replacing group-name keys with their patterns.
     * <p>
     * When a key matches a group name, each pattern in the group gets the
     * key's signer list. Literal pattern keys are preserved unchanged.
     *
     * @param rawTrust the raw trust mappings from the config
     * @return the expanded mappings with group names replaced by patterns
     */
    public Map<String, List<String>> expandTrustMappings(Map<String, List<String>> rawTrust) {
        if (groups.isEmpty()) {
            return rawTrust;
        }
        Map<String, List<String>> expanded = new LinkedHashMap<>();
        for (var entry : rawTrust.entrySet()) {
            List<String> patterns = groups.getOrDefault(entry.getKey(), List.of(entry.getKey()));
            for (String pattern : patterns) {
                expanded.merge(pattern, entry.getValue(), ArtifactsConfig::mergeUnique);
            }
        }
        return expanded;
    }

    /**
     * Expands a list of entries (e.g., unsigned patterns), replacing group names
     * with their patterns. Non-group entries are preserved as-is.
     *
     * @param entries the raw list of group names or literal patterns
     * @return the expanded list with group names replaced
     */
    public List<String> expandPatterns(List<String> entries) {
        if (groups.isEmpty()) {
            return entries;
        }
        List<String> expanded = new ArrayList<>();
        for (String entry : entries) {
            expanded.addAll(groups.getOrDefault(entry, List.of(entry)));
        }
        return expanded;
    }

    private static List<String> mergeUnique(List<String> existing, List<String> incoming) {
        var merged = new ArrayList<>(existing);
        for (String ref : incoming) {
            if (!merged.contains(ref)) {
                merged.add(ref);
            }
        }
        return Collections.unmodifiableList(merged);
    }
}
```

- [ ] **Step 5: Write `DiscoveryConfig` tests**

```java
package dev.cyberstamp.sigmund.core;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DiscoveryConfigTest {

    @Test
    void defaultValues() {
        var config = DiscoveryConfig.DEFAULT;
        assertTrue(config.resolveSigners());
        assertFalse(config.importToKeyring());
        assertEquals(List.of(DiscoveryConfig.DEFAULT_KEYSERVER), config.keyservers());
        assertNull(config.toolchain());
    }

    @Test
    void effectiveToolchainFallsBackToDefault() {
        var config = DiscoveryConfig.DEFAULT;
        assertEquals(DiscoveryConfig.DEFAULT_TOOL_PRIORITY, config.effectiveToolchain());
    }

    @Test
    void effectiveToolchainUsesExplicitList() {
        var config = new DiscoveryConfig(true, false, List.of(), List.of("bc", "sq"));
        assertEquals(List.of("bc", "sq"), config.effectiveToolchain());
    }

    @Test
    void nullKeyserversFallsBackToDefault() {
        var config = new DiscoveryConfig(true, false, null, null);
        assertEquals(List.of(DiscoveryConfig.DEFAULT_KEYSERVER), config.keyservers());
    }
}
```

- [ ] **Step 6: Implement `DiscoveryConfig`**

```java
package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * Configuration for signature discovery and verification operations,
 * parsed from the {@code discovery} section of {@code sigmund.yaml}.
 * <p>
 * Contains operational concerns: key fetching behavior, keyserver URLs,
 * and the verification toolchain. Per-tool settings live in {@link ToolsConfig}.
 *
 * @param resolveSigners whether tools should fetch missing keys to resolve signer identities
 * @param importToKeyring whether to persist fetched keys into the tool's keyring
 * @param keyservers keyserver URLs for key fetching (empty = default)
 * @param toolchain tools to use for verification and their order; {@code null} means all available
 * @see ToolsConfig
 * @see SigmundConfig
 */
public record DiscoveryConfig(
        boolean resolveSigners,
        boolean importToKeyring,
        List<String> keyservers,
        List<String> toolchain) {

    /** Default keyserver. */
    public static final String DEFAULT_KEYSERVER = "hkps://keys.openpgp.org";

    /** Default tool priority order. */
    public static final List<String> DEFAULT_TOOL_PRIORITY = List.of("bc", "sq", "gpg");

    /** Default discovery configuration. */
    public static final DiscoveryConfig DEFAULT = new DiscoveryConfig(
            true, false, List.of(DEFAULT_KEYSERVER), null);

    /**
     * Creates a discovery config with defensive copies.
     */
    public DiscoveryConfig {
        keyservers = keyservers != null && !keyservers.isEmpty()
                ? List.copyOf(keyservers) : List.of(DEFAULT_KEYSERVER);
        toolchain = toolchain != null && !toolchain.isEmpty()
                ? List.copyOf(toolchain) : null;
    }

    /**
     * Returns the toolchain for iteration, falling back to the default order
     * when {@link #toolchain()} is {@code null}.
     *
     * @return the effective toolchain list, never {@code null}
     */
    public List<String> effectiveToolchain() {
        return toolchain != null ? toolchain : DEFAULT_TOOL_PRIORITY;
    }
}
```

- [ ] **Step 7: Run tests**

Run: `mvn test -pl core -Dtest="SignersConfigTest,ArtifactsConfigTest,DiscoveryConfigTest" -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
git add core/src/main/java/dev/cyberstamp/sigmund/core/SignersConfig.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/ArtifactsConfig.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/DiscoveryConfig.java \
        core/src/test/java/dev/cyberstamp/sigmund/core/SignersConfigTest.java \
        core/src/test/java/dev/cyberstamp/sigmund/core/ArtifactsConfigTest.java \
        core/src/test/java/dev/cyberstamp/sigmund/core/DiscoveryConfigTest.java
git commit -m "feat: add SignersConfig, ArtifactsConfig, DiscoveryConfig types"
```

---

### Task 2: Evidence policy enums and `TrustPolicy` update

Replace `requireAllEvidenceMatch()` with `listedEvidence()` and `unlistedEvidence()`.

**Files:**
- Create: `core/src/main/java/dev/cyberstamp/sigmund/core/ListedEvidencePolicy.java`
- Create: `core/src/main/java/dev/cyberstamp/sigmund/core/UnlistedEvidencePolicy.java`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/TrustPolicy.java` — replace `requireAllEvidenceMatch()` with two new methods
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/DefaultTrustPolicy.java` — update constructor and fields
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/TrustVerifier.java:166-173` — update `applyPolicy()` to use new enums
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/TrustVerifierTest.java` — update policy helper and tests
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/SigmundConfigParserTest.java:323-340` — update policy parsing tests
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/SigmundTest.java` — update any policy references
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/VerifyMojo.java:691-706` — update `OverrideTrustPolicy`

**Interfaces:**
- Consumes: `TrustPolicy` (existing), `DefaultTrustPolicy` (existing)
- Produces:
  - `ListedEvidencePolicy` enum — `ALL`, `ANY`
  - `UnlistedEvidencePolicy` enum — `IGNORE`, `WARN`, `REQUIRE`
  - `TrustPolicy.listedEvidence(): ListedEvidencePolicy`
  - `TrustPolicy.unlistedEvidence(): UnlistedEvidencePolicy`

- [ ] **Step 1: Create `ListedEvidencePolicy` and `UnlistedEvidencePolicy` enums**

```java
// ListedEvidencePolicy.java
package dev.cyberstamp.sigmund.core;

/**
 * Controls how evidence for formats listed in a signer's credentials is evaluated.
 * <p>
 * "Listed" evidence is evidence whose format matches a credential type in the
 * expected signer's credential bag (e.g., a {@code .sigstore.json} file is listed
 * evidence when the signer has an {@code oidc} credential).
 */
public enum ListedEvidencePolicy {
    /** All listed evidence must match an expected signer. */
    ALL,
    /** At least one listed evidence match is sufficient. */
    ANY
}
```

```java
// UnlistedEvidencePolicy.java
package dev.cyberstamp.sigmund.core;

/**
 * Controls how evidence for formats not listed in a signer's credentials is handled.
 * <p>
 * "Unlisted" evidence is evidence found for a format that no expected signer has
 * credentials for (e.g., a {@code .sigstore.json} when the signer only has
 * {@code openpgp4} credentials).
 */
public enum UnlistedEvidencePolicy {
    /** Ignore unlisted evidence (don't probe unless no listed evidence found). */
    IGNORE,
    /** Probe all formats and log warnings for unlisted evidence. */
    WARN,
    /** Probe all formats and require unlisted evidence to match. */
    REQUIRE
}
```

- [ ] **Step 2: Update `TrustPolicy` interface**

Replace `requireAllEvidenceMatch()` with:

```java
/**
 * Returns the policy for evaluating listed evidence.
 *
 * @return the listed evidence policy
 * @see ListedEvidencePolicy
 */
ListedEvidencePolicy listedEvidence();

/**
 * Returns the policy for handling unlisted evidence.
 *
 * @return the unlisted evidence policy
 * @see UnlistedEvidencePolicy
 */
UnlistedEvidencePolicy unlistedEvidence();
```

- [ ] **Step 3: Update `DefaultTrustPolicy`**

Replace `boolean requireAllEvidenceMatch` field with `ListedEvidencePolicy listedEvidence` and `UnlistedEvidencePolicy unlistedEvidence`. Update constructor, `EMPTY` constant, and implement new interface methods.

- [ ] **Step 4: Update `TrustVerifier.applyPolicy()` (line 166)**

```java
private TrustVerdict applyPolicy(List<MatchedEvidence> matched, List<EvidenceResult> unmatched) {
    if (matched.isEmpty()) {
        return TrustVerdict.UNTRUSTED;
    }
    if (policy.listedEvidence() == ListedEvidencePolicy.ALL && !unmatched.isEmpty()) {
        return TrustVerdict.UNTRUSTED;
    }
    return TrustVerdict.TRUSTED;
}
```

- [ ] **Step 5: Update `VerifyMojo.OverrideTrustPolicy` (line 691)**

Replace `requireAllEvidenceMatch` with `listedEvidence` and `unlistedEvidence` in the override record. Update `applyPolicyOverrides()` to map the existing `verifyAllSignatures` parameter to `ListedEvidencePolicy`.

- [ ] **Step 6: Update all tests**

Update `TrustVerifierTest.policyFor()` helper (line 211) to use `ListedEvidencePolicy` instead of `boolean`. Update `SigmundConfigParserTest` policy tests. Update `SigmundTest` if it references `requireAllEvidenceMatch`. Update `DefaultTrustPolicyTest` if it exists.

- [ ] **Step 7: Run full core and plugin tests**

Run: `mvn test -pl core,maven-plugin -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
git add core/src/main/java/dev/cyberstamp/sigmund/core/ListedEvidencePolicy.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/UnlistedEvidencePolicy.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/TrustPolicy.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/DefaultTrustPolicy.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/TrustVerifier.java \
        maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/VerifyMojo.java
git add core/src/test/ maven-plugin/src/test/
git commit -m "feat: replace requireAllEvidenceMatch with listed/unlisted evidence policies"
```

---

### Task 3: Restructure `ToolsConfig` and `SigningConfig`

Transform `ToolsConfig` from a record holding discovery settings into a read-only tool registry. Update `SigningConfig` to use `toolchain` instead of `tools` map.

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/ToolsConfig.java` — rewrite as tool registry
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SigningConfig.java` — `tools` → `toolchain`
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/ToolsConfigTest.java` — rewrite tests
- Create: `core/src/test/java/dev/cyberstamp/sigmund/core/SigningConfigTest.java`

**Interfaces:**
- Consumes: `ToolConfig` (existing, unchanged)
- Produces:
  - `ToolsConfig` — `get(String name): ToolConfig`, `toolNames(): Set<String>`, `isEmpty(): boolean`, `size(): int`, static `EMPTY` constant
  - `SigningConfig` — record with `signer: String`, `toolchain: List<String>`, `profiles: Map<String, List<String>>`, `defaultProfile: String`

- [ ] **Step 1: Write `ToolsConfig` tests**

```java
package dev.cyberstamp.sigmund.core;

import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ToolsConfigTest {

    @Test
    void getReturnsTool() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(null, Map.of("key", "val"))));
        assertNotNull(tc.get("bc"));
        assertEquals("val", tc.get("bc").settings().get("key"));
    }

    @Test
    void getReturnsNullForUnknown() {
        var tc = ToolsConfig.EMPTY;
        assertNull(tc.get("bc"));
    }

    @Test
    void toolNamesReturnsAllKeys() {
        var tc = new ToolsConfig(Map.of(
                "bc", new ToolConfig(null, Map.of()),
                "sq", new ToolConfig(null, Map.of())));
        assertEquals(2, tc.toolNames().size());
        assertTrue(tc.toolNames().contains("bc"));
        assertTrue(tc.toolNames().contains("sq"));
    }

    @Test
    void emptyConfig() {
        assertTrue(ToolsConfig.EMPTY.isEmpty());
        assertEquals(0, ToolsConfig.EMPTY.size());
    }
}
```

- [ ] **Step 2: Rewrite `ToolsConfig`**

Replace the current record (which holds `resolveSigners`, `importToKeyring`, `keyservers`, `tools`, `toolPriority`) with a read-only tool registry class. Move the constants `DEFAULT_KEYSERVER` and `DEFAULT_TOOL_PRIORITY` to `DiscoveryConfig`. Move `parseKeyserversSetting()` to `DiscoveryConfig`.

```java
package dev.cyberstamp.sigmund.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Read-only registry of per-tool configurations, parsed from the top-level
 * {@code tools} section of {@code sigmund.yaml}.
 * <p>
 * Each entry maps a tool name to its {@link ToolConfig} containing credentials
 * and settings. The registry is ordered by insertion (YAML declaration order).
 *
 * @see ToolConfig
 * @see SigmundConfig
 */
public class ToolsConfig {

    /** Empty tool registry. */
    public static final ToolsConfig EMPTY = new ToolsConfig(Map.of());

    private final Map<String, ToolConfig> tools;

    /**
     * Creates a tool registry from the given map.
     *
     * @param tools tool configurations keyed by tool name
     */
    public ToolsConfig(Map<String, ToolConfig> tools) {
        this.tools = tools != null
                ? new LinkedHashMap<>(tools)
                : new LinkedHashMap<>();
    }

    /**
     * Returns the configuration for the given tool, or {@code null} if not registered.
     *
     * @param toolName the tool name
     * @return the tool configuration, or {@code null}
     */
    public ToolConfig get(String toolName) {
        return tools.get(toolName);
    }

    /**
     * Returns all registered tool names.
     *
     * @return an unmodifiable set of tool names
     */
    public Set<String> toolNames() {
        return Set.copyOf(tools.keySet());
    }

    /**
     * Returns whether this registry is empty.
     *
     * @return {@code true} if no tools are registered
     */
    public boolean isEmpty() {
        return tools.isEmpty();
    }

    /**
     * Returns the number of registered tools.
     *
     * @return the number of tools
     */
    public int size() {
        return tools.size();
    }
}
```

- [ ] **Step 3: Update `SigningConfig`**

Replace `tools: Map<String, ToolConfig>` with `toolchain: List<String>`:

```java
public record SigningConfig(
        String signer,
        List<String> toolchain,
        Map<String, List<String>> profiles,
        String defaultProfile) {

    public static final SigningConfig DEFAULT = new SigningConfig(null, List.of(), Map.of(), null);

    public SigningConfig {
        toolchain = toolchain != null ? List.copyOf(toolchain) : List.of();
        profiles = profiles != null ? Map.copyOf(profiles) : Map.of();
    }
}
```

- [ ] **Step 4: Run tests — expect compilation failures**

At this point, many consumers of the old `ToolsConfig` and `SigningConfig` APIs will fail to compile. This is expected — the next task updates all consumers.

- [ ] **Step 5: Commit work-in-progress**

```bash
git add core/src/main/java/dev/cyberstamp/sigmund/core/ToolsConfig.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/SigningConfig.java \
        core/src/test/java/dev/cyberstamp/sigmund/core/ToolsConfigTest.java
git commit -m "feat: restructure ToolsConfig as tool registry, SigningConfig with toolchain list"
```

---

### Task 4: Update `SigmundConfig`, parser, and all consumers

Wire the new config types through `SigmundConfig`, update the parser, and fix all compilation failures from Task 3.

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SigmundConfig.java` — new record fields
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SigmundConfigParser.java` — parse new schema
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/Sigmund.java` — builder reads from new config types
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/Signer.java:126-147` — `SignedFile` gains `fileExtension`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SignedFile.java` — add `fileExtension` field
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/AbstractSigmundMojo.java` — use new config types
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/AbstractSigningMojo.java` — use new config types
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/VerifyMojo.java` — use new config types
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/SignatureInspector.java` — use new config types
- Modify: `cli/src/main/java/dev/cyberstamp/sigmund/cli/SigningSupport.java` — use new config types
- Modify: `cli/src/main/java/dev/cyberstamp/sigmund/cli/SignCommand.java` — handle multiple output files
- Modify: `cli/src/main/java/dev/cyberstamp/sigmund/cli/VerifySignatureCommand.java` — use new config types
- Modify: all existing tests that reference old config shapes
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/SigmundConfigParserTest.java` — update for new YAML schema

**Interfaces:**
- Consumes: `SignersConfig`, `ArtifactsConfig`, `DiscoveryConfig`, `ToolsConfig` (all from Tasks 1, 3), `ListedEvidencePolicy`, `UnlistedEvidencePolicy` (Task 2)
- Produces:
  - Updated `SigmundConfig` record with new fields
  - `SignedFile` with `fileExtension` field
  - `Sigmund.signatureFileExtensions(): Set<String>`
  - Updated `Sigmund.Builder.config(SigmundConfig)` that reads all new config types

This is the largest task — it's the consumer migration. It cannot be split because all these files must compile together. The implementation approach:

1. Update `SigmundConfig` record
2. Update `SigmundConfigParser` to produce new types
3. Update `Sigmund.Builder` to read from new config types
4. Add `fileExtension` to `SignedFile`, update `Signer`
5. Add `signatureFileExtensions()` to `Sigmund`
6. Fix Maven plugin consumers
7. Fix CLI consumers
8. Update all tests

- [ ] **Step 1: Update `SigmundConfig` record**

```java
public record SigmundConfig(
        int version,
        SignersConfig signers,
        ArtifactsConfig artifacts,
        TrustPolicy trustPolicy,
        SigningConfig signingConfig,
        ToolsConfig toolsConfig,
        DiscoveryConfig discoveryConfig) {

    public SigmundConfig {
        if (signers == null) signers = SignersConfig.EMPTY;
        if (artifacts == null) artifacts = ArtifactsConfig.EMPTY;
        if (trustPolicy == null) trustPolicy = DefaultTrustPolicy.EMPTY;
        if (signingConfig == null) signingConfig = SigningConfig.DEFAULT;
        if (toolsConfig == null) toolsConfig = ToolsConfig.EMPTY;
        if (discoveryConfig == null) discoveryConfig = DiscoveryConfig.DEFAULT;
    }
}
```

- [ ] **Step 2: Update `SigmundConfigParser`**

Key changes:
- `parseSigners()` returns `SignersConfig` instead of `Map`
- `parseArtifactGroups()` returns `ArtifactsConfig`
- `parseToolsConfig()` renamed to `parseDiscoveryConfig()`, returns `DiscoveryConfig`
- New `parseToolsRegistry()` method parses the top-level `tools` section into `ToolsConfig`
- `parseSigningConfig()` reads `toolchain` as a string list, not `tools` as a map
- Policy parsing reads `listed-evidence` and `unlisted-evidence` instead of `require-all-evidence-match`
- Trust resolution uses `SignersConfig.resolve()` instead of raw map lookup
- Group expansion delegates to `ArtifactsConfig` methods

- [ ] **Step 3: Update `SignedFile` — add `fileExtension`**

```java
public record SignedFile(
        Path path,
        String toolName,
        String format,
        String algorithm,
        String fileExtension) { }
```

- [ ] **Step 4: Update `Signer.combineAndWrite()` — populate `fileExtension`**

Both code paths in `combineAndWrite()` (combining and non-combining) populate `fileExtension` from `format.fileExtension()`.

- [ ] **Step 5: Add `Sigmund.signatureFileExtensions()`**

```java
public Set<String> signatureFileExtensions() {
    Set<String> extensions = new LinkedHashSet<>();
    for (SignatureFormat format : formats) {
        extensions.add(format.fileExtension());
    }
    return Set.copyOf(extensions);
}
```

- [ ] **Step 6: Update `Sigmund.Builder`**

The builder reads:
- Tool settings from `ToolsConfig` (top-level tools map) via `toolsConfig.get(toolName)`
- Discovery toolchain from `DiscoveryConfig.effectiveToolchain()` instead of `ToolsConfig.effectiveToolPriority()`
- Signing toolchain from `SigningConfig.toolchain()` instead of `SigningConfig.tools().keySet()`
- Make `injectFetchSettings()` conditional — skip for non-OpenPGP factories

The `config(SigmundConfig)` method stores both `toolsConfig` and `discoveryConfig`. The builder holds both as fields.

- [ ] **Step 7: Update Maven plugin classes**

`AbstractSigmundMojo`:
- `resolveToolsConfig()` → `resolveDiscoveryConfig()`, works with `DiscoveryConfig`
- `buildSigmund()` receives both `ToolsConfig` and `DiscoveryConfig`
- `toolOverrides()` merges settings into `ToolsConfig`

`AbstractSigningMojo`:
- `createSigner()` uses `SigningConfig.toolchain()` instead of `SigningConfig.tools()`
- `mergeToolSettings()` reads from `ToolsConfig` instead of `SigningConfig.tools()`

`SignMojo`:
- `collectFilesToSign()` uses `sigmund.signatureFileExtensions()` for exclusion
- `signAndAttach()` iterates `SigningOutput.files()`, uses `SignedFile.fileExtension()`

`VerifyMojo`:
- `OverrideTrustPolicy` uses new `listedEvidence`/`unlistedEvidence` methods
- Discovery config references updated

- [ ] **Step 8: Update CLI classes**

`SigningSupport`:
- Reads toolchain from `SigningConfig.toolchain()` and settings from `ToolsConfig`

`SignCommand`:
- Handle multiple output files from signing
- Error on `--output` when multiple files are produced

`VerifySignatureCommand`:
- Override sq home through `ToolsConfig` instead of the old `ToolsConfig` record

- [ ] **Step 9: Update all parser tests**

`SigmundConfigParserTest`:
- Update YAML snippets to new schema (top-level `tools`, `signing.toolchain`, `discovery` without `tools` subsection)
- Assert on `SignersConfig`, `ArtifactsConfig`, `DiscoveryConfig`, `ToolsConfig` types
- Add tests for `listed-evidence` and `unlisted-evidence` parsing

- [ ] **Step 10: Update `SigmundTest`, `SignerTest`, and other affected tests**

Fix compilation: update mock construction, config creation, and assertions to match the new types.

- [ ] **Step 11: Run full build**

Run: `mvn verify -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass, build succeeds.

- [ ] **Step 12: Commit**

```bash
git add -u
git commit -m "feat: wire new config types through parser, builder, plugin, and CLI"
```

---

### Task 5: Update documentation for new config schema

Update all docs in `docs/` that reference the old config schema.

**Files:**
- Modify: `docs/configuration.md` — rewrite for new schema
- Modify: `docs/getting-started.md` — update example configs
- Modify: `docs/architecture.md` — update config section
- Modify: `docs/verification.md` — update evidence policy docs
- Modify: `docs/trust-verification.md` — update evidence matching docs
- Modify: `docs/signing.md` — update signing config docs
- Modify: `docs/maven-plugin.md` — update plugin config docs
- Modify: `docs/cli-reference.md` — update CLI examples

**Interfaces:**
- Consumes: None (documentation only)
- Produces: Updated documentation reflecting the new config schema

- [ ] **Step 1: Update `docs/configuration.md`**

Rewrite the complete example and section reference:
- Replace `discovery` section docs with separate `tools` (top-level) and `discovery` sections
- Replace `signing.tools` map docs with `signing.toolchain` list
- Replace `policy.require-all-evidence-match` with `listed-evidence`/`unlisted-evidence`
- Update tool settings tables to show settings in the top-level `tools` section
- Update all example YAML snippets

- [ ] **Step 2: Update remaining docs**

Scan each doc file for references to the old config keys (`discovery.tools`, `signing.tools`, `tool-priority`, `require-all-evidence-match`) and update them.

- [ ] **Step 3: Commit**

```bash
git add docs/
git commit -m "docs: update documentation for restructured config schema"
```

---

### Task 6: `SignatureFormat` extension-first detection and `SignatureToolFactory` public API

Prepare the core SPI changes needed for Phase 2.

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SignatureFormat.java` — add default `canHandle()`, new `canHandleByContent()`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/OpenPgpSignatureFormat.java` — rename `canHandle()` to `canHandleByContent()`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SignatureToolFactory.java` — make public, rename `create()` to `createSigning()`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/BcToolFactory.java` — rename `create()` to `createSigning()`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/GpgToolFactory.java` — rename `create()` to `createSigning()`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SqToolFactory.java` — rename `create()` to `createSigning()`
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/Sigmund.java` — use `allFactories()` with ServiceLoader, use `createSigning()`
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/OpenPgpSignatureFormatTest.java` — update if needed
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/ToolFactoryTest.java` — rename `create()` calls

**Interfaces:**
- Consumes: `SignatureFormat` (existing)
- Produces:
  - `SignatureFormat.canHandleByContent(Path): boolean` — new abstract method
  - `SignatureFormat.canHandle(Path): boolean` — default method with extension-first fast path
  - `SignatureToolFactory` made `public`
  - `SignatureToolFactory.createSigning(Credential, Map): SignatureTool` — renamed from `create()`

- [ ] **Step 1: Update `SignatureFormat` interface**

Add `canHandleByContent()` as a new method. Change `canHandle()` from abstract to default with extension-first logic.

- [ ] **Step 2: Update `OpenPgpSignatureFormat`**

Rename `canHandle()` to `canHandleByContent()`. The inherited default `canHandle()` handles extension matching for `.asc`.

- [ ] **Step 3: Make `SignatureToolFactory` public and rename `create()`**

Change visibility from package-private to public. Rename `create(Credential, Map)` to `createSigning(Credential, Map)`. Add default implementation that throws `UnsupportedOperationException`.

- [ ] **Step 4: Update all factory implementations**

Rename `create()` to `createSigning()` in `BcToolFactory`, `GpgToolFactory`, `SqToolFactory`.

- [ ] **Step 5: Update builder to use ServiceLoader and `createSigning()`**

Replace `FACTORIES` with `BUILTIN_FACTORIES` + `allFactories()`. Update all call sites: `createFromFactory()`, `enforceExclusiveSigners()`, `initializeTools()`, `initializeTool()`.

- [ ] **Step 6: Update tests**

Update `ToolFactoryTest` to use `createSigning()`. Update `SigmundTest` if it references factories.

- [ ] **Step 7: Run full core tests**

Run: `mvn test -pl core -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
git add core/src/main/java/dev/cyberstamp/sigmund/core/SignatureFormat.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/OpenPgpSignatureFormat.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/SignatureToolFactory.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/BcToolFactory.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/GpgToolFactory.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/SqToolFactory.java \
        core/src/main/java/dev/cyberstamp/sigmund/core/Sigmund.java
git add core/src/test/
git commit -m "feat: extension-first format detection, public SignatureToolFactory with ServiceLoader"
```

---

### Task 7: `Sigmund` becomes `AutoCloseable`

Add lifecycle management for tools with cleanup needs.

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/Sigmund.java` — implement `AutoCloseable`
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/AbstractSigmundMojo.java` — try-with-resources
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/AbstractSigningMojo.java` — try-with-resources
- Modify: `cli/src/main/java/dev/cyberstamp/sigmund/cli/SignCommand.java` — try-with-resources
- Modify: `cli/src/main/java/dev/cyberstamp/sigmund/cli/VerifySignatureCommand.java` — try-with-resources
- Modify: `core/src/test/java/dev/cyberstamp/sigmund/core/SigmundTest.java` — add AutoCloseable test

**Interfaces:**
- Consumes: `Sigmund` (existing)
- Produces: `Sigmund implements AutoCloseable`, `close()` method

- [ ] **Step 1: Write test for AutoCloseable**

```java
@Test
void closeCallsAutoCloseableTools() throws Exception {
    // Create a mock tool implementing both SignatureTool and AutoCloseable
    // Verify close() is called when Sigmund.close() is invoked
}
```

- [ ] **Step 2: Implement `AutoCloseable` on `Sigmund`**

```java
public class Sigmund implements AutoCloseable {
    // ...existing code...

    @Override
    public void close() {
        for (SignatureTool tool : tools) {
            if (tool instanceof AutoCloseable ac) {
                try {
                    ac.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
```

- [ ] **Step 3: Wrap builder's `build()` with cleanup on failure**

In `build()`, if tool initialization succeeds but a later step fails, close any `AutoCloseable` tools before propagating the exception.

- [ ] **Step 4: Update Maven plugin mojos**

Refactor `AbstractSigmundMojo` and `AbstractSigningMojo` so that `Sigmund` instances are used in try-with-resources blocks.

- [ ] **Step 5: Update CLI commands**

Wrap `Sigmund` usage in try-with-resources in `SignCommand` and `VerifySignatureCommand`.

- [ ] **Step 6: Run full build**

Run: `mvn verify -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add -u
git commit -m "feat: Sigmund implements AutoCloseable for tool lifecycle management"
```

---

### Task 8: `sigmund-sigstore` module — `SigstoreSignatureFormat`

Create the new module and implement the signature format.

**Files:**
- Modify: `pom.xml` (root) — add `sigstore` module, `sigstore-java` dependency management
- Create: `sigstore/pom.xml`
- Create: `sigstore/src/main/java/dev/cyberstamp/sigmund/sigstore/SigstoreSignatureFormat.java`
- Create: `sigstore/src/test/java/dev/cyberstamp/sigmund/sigstore/SigstoreSignatureFormatTest.java`
- Create: test resource files with sample `.sigstore.json` bundles

**Interfaces:**
- Consumes: `SignatureFormat` (core), `SigstoreVerificationUnit` (core)
- Produces:
  - `SigstoreSignatureFormat` — `name()` → `"sigstore"`, `fileExtension()` → `".sigstore.json"`, `canHandleByContent(Path)`, `parse(Path): List<VerificationUnit>`

- [ ] **Step 1: Create module structure**

Add `<module>sigstore</module>` to root `pom.xml`. Create `sigstore/pom.xml` with dependency on `sigmund-core` and `dev.sigstore:sigstore-java`. Create the package directory.

- [ ] **Step 2: Write `SigstoreSignatureFormat` tests**

```java
package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.SigstoreVerificationUnit;
import dev.cyberstamp.sigmund.core.VerificationUnit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class SigstoreSignatureFormatTest {

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    @TempDir
    Path tempDir;

    @Nested
    class Detection {
        @Test
        void canHandleByExtension() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, "{}");
            assertTrue(format.canHandle(file));
        }

        @Test
        void canHandleByContent() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sig");
            Files.writeString(file, "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}");
            assertTrue(format.canHandleByContent(file));
        }

        @Test
        void rejectsNonJsonFile() throws IOException {
            Path file = tempDir.resolve("artifact.jar.asc");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----");
            assertFalse(format.canHandleByContent(file));
        }

        @Test
        void rejectsJsonWithoutMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"key\":\"value\"}");
            assertFalse(format.canHandleByContent(file));
        }
    }

    @Nested
    class Parsing {
        @Test
        void parseReturnsSingleUnit() throws IOException {
            String bundle = "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"content\":\"test\"}";
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, bundle);
            List<VerificationUnit> units = format.parse(file);
            assertEquals(1, units.size());
            assertInstanceOf(SigstoreVerificationUnit.class, units.get(0));
            assertEquals(bundle, ((SigstoreVerificationUnit) units.get(0)).jsonBundle());
        }
    }

    @Test
    void formatProperties() {
        assertEquals("sigstore", format.name());
        assertEquals(".sigstore.json", format.fileExtension());
        assertFalse(format.supportsCombining());
    }
}
```

- [ ] **Step 3: Implement `SigstoreSignatureFormat`**

```java
package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.SignatureFormat;
import dev.cyberstamp.sigmund.core.SigstoreVerificationUnit;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import dev.cyberstamp.sigmund.core.VerificationUnit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Signature format for Sigstore bundles ({@code .sigstore.json}).
 * <p>
 * Each bundle is a standalone JSON file containing the Fulcio certificate,
 * message signature, and Rekor transparency log entry. Unlike OpenPGP where
 * one {@code .asc} file may contain multiple armored blocks, a Sigstore
 * bundle is always a single verifiable unit.
 */
public class SigstoreSignatureFormat implements SignatureFormat {

    /** Format name constant. */
    public static final String FORMAT_SIGSTORE = "sigstore";

    private static final String SIGSTORE_MEDIA_TYPE_PREFIX = "application/vnd.dev.sigstore.bundle";

    @Override
    public String name() {
        return FORMAT_SIGSTORE;
    }

    @Override
    public String fileExtension() {
        return ".sigstore.json";
    }

    @Override
    public boolean canHandleByContent(Path signatureFile) {
        try {
            String content = Files.readString(signatureFile).trim();
            if (!content.startsWith("{")) {
                return false;
            }
            return content.contains("\"mediaType\"") && content.contains(SIGSTORE_MEDIA_TYPE_PREFIX);
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public List<VerificationUnit> parse(Path signatureFile) {
        try {
            String json = Files.readString(signatureFile);
            return List.of(new SigstoreVerificationUnit(json));
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to read Sigstore bundle: " + signatureFile, e);
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `mvn test -pl sigstore -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add sigstore/ pom.xml
git commit -m "feat: add sigmund-sigstore module with SigstoreSignatureFormat"
```

---

### Task 9: `SigstoreVerifyResult` update and `SigstoreTool`

Implement the core Sigstore tool wrapping sigstore-java.

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/sigmund/core/SigstoreVerifyResult.java` — add `subjectType`, override `signerIdentifier()`
- Create: `sigstore/src/main/java/dev/cyberstamp/sigmund/sigstore/SigstoreTool.java`
- Create: `sigstore/src/test/java/dev/cyberstamp/sigmund/sigstore/SigstoreToolTest.java`

**Interfaces:**
- Consumes: `SignatureTool` (core), `SigstoreSignatureFormat` (Task 8), `SigstoreVerificationUnit` (core), `SigstoreVerifyResult` (core), `OidcCredential` (core), `EmailCredential` (core)
- Produces:
  - `SigstoreTool` implementing `SignatureTool` and `AutoCloseable`
  - Updated `SigstoreVerifyResult` with `subjectType` field and `signerIdentifier()` override

- [ ] **Step 1: Update `SigstoreVerifyResult`**

Add `int subjectType` field to the constructor and a getter. Override `signerIdentifier()` to return `signerDisplayName()`.

- [ ] **Step 2: Write `SigstoreTool` unit tests**

Test `extractCredentials()` with mock `SigstoreVerifyResult` objects:
- Email subject (rfc822Name) → produces both `OidcCredential` and `EmailCredential`
- URI subject (uniformResourceIdentifier) → produces only `OidcCredential`
- Failed verification → produces empty credentials
- `canVerify()` dispatches correctly
- `name()`, `isAvailable()`, `signatureFormat()`, `supportedCredentialTypes()`

- [ ] **Step 3: Implement `SigstoreTool`**

The tool wraps sigstore-java's `KeylessSigner` (nullable for verify-only) and `KeylessVerifier`. Implements `SignatureTool` and `AutoCloseable`.

Key methods:
- `sign()` — calls `KeylessSigner.signFile()`, writes bundle JSON, extracts algorithm from certificate
- `verify()` — calls `KeylessVerifier.verify()`, extracts issuer from Fulcio cert OID extensions (V2 then V1), subject from SAN, builds `SigstoreVerifyResult`
- `extractCredentials()` — produces `OidcCredential` and optionally `EmailCredential`
- `close()` — delegates to `KeylessSigner.close()`

Identity extraction helpers:
- `extractIssuer(X509Certificate)` — reads Sigstore OID `1.3.6.1.4.1.57264.1.8` (V2) or `1.3.6.1.4.1.57264.1.1` (V1)
- `extractSubject(X509Certificate)` — reads SAN extension
- `resolveSubjectType(X509Certificate)` — returns `GeneralName` tag value

- [ ] **Step 4: Run tests**

Run: `mvn test -pl core,sigstore -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/cyberstamp/sigmund/core/SigstoreVerifyResult.java \
        sigstore/src/main/java/dev/cyberstamp/sigmund/sigstore/SigstoreTool.java \
        sigstore/src/test/java/dev/cyberstamp/sigmund/sigstore/SigstoreToolTest.java
git commit -m "feat: SigstoreTool wrapping sigstore-java KeylessSigner and KeylessVerifier"
```

---

### Task 10: `SigstoreToolFactory` and ServiceLoader registration

Create the factory and wire up ServiceLoader discovery.

**Files:**
- Create: `sigstore/src/main/java/dev/cyberstamp/sigmund/sigstore/SigstoreToolFactory.java`
- Create: `sigstore/src/main/resources/META-INF/services/dev.cyberstamp.sigmund.core.SignatureToolFactory`
- Create: `sigstore/src/test/java/dev/cyberstamp/sigmund/sigstore/SigstoreToolFactoryTest.java`

**Interfaces:**
- Consumes: `SignatureToolFactory` (core, public from Task 6), `SigstoreTool` (Task 9), `SigstoreSignatureFormat` (Task 8), `OidcCredential` (core)
- Produces:
  - `SigstoreToolFactory` implementing `SignatureToolFactory`
  - `toolName()` → `"sigstore"`
  - `supportedCredentialTypes()` → `Set.of("oidc")`
  - `createSigning(Credential, Map)` → signing-capable `SigstoreTool`
  - `createVerifyOnly(Map)` → verify-only `SigstoreTool`
  - ServiceLoader registration file

- [ ] **Step 1: Write factory tests**

```java
package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.OidcCredential;
import java.util.Map;
import java.util.ServiceLoader;
import dev.cyberstamp.sigmund.core.SignatureToolFactory;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SigstoreToolFactoryTest {

    private final SigstoreToolFactory factory = new SigstoreToolFactory();

    @Test
    void toolName() {
        assertEquals("sigstore", factory.toolName());
    }

    @Test
    void supportedCredentialTypes() {
        assertTrue(factory.supportedCredentialTypes().contains("oidc"));
        assertEquals(1, factory.supportedCredentialTypes().size());
    }

    @Test
    void createVerifyOnlyReturnsNonNull() {
        // Uses staging to avoid production TUF fetch in tests
        var tool = factory.createVerifyOnly(Map.of("staging", "true"));
        assertNotNull(tool);
        assertFalse(tool.canSign());
        assertTrue(tool.isAvailable());
    }

    @Test
    void serviceLoaderDiscoversFactory() {
        var found = ServiceLoader.load(SignatureToolFactory.class)
                .stream()
                .anyMatch(p -> p.get() instanceof SigstoreToolFactory);
        assertTrue(found, "SigstoreToolFactory should be discoverable via ServiceLoader");
    }

    @Test
    void settingsParsing() {
        assertEquals("sigstore", factory.toolName());
        // staging, trusted-root, interactive are parsed from settings map
    }
}
```

- [ ] **Step 2: Implement `SigstoreToolFactory`**

```java
package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.OidcCredential;
import dev.cyberstamp.sigmund.core.SignatureToolFactory;
import dev.cyberstamp.sigmund.core.SignatureTool;
import java.util.Map;
import java.util.Set;

/**
 * Factory for creating {@link SigstoreTool} instances.
 * <p>
 * Discovered via {@link java.util.ServiceLoader} when {@code sigmund-sigstore}
 * is on the classpath. Supports three settings:
 * <ul>
 *   <li>{@code staging} (boolean, default false) — use sigstage.dev</li>
 *   <li>{@code trusted-root} (path) — custom trusted root JSON</li>
 *   <li>{@code interactive} (boolean, default false) — enable browser OIDC flow</li>
 * </ul>
 */
public class SigstoreToolFactory implements SignatureToolFactory {
    // Implementation details per the ADR
}
```

- [ ] **Step 3: Create ServiceLoader registration**

Create `sigstore/src/main/resources/META-INF/services/dev.cyberstamp.sigmund.core.SignatureToolFactory`:
```
dev.cyberstamp.sigmund.sigstore.SigstoreToolFactory
```

- [ ] **Step 4: Run tests**

Run: `mvn test -pl sigstore -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add sigstore/
git commit -m "feat: SigstoreToolFactory with ServiceLoader registration"
```

---

### Task 11: CLI and Maven plugin Sigstore integration

Wire `sigmund-sigstore` into the CLI (bundled) and update Maven plugin for multi-format signing/verification.

**Files:**
- Modify: `cli/pom.xml` — add `sigmund-sigstore` dependency
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/SignMojo.java` — multi-format signing
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/ArtifactFileResolver.java` — multi-extension evidence resolution
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/VerifyMojo.java` — policy-driven evidence resolution
- Modify: `cli/src/main/java/dev/cyberstamp/sigmund/cli/SignCommand.java` — multi-file output handling

**Interfaces:**
- Consumes: `SignedFile.fileExtension()` (Task 4), `Sigmund.signatureFileExtensions()` (Task 4), `SigstoreSignatureFormat` (Task 8)
- Produces: Updated Maven plugin and CLI that handle both `.asc` and `.sigstore.json`

- [ ] **Step 1: Add `sigmund-sigstore` dependency to CLI**

In `cli/pom.xml`, add:
```xml
<dependency>
    <groupId>dev.cyberstamp.sigmund</groupId>
    <artifactId>sigmund-sigstore</artifactId>
</dependency>
```

And add version management in root `pom.xml` `<dependencyManagement>`.

- [ ] **Step 2: Update `SignMojo` for multi-format signing**

Replace the hardcoded `.asc` logic:
- `collectFilesToSign()` — use `signatureFileExtensions()` for exclusion
- `signAndAttach()` — iterate all `output.files()`, attach each with its `fileExtension()`

- [ ] **Step 3: Update `ArtifactFileResolver` for multi-extension evidence**

Add probing for `.sigstore.json` alongside `.asc`. The resolver tries all extensions from the tool chain's registered formats.

- [ ] **Step 4: Update `SignCommand` for multi-file output**

When signing produces multiple files (e.g., both `.asc` and `.sigstore.json`):
- List all produced files in output
- Error on `--output` when multiple files are produced
- Default output path per file uses format extension

- [ ] **Step 5: Run full build with integration tests**

Run: `mvn verify -f /home/aloubyansky/git/sigmund/pom.xml`

Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add cli/pom.xml pom.xml \
        maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/SignMojo.java \
        maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/ArtifactFileResolver.java \
        maven-plugin/src/main/java/dev/cyberstamp/sigmund/plugin/VerifyMojo.java \
        cli/src/main/java/dev/cyberstamp/sigmund/cli/SignCommand.java
git commit -m "feat: CLI and Maven plugin support for Sigstore signing and verification"
```

---

### Task 12: Documentation and AGENTS.md

Update all documentation for Sigstore support and write AGENTS.md.

**Files:**
- Modify: `docs/configuration.md` — add Sigstore tool settings and examples
- Modify: `docs/signing.md` — add Sigstore signing section
- Modify: `docs/verification.md` — add Sigstore verification section
- Modify: `docs/architecture.md` — add Sigstore module to architecture
- Modify: `docs/getting-started.md` — add Sigstore quickstart
- Modify: `docs/maven-plugin.md` — add Sigstore plugin dependency example
- Create: `AGENTS.md` — document collaboration workflow

**Interfaces:**
- Consumes: All completed implementation
- Produces: Updated docs, new AGENTS.md

- [ ] **Step 1: Update docs for Sigstore**

Add Sigstore configuration examples, signing workflow, verification behavior, and the `sigmund-sigstore` module dependency instructions for Maven users.

- [ ] **Step 2: Write `AGENTS.md`**

Document the collaboration patterns used during this implementation:
- Brainstorming → design spec → implementation plan → task-by-task execution cycle
- Code style preferences (small methods, package imports, detailed javadoc, tests)
- Config-to-type mapping convention (YAML section → Java type)
- TDD approach
- Commit granularity

- [ ] **Step 3: Commit**

```bash
git add docs/ AGENTS.md
git commit -m "docs: Sigstore documentation and AGENTS.md"
```
