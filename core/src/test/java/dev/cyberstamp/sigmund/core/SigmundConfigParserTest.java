package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.StringReader;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigmundConfigParserTest {

    private SigmundConfig parse(String yaml) {
        return SigmundConfigParser.parse("<test>", new StringReader(yaml));
    }

    @Nested
    class SignerParsing {

        @Test
        void minimalSignerEmailString() {
            var config = parse("""
                    signers:
                      bob: "bob@example.com"
                    """);
            var bob = config.signers().get("bob");
            assertNotNull(bob);
            assertEquals("bob", bob.displayName());
            assertEquals(1, bob.credentials().size());
            assertInstanceOf(EmailCredential.class, bob.credentials().get(0));
            assertEquals("bob@example.com", ((EmailCredential) bob.credentials().get(0)).email());
        }

        @Test
        void objectSignerWithFingerprints() {
            var config = parse("""
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        openpgp4: "4AEE18F83AFDEB23"
                        openpgp6: "ABCD1234ABCD1234"
                    """);
            var alice = config.signers().get("alice");
            assertEquals("Alice", alice.displayName());
            assertEquals(3, alice.credentials().size());

            var types = alice.credentials().stream().map(Credential::type).toList();
            assertTrue(types.contains("openpgp4"));
            assertTrue(types.contains("openpgp6"));
            assertTrue(types.contains("email"));
        }

        @Test
        void objectSignerWithSigstoreRepoUri() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        name: "CI Pipeline"
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          source-repository-uri: "https://github.com/org/repo"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertEquals("CI Pipeline", ci.displayName());
            assertEquals(1, ci.credentials().size());
            var sc = assertInstanceOf(SigstoreCredential.class, ci.credentials().get(0));
            assertEquals("https://token.actions.githubusercontent.com", sc.issuer());
            assertEquals("https://github.com/org/repo", sc.sourceRepositoryUri());
            assertNull(sc.subject());
        }

        @Test
        void objectSignerWithSigstoreSubject() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          subject: "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0"
                    """);
            var ci = config.signers().get("ci-pipeline");
            var sc = assertInstanceOf(SigstoreCredential.class, ci.credentials().get(0));
            assertEquals("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0",
                    sc.subject());
        }

        @Test
        void sigstoreUnknownFieldThrows() {
            var ex = assertThrows(PolicyConfigException.class, () -> parse("""
                    signers:
                      ci-pipeline:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          oidc-subject: "https://github.com/org/repo"
                    """));
            assertTrue(ex.getMessage().contains("oidc-subject"),
                    "Error should name the unknown field: " + ex.getMessage());
        }

        @Test
        void objectSignerWithSigstoreAllFields() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          source-repository-uri: "https://github.com/org/repo"
                          build-trigger: "release"
                          build-config-uri: "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
                          runner-environment: "github-hosted"
                    """);
            var ci = config.signers().get("ci-pipeline");
            var sc = assertInstanceOf(SigstoreCredential.class, ci.credentials().get(0));
            assertEquals("https://token.actions.githubusercontent.com", sc.issuer());
            assertEquals("https://github.com/org/repo", sc.sourceRepositoryUri());
            assertEquals("release", sc.buildTrigger());
            assertEquals("https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main",
                    sc.buildConfigUri());
            assertEquals("github-hosted", sc.runnerEnvironment());
        }

        @Test
        void pgp4Alias() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23"
                    """);
            var alice = config.signers().get("alice");
            var fp = assertInstanceOf(FingerprintCredential.class, alice.credentials().get(0));
            assertEquals("openpgp4", fp.type());
        }

        @Test
        void pgp6Alias() {
            var config = parse("""
                    signers:
                      alice:
                        pgp6: "ABCD1234ABCD1234"
                    """);
            var fp = assertInstanceOf(FingerprintCredential.class,
                    config.signers().get("alice").credentials().get(0));
            assertEquals("openpgp6", fp.type());
        }

        @Test
        void objectSignerWithEmailAndFingerprint() {
            var config = parse("""
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23"
                    """);
            var alice = config.signers().get("alice");
            assertEquals("Alice", alice.displayName());
            assertTrue(alice.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("alice@example.com")));
        }

        @Test
        void organizationWithMembers() {
            var config = parse("""
                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@maven.apache.org"
                          - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    """);
            var apache = config.signers().get("apache");
            assertEquals("Apache Software Foundation", apache.displayName());
            assertEquals(3, apache.credentials().size());

            var fps = apache.credentials().stream()
                    .filter(c -> c instanceof FingerprintCredential)
                    .map(c -> ((FingerprintCredential) c).fingerprint())
                    .toList();
            assertEquals(2, fps.size());
            assertTrue(fps.contains("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"));
            assertTrue(fps.contains("BBE7232D7991050B54C8EA0ADC08637CA615D22C"));

            assertTrue(apache.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("dev@maven.apache.org")));
        }

        @Test
        void membersWithMultipleCredentialTypes() {
            var config = parse("""
                    signers:
                      team:
                        name: "Release Team"
                        members:
                          - openpgp4: "AAAA1111AAAA1111"
                            openpgp6: "BBBB2222BBBB2222"
                            email: "alice@example.com"
                    """);
            var team = config.signers().get("team");
            assertEquals(3, team.credentials().size());

            var types = team.credentials().stream().map(Credential::type).toList();
            assertTrue(types.contains("openpgp4"));
            assertTrue(types.contains("openpgp6"));
            assertTrue(types.contains("email"));
        }

        @Test
        void topLevelCredentialsCombinedWithMembers() {
            var config = parse("""
                    signers:
                      org:
                        name: "My Org"
                        email: "org@example.com"
                        members:
                          - openpgp4: "CCCC3333CCCC3333"
                    """);
            var org = config.signers().get("org");
            assertEquals(2, org.credentials().size());
            assertTrue(org.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("org@example.com")));
            assertTrue(org.credentials().stream()
                    .anyMatch(c -> c instanceof FingerprintCredential fc
                            && fc.fingerprint().equals("CCCC3333CCCC3333")));
        }

        @Test
        void emptyMembersWithNoTopLevelCredentialsThrows() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    signers:
                      empty-org:
                        name: "Empty Org"
                        members: []
                    """));
        }

        @Test
        void nestedMembersThrows() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    signers:
                      bad-org:
                        name: "Bad Org"
                        members:
                          - openpgp4: "AAAA1111AAAA1111"
                            members:
                              - openpgp4: "BBBB2222BBBB2222"
                    """));
        }

        @Test
        void membersNotArrayThrows() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    signers:
                      bad-org:
                        name: "Bad Org"
                        members: "not-an-array"
                    """));
        }
    }

    @Nested
    class TrustParsing {

        @Test
        void artifactGroupsExpandInTrust() {
            String yaml = """
                    signers:
                      alice: "alice@example.com"
                    artifacts:
                      apache-stack:
                        - org.apache.maven.*
                        - org.apache.commons.*
                    trust:
                      apache-stack: alice
                    """;
            SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader(yaml));
            TrustPolicy policy = config.trustPolicy();
            // "apache-stack" should be expanded into its two patterns
            assertFalse(policy.expectedSigners(
                    artifact("org.apache.maven.plugins", "maven-compiler-plugin", "3.13.0")).isEmpty());
            assertFalse(policy.expectedSigners(
                    artifact("org.apache.commons", "commons-lang3", "3.14")).isEmpty());
            // A non-matching artifact should have no signers
            assertTrue(policy.expectedSigners(
                    artifact("com.example", "lib", "1.0")).isEmpty());
        }

        @Test
        void trustMappingsResolved() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23"
                    trust:
                      "org.example:*": [alice]
                    """);
            var artifact = artifact("org.example", "lib", "1.0");
            var expected = config.trustPolicy().expectedSigners(artifact);
            assertEquals(1, expected.size());
            assertEquals("alice", expected.get(0).id());
        }

        @Test
        void trustMappingsSingleString() {
            var config = parse("""
                    signers:
                      bob: "bob@example.com"
                    trust:
                      "org.example:lib": bob
                    """);
            var expected = config.trustPolicy().expectedSigners(artifact("org.example", "lib", "1.0"));
            assertEquals(1, expected.size());
            assertEquals("bob", expected.get(0).id());
        }

        @Test
        void trustMappingsUndefinedSignerThrows() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    trust:
                      "org.example:*": [nonexistent]
                    """));
        }

        @Test
        void memberCredentialMatchesTrust() {
            var config = parse("""
                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                          - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    trust:
                      "org.apache.*": apache
                    """);
            var expected = config.trustPolicy().expectedSigners(
                    artifact("org.apache.maven.plugins", "maven-compiler-plugin", "3.13.0"));
            assertEquals(1, expected.size());
            assertEquals("apache", expected.get(0).id());

            var creds = expected.get(0).credentials();
            assertEquals(2, creds.size());
            assertTrue(creds.stream()
                    .anyMatch(c -> c instanceof FingerprintCredential fc
                            && fc.fingerprint().equals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")));
            assertTrue(creds.stream()
                    .anyMatch(c -> c instanceof FingerprintCredential fc
                            && fc.fingerprint().equals("BBE7232D7991050B54C8EA0ADC08637CA615D22C")));
        }

        @Test
        void unsignedAllowed() {
            var config = parse("""
                    unsigned:
                      - "org.example:unsigned-lib"
                    """);
            assertTrue(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "unsigned-lib", "1.0")));
            assertFalse(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "other-lib", "1.0")));
        }
    }

    @Nested
    class PolicyParsing {

        @Test
        void defaults() {
            var config = parse("version: 1");
            assertEquals(ListedEvidencePolicy.ALL, config.trustPolicy().listedEvidence());
            assertEquals(UnlistedEvidencePolicy.IGNORE, config.trustPolicy().unlistedEvidence());
            assertEquals(UntrustedPolicy.FAIL, config.trustPolicy().onUntrusted());
        }

        @Test
        void warnPolicy() {
            var config = parse("""
                    policy:
                      on-untrusted: warn
                      listed-evidence: any
                    """);
            assertEquals(UntrustedPolicy.WARN, config.trustPolicy().onUntrusted());
            assertEquals(ListedEvidencePolicy.ANY, config.trustPolicy().listedEvidence());
        }

        @Test
        void invalidPolicyThrows() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    policy:
                      on-untrusted: ignore
                    """));
        }
    }

    @Nested
    class SigningParsing {

        @Test
        void signingConfig() {
            var config = parse("""
                    signing:
                      signer: alice
                      default-profile: hybrid
                      profiles:
                        hybrid: [openpgp4, openpgp6]
                      toolchain: [sq]
                    tools:
                      sq:
                        cipher-suite: "mldsa87-ed448"
                    """);
            var signing = config.signingConfig();
            assertEquals("alice", signing.signer());
            assertEquals("hybrid", signing.defaultProfile());
            assertEquals(List.of("openpgp4", "openpgp6"), signing.profiles().get("hybrid"));
            assertEquals(List.of("sq"), signing.toolchain());
            assertEquals("mldsa87-ed448", config.toolsConfig().get("sq").settings().get("cipher-suite"));
        }

        @Test
        void noSigningSection() {
            var config = parse("version: 1");
            assertEquals(SigningConfig.DEFAULT, config.signingConfig());
        }
    }

    @Nested
    class DiscoveryParsing {

        @Test
        void discoveryConfig() {
            var config = parse("""
                    discovery:
                      resolve-signers: true
                      import-to-keyring: false
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            var dc = config.discoveryConfig();
            assertTrue(dc.resolveSigners());
            assertFalse(dc.importToKeyring());
            assertEquals(List.of("hkps://keys.openpgp.org"), dc.keyservers());
        }

        @Test
        void toolchainList() {
            var config = parse("""
                    discovery:
                      toolchain: [sq, gpg]
                    """);
            assertEquals(List.of("sq", "gpg"), config.discoveryConfig().toolchain());
        }

        @Test
        void toolchainScalar() {
            var config = parse("""
                    discovery:
                      toolchain: gpg
                    """);
            assertEquals(List.of("gpg"), config.discoveryConfig().toolchain());
        }

        @Test
        void toolchainDefault() {
            var config = parse("""
                    discovery:
                      resolve-signers: true
                    """);
            assertNull(config.discoveryConfig().toolchain());
            assertEquals(DiscoveryConfig.DEFAULT_TOOL_PRIORITY, config.discoveryConfig().effectiveToolchain());
        }

        @Test
        void noDiscoverySection() {
            var config = parse("version: 1");
            assertEquals(DiscoveryConfig.DEFAULT, config.discoveryConfig());
        }
    }

    @Nested
    class ToolsParsing {

        @Test
        void topLevelToolsConfig() {
            var config = parse("""
                    tools:
                      sigstore:
                        trusted-root: "/path/to/root.json"
                      bc:
                        gnupg-home: "/custom/gnupg"
                    """);
            var tc = config.toolsConfig();
            assertFalse(tc.isEmpty());
            assertEquals(2, tc.size());
            assertNotNull(tc.get("sigstore"));
            assertEquals("/path/to/root.json", tc.get("sigstore").settings().get("trusted-root"));
            assertNotNull(tc.get("bc"));
            assertEquals("/custom/gnupg", tc.get("bc").settings().get("gnupg-home"));
        }

        @Test
        void noToolsSection() {
            var config = parse("version: 1");
            assertTrue(config.toolsConfig().isEmpty());
        }
    }

    @Nested
    class FullConfig {

        @Test
        void parsesCompleteConfig() {
            var config = parse("""
                    version: 1
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        openpgp4: "4AEE18F83AFDEB23"
                        openpgp6: "ABCD1234ABCD1234"
                      bob: "bob@example.com"
                    signing:
                      signer: alice
                    trust:
                      "org.example:*": [alice, bob]
                    unsigned:
                      - "org.example:unsigned-lib"
                    policy:
                      on-untrusted: fail
                    discovery:
                      resolve-signers: true
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            assertEquals(1, config.version());
            assertEquals(2, config.signers().names().size());
            assertEquals("alice", config.signingConfig().signer());
            assertEquals(ListedEvidencePolicy.ALL, config.trustPolicy().listedEvidence());
            assertTrue(config.discoveryConfig().resolveSigners());
        }
    }

    private static ArtifactIdentity artifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return ns;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String version() {
                return version;
            }
        };
    }
}
