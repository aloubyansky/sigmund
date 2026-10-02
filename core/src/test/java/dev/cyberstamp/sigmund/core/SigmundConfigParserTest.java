package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
                    issuers: [keys.openpgp.org]
                    signers:
                      bob: "bob@example.com"
                    """);
            var bob = config.signers().get("bob");
            assertThat(bob).isNotNull();
            assertThat(bob.credentials().size()).isEqualTo(1);
            assertThat(bob.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            assertThat(((IdentityCredential) bob.credentials().get(0)).attribute(IdentityCredential.EMAIL))
                    .isEqualTo("bob@example.com");
        }

        @Test
        void objectSignerWithFingerprints() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                        openpgp4: "4AEE18F83AFDEB23000000000000000000000000"
                        openpgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                    """);
            var alice = config.signers().get("alice");
            assertThat(alice.credentials().size()).isEqualTo(3);

            var types = alice.credentials().stream().map(Credential::type).toList();
            assertThat(types).contains("openpgp4", "openpgp6", Credential.TYPE_IDENTITY);
        }

        @Test
        void objectSignerWithIdentityRepoUri() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-uri: "https://github.com/org/repo"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().size()).isEqualTo(1);
            assertThat(ci.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            var sc = (IdentityCredential) ci.credentials().get(0);
            assertThat(sc.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
            assertThat(sc.attribute("source-repository-uri")).isEqualTo("https://github.com/org/repo");
            assertThat(sc.attribute(IdentityCredential.SUBJECT)).isNull();
        }

        @Test
        void objectSignerWithIdentitySubject() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            subject: "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            var sc = (IdentityCredential) ci.credentials().get(0);
            assertThat(sc.attribute(IdentityCredential.SUBJECT)).isEqualTo(
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0");
        }

        @Test
        void identityUnknownFieldThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            oidc-subject: "https://github.com/org/repo"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("oidc-subject");
        }

        @Test
        void misspelledAttributeSuggestsTheKnownName() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            build-config-ur: "https://github.com/org/repo/.github/workflows/release.yml"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("did you mean 'build-config-uri'");
        }

        @Test
        void extensionFromTheFulcioRegistryIsAccepted() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-ref: "refs/heads/main"
                    """);
            var sc = (IdentityCredential) config.signers().get("ci-pipeline").credentials().get(0);
            assertThat(sc.attribute("source-repository-ref")).isEqualTo("refs/heads/main");
        }

        @Test
        void identityWithOnlyAnIssuerThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("at least one attribute besides its issuer");
        }

        @Test
        void identityWithoutIssuerNeedsAListedOidcIssuer() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - source-repository-uri: "https://github.com/org/repo"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("no listed issuer can assert source-repository-uri");
        }

        @Test
        void unclassifiableIssuerInTheListThrows() {
            assertThatThrownBy(() -> parse("""
                    issuers:
                      - keyserver.ubuntu.com
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("keyserver.ubuntu.com")
                    .hasMessageContaining("neither a known directory");
        }

        @Test
        void knownDirectoryWithoutSchemeIsListedByItsUrl() {
            var config = parse("""
                    issuers:
                      - keys.openpgp.org
                      - https://keys.openpgp.org/
                    """);
            assertThat(config.trustPolicy().issuers()).containsExactly("https://keys.openpgp.org");
        }

        @Test
        void emailWithoutAnyIssuerThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        email: "alice@example.com"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("no listed issuer can assert email")
                    .hasMessageContaining("keys.openpgp.org");
        }

        @Test
        void identityNamesItsOwnIssuerWithoutListingIt() {
            var config = parse("""
                    signers:
                      bot:
                        identities:
                          - issuer: "https://accounts.google.com"
                            email: "bot@example.com"
                    """);
            var identity = (IdentityCredential) config.signers().get("bot").credentials().get(0);
            assertThat(identity.issuer()).isEqualTo("https://accounts.google.com");
            assertThat(identity.attribute(IdentityCredential.EMAIL)).isEqualTo("bot@example.com");
            assertThat(config.trustPolicy().issuers()).isEmpty();
        }

        @Test
        void emailIsAnAddressOnly() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bot:
                        email:
                          address: "bot@example.com"
                          issuer: "https://accounts.google.com"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("to name its issuer, use 'identities'");
        }

        @Test
        void unknownSignerKeyThrowsRatherThanDroppingACredential() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          source-repository-uri: "https://github.com/org/repo"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("unknown key 'sigstore'");
        }

        @Test
        void nameIsNotASignerKey() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        name: "Alice"
                        pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("unknown key 'name'");
        }

        @Test
        void oneSignerMayCarrySeveralIdentities() {
            var config = parse("""
                    signers:
                      alice:
                        identities:
                          - issuer: keys.openpgp.org
                            email: "alice@example.com"
                          - issuer: "https://accounts.google.com"
                            email: "alice@example.com"
                    """);
            var issuers = config.signers().get("alice").credentials().stream()
                    .map(c -> ((IdentityCredential) c).issuer())
                    .toList();
            assertThat(issuers).containsExactly(IssuerKind.KEYS_OPENPGP_ORG, "https://accounts.google.com");
        }

        @Test
        void inlineDirectoryCannotAssertWorkflowAttributes() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci:
                        identities:
                          - issuer: keys.openpgp.org
                            source-repository-uri: "https://github.com/org/repo"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("issuer 'https://keys.openpgp.org' cannot assert source-repository-uri");
        }

        @Test
        void keyIdIsRejectedAsAFingerprint() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("Signer 'alice'")
                    .hasMessageContaining("not a full fingerprint");
        }

        @Test
        void identityWithoutIssuerUsesTheList() {
            var config = parse("""
                    issuers:
                      - https://token.actions.githubusercontent.com
                    signers:
                      ci-pipeline:
                        identities:
                          - source-repository-uri: "https://github.com/org/repo"
                    """);
            var sc = (IdentityCredential) config.signers().get("ci-pipeline").credentials().get(0);
            assertThat(sc.issuer()).isNull();
            assertThat(config.trustPolicy().issuers())
                    .containsExactly("https://token.actions.githubusercontent.com");
        }

        @Test
        void objectSignerWithIdentityAllFields() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-uri: "https://github.com/org/repo"
                            build-trigger: "release"
                            build-config-uri: "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
                            runner-environment: "github-hosted"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            var sc = (IdentityCredential) ci.credentials().get(0);
            assertThat(sc.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
            assertThat(sc.attribute("source-repository-uri")).isEqualTo("https://github.com/org/repo");
            assertThat(sc.attribute("build-trigger")).isEqualTo("release");
            assertThat(sc.attribute("build-config-uri")).isEqualTo(
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main");
            assertThat(sc.attribute("runner-environment")).isEqualTo("github-hosted");
        }

        @Test
        void pgp4Canonical() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    """);
            var fp = (KeyCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp4");
        }

        @Test
        void pgp6Canonical() {
            var config = parse("""
                    signers:
                      alice:
                        pgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                    """);
            var fp = (KeyCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp6");
        }

        @Test
        void openpgp4Alias() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    """);
            var fp = (KeyCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp4");
        }

        @Test
        void openpgp6Alias() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                    """);
            var fp = (KeyCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp6");
        }

        @Test
        void objectSignerWithEmailAndFingerprint() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    """);
            var alice = config.signers().get("alice");
            assertThat(alice.credentials().stream()
                    .anyMatch(c -> c instanceof IdentityCredential ec
                            && ec.attribute(IdentityCredential.EMAIL).equals("alice@example.com")))
                    .isTrue();
        }

        @Test
        void organizationWithMembers() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      apache:
                        members:
                          - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@maven.apache.org"
                          - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    """);
            var apache = config.signers().get("apache");
            assertThat(apache.credentials().size()).isEqualTo(3);

            var fps = apache.credentials().stream()
                    .filter(c -> c instanceof KeyCredential)
                    .map(c -> ((KeyCredential) c).fingerprint())
                    .toList();
            assertThat(fps.size()).isEqualTo(2);
            assertThat(fps.contains("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")).isTrue();
            assertThat(fps.contains("BBE7232D7991050B54C8EA0ADC08637CA615D22C")).isTrue();

            assertThat(apache.credentials().stream()
                    .anyMatch(c -> c instanceof IdentityCredential ec
                            && ec.attribute(IdentityCredential.EMAIL).equals("dev@maven.apache.org")))
                    .isTrue();
        }

        @Test
        void membersWithMultipleCredentialTypes() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      team:
                        members:
                          - openpgp4: "AAAA1111AAAA1111000000000000000000000000"
                            openpgp6: "BBBB2222BBBB2222000000000000000000000000000000000000000000000000"
                            email: "alice@example.com"
                    """);
            var team = config.signers().get("team");
            assertThat(team.credentials().size()).isEqualTo(3);

            var types = team.credentials().stream().map(Credential::type).toList();
            assertThat(types).contains("openpgp4", "openpgp6", Credential.TYPE_IDENTITY);
        }

        @Test
        void topLevelCredentialsCombinedWithMembers() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      org:
                        email: "org@example.com"
                        members:
                          - openpgp4: "CCCC3333CCCC3333000000000000000000000000"
                    """);
            var org = config.signers().get("org");
            assertThat(org.credentials().size()).isEqualTo(2);
            assertThat(org.credentials().stream()
                    .anyMatch(c -> c instanceof IdentityCredential ec
                            && ec.attribute(IdentityCredential.EMAIL).equals("org@example.com")))
                    .isTrue();
            assertThat(org.credentials().stream()
                    .anyMatch(c -> c instanceof KeyCredential fc
                            && fc.fingerprint().equals("CCCC3333CCCC3333000000000000000000000000")))
                    .isTrue();
        }

        @Test
        void emptyMembersWithNoTopLevelCredentialsThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      empty-org:
                        members: []
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void nestedMembersThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bad-org:
                        members:
                          - openpgp4: "AAAA1111AAAA1111000000000000000000000000"
                            members:
                              - openpgp4: "BBBB2222BBBB2222000000000000000000000000"
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void membersNotArrayThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bad-org:
                        members: "not-an-array"
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class TrustParsing {

        @Test
        void artifactGroupsExpandInTrust() {
            String yaml = """
                    issuers: [keys.openpgp.org]
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
            assertThat(policy.expectedSigners(
                    artifact("org.apache.maven.plugins", "maven-compiler-plugin", "3.13.0")).isEmpty())
                    .isFalse();
            assertThat(policy.expectedSigners(
                    artifact("org.apache.commons", "commons-lang3", "3.14")).isEmpty())
                    .isFalse();
            // A non-matching artifact should have no signers
            assertThat(policy.expectedSigners(
                    artifact("com.example", "lib", "1.0")).isEmpty())
                    .isTrue();
        }

        @Test
        void trustMappingsResolved() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    trust:
                      "org.example:*": [alice]
                    """);
            var artifact = artifact("org.example", "lib", "1.0");
            var expected = config.trustPolicy().expectedSigners(artifact);
            assertThat(expected.size()).isEqualTo(1);
            assertThat(expected.get(0).id()).isEqualTo("alice");
        }

        @Test
        void trustMappingsSingleString() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      bob: "bob@example.com"
                    trust:
                      "org.example:lib": bob
                    """);
            var expected = config.trustPolicy().expectedSigners(artifact("org.example", "lib", "1.0"));
            assertThat(expected.size()).isEqualTo(1);
            assertThat(expected.get(0).id()).isEqualTo("bob");
        }

        @Test
        void trustMappingsUndefinedSignerThrows() {
            assertThatThrownBy(() -> parse("""
                    trust:
                      "org.example:*": [nonexistent]
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void memberCredentialMatchesTrust() {
            var config = parse("""
                    signers:
                      apache:
                        members:
                          - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                          - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    trust:
                      "org.apache.*": apache
                    """);
            var expected = config.trustPolicy().expectedSigners(
                    artifact("org.apache.maven.plugins", "maven-compiler-plugin", "3.13.0"));
            assertThat(expected.size()).isEqualTo(1);
            assertThat(expected.get(0).id()).isEqualTo("apache");

            var creds = expected.get(0).credentials();
            assertThat(creds.size()).isEqualTo(2);
            assertThat(creds.stream()
                    .anyMatch(c -> c instanceof KeyCredential fc
                            && fc.fingerprint().equals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")))
                    .isTrue();
            assertThat(creds.stream()
                    .anyMatch(c -> c instanceof KeyCredential fc
                            && fc.fingerprint().equals("BBE7232D7991050B54C8EA0ADC08637CA615D22C")))
                    .isTrue();
        }

        @Test
        void signatureOptionalAllowed() {
            var config = parse("""
                    signature-optional:
                      - "org.example:optional-lib"
                    """);
            assertThat(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "optional-lib", "1.0"))).isTrue();
            assertThat(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "other-lib", "1.0"))).isFalse();
        }
    }

    @Nested
    class PolicyParsing {

        @Test
        void defaults() {
            var config = parse("version: 1");
            assertThat(config.trustPolicy().listedEvidence()).isEqualTo(ListedEvidencePolicy.ALL);
            assertThat(config.trustPolicy().unlistedEvidence()).isEqualTo(UnlistedEvidencePolicy.IGNORE);
            assertThat(config.trustPolicy().onUntrusted()).isEqualTo(UntrustedPolicy.FAIL);
        }

        @Test
        void warnPolicy() {
            var config = parse("""
                    policy:
                      on-untrusted: warn
                      listed-evidence: any
                    """);
            assertThat(config.trustPolicy().onUntrusted()).isEqualTo(UntrustedPolicy.WARN);
            assertThat(config.trustPolicy().listedEvidence()).isEqualTo(ListedEvidencePolicy.ANY);
        }

        @Test
        void invalidPolicyThrows() {
            assertThatThrownBy(() -> parse("""
                    policy:
                      on-untrusted: ignore
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class SigningParsing {

        @Test
        void signingConfig() {
            var config = parse("""
                    signing:
                      signer: alice
                      credential-types: [pgp4, pgp6]
                      profiles:
                        classic: [pgp4]
                      toolchain: [sq]
                    tools:
                      sq:
                        cipher-suite: "mldsa87-ed448"
                    """);
            var signing = config.signingConfig();
            assertThat(signing.signer()).isEqualTo("alice");
            assertThat(signing.credentialTypes()).isEqualTo(List.of("pgp4", "pgp6"));
            assertThat(signing.profiles().get("classic")).isEqualTo(List.of("pgp4"));
            assertThat(signing.toolchain()).isEqualTo(List.of("sq"));
            assertThat(config.toolsConfig().get("sq").settings().get("cipher-suite")).isEqualTo("mldsa87-ed448");
        }

        @Test
        void noSigningSection() {
            var config = parse("version: 1");
            assertThat(config.signingConfig()).isEqualTo(SigningConfig.DEFAULT);
        }
    }

    @Nested
    class VerificationParsing {

        @Test
        void verificationConfig() {
            var config = parse("""
                    verification:
                      resolve-signers: true
                      import-to-keyring: false
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            var dc = config.discoveryConfig();
            assertThat(dc.resolveSigners()).isTrue();
            assertThat(dc.importToKeyring()).isFalse();
            assertThat(dc.keyservers()).isEqualTo(List.of("hkps://keys.openpgp.org"));
        }

        @Test
        void toolchainList() {
            var config = parse("""
                    verification:
                      toolchain: [sq, gpg]
                    """);
            assertThat(config.discoveryConfig().toolchain()).isEqualTo(List.of("sq", "gpg"));
        }

        @Test
        void toolchainScalar() {
            var config = parse("""
                    verification:
                      toolchain: gpg
                    """);
            assertThat(config.discoveryConfig().toolchain()).isEqualTo(List.of("gpg"));
        }

        @Test
        void toolchainDefault() {
            var config = parse("""
                    verification:
                      resolve-signers: true
                    """);
            assertThat(config.discoveryConfig().toolchain()).isNull();
            assertThat(config.discoveryConfig().effectiveToolchain()).isEqualTo(DiscoveryConfig.DEFAULT_TOOL_PRIORITY);
        }

        @Test
        void noVerificationSection() {
            var config = parse("version: 1");
            assertThat(config.discoveryConfig()).isEqualTo(DiscoveryConfig.DEFAULT);
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
            assertThat(tc.isEmpty()).isFalse();
            assertThat(tc.size()).isEqualTo(2);
            assertThat(tc.get("sigstore")).isNotNull();
            assertThat(tc.get("sigstore").settings().get("trusted-root")).isEqualTo("/path/to/root.json");
            assertThat(tc.get("bc")).isNotNull();
            assertThat(tc.get("bc").settings().get("gnupg-home")).isEqualTo("/custom/gnupg");
        }

        @Test
        void noToolsSection() {
            var config = parse("version: 1");
            assertThat(config.toolsConfig().isEmpty()).isTrue();
        }
    }

    @Nested
    class FullConfig {

        @Test
        void parsesCompleteConfig() {
            var config = parse("""
                    version: 1
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                        pgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                      bob: "bob@example.com"
                    signing:
                      signer: alice
                    trust:
                      "org.example:*": [alice, bob]
                    signature-optional:
                      - "org.example:optional-lib"
                    policy:
                      on-untrusted: fail
                    verification:
                      resolve-signers: true
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            assertThat(config.version()).isEqualTo(1);
            assertThat(config.signers().names().size()).isEqualTo(2);
            assertThat(config.signingConfig().signer()).isEqualTo("alice");
            assertThat(config.trustPolicy().listedEvidence()).isEqualTo(ListedEvidencePolicy.ALL);
            assertThat(config.discoveryConfig().resolveSigners()).isTrue();
        }
    }

    private static ArtifactCoords artifact(String ns, String name, String version) {
        return new ArtifactCoords(ns, name, "", "jar", version);
    }
}
