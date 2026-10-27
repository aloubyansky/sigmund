package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IssuerKind;
import dev.cyberstamp.sigmund.core.SigmundSchema;
import dev.cyberstamp.sigmund.core.SignatureToolFactory;
import dev.cyberstamp.sigmund.core.SignerIdentity;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import dev.sigstore.oidc.client.OidcToken;
import dev.sigstore.oidc.client.OidcTokenMatcher;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class SigstoreToolFactoryTest {

    private static final String GITHUB = "https://token.actions.githubusercontent.com";

    private final SigstoreToolFactory factory = new SigstoreToolFactory();

    @Nested
    class Properties {
        @Test
        void toolName() {
            assertThat(factory.toolName()).isEqualTo("sigstore");
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(factory.supportedCredentialTypes().contains("sigstore")).isTrue();
            assertThat(factory.supportedCredentialTypes().size()).isEqualTo(1);
        }

        /**
         * The settings Sigstore accepts are exactly those the published schema lists for
         * {@code tools.sigstore}, as core checks for the built-in tools.
         */
        @Test
        void acceptsTheSettingsTheSchemaLists() throws IOException {
            JsonNode schema;
            try (InputStream in = SigmundSchema.class.getResourceAsStream("/" + SigmundSchema.RESOURCE)) {
                schema = new ObjectMapper().readTree(in);
            }
            List<String> listed = new ArrayList<>(
                    schema.at("/properties/tools/properties/sigstore/properties").propertyNames());

            assertThat(factory.acceptedSettings()).containsExactlyInAnyOrderElementsOf(listed);
        }
    }

    @Nested
    class ServiceLoaderDiscovery {
        @Test
        void isDiscoverable() {
            boolean found = ServiceLoader.load(SignatureToolFactory.class)
                    .stream()
                    .anyMatch(p -> p.get() instanceof SigstoreToolFactory);
            assertThat(found)
                    .as("SigstoreToolFactory should be discoverable via ServiceLoader")
                    .isTrue();
        }
    }

    @Nested
    class CreateVerifyOnly {
        @Test
        void failsWithInvalidTrustedRoot(@TempDir Path tempDir) {
            Path badRoot = tempDir.resolve("bad-root.json");
            assertThatThrownBy(() -> factory.createVerifyOnly(
                    Map.of("trusted-root", badRoot.toString())))
                    .isInstanceOf(ToolExecutionException.class);
        }

        @Test
        void failsWithMalformedTrustedRoot(@TempDir Path tempDir) throws IOException {
            Path badRoot = tempDir.resolve("bad-root.json");
            Files.writeString(badRoot, "not valid json");
            assertThatThrownBy(() -> factory.createVerifyOnly(
                    Map.of("trusted-root", badRoot.toString())))
                    .isInstanceOf(ToolExecutionException.class);
        }
    }

    @Nested
    class CreateSigning {
        private static final String GOOGLE = "https://accounts.google.com";

        private SignerIdentity signerWith(IdentityCredential entry) {
            return new SignerIdentity("alice", List.of(entry));
        }

        @Test
        void withoutAnExpectedSignerAnyIdentityIsAccepted() throws Exception {
            try (var tool = (SigstoreTool) factory.createSigning(Map.of("staging", "true"), null)) {
                assertThat(tool.canSign()).isTrue();
                assertThat(tool.name()).isEqualTo("sigstore");
                assertThat(tool.signingInfo().get(0).userId()).isNull();
                assertThat(tool.allowedIdentities()).isEmpty();
            }
        }

        @Test
        void aSubjectEntryNamesTheExpectedIdentity() throws Exception {
            var entry = new IdentityCredential(GOOGLE,
                    Map.of(IdentityCredential.SUBJECT, "alice@example.com"));
            try (var tool = (SigstoreTool) factory.createSigning(
                    Map.of("staging", "true"), signerWith(entry))) {
                assertThat(tool.canSign()).isTrue();
                assertThat(tool.signingInfo().get(0).userId()).isEqualTo("alice@example.com");
            }
        }

        @Test
        void anEntryResolvedFromTheDefaultIssuersBuildsItsMatcher() throws Exception {
            var entry = new IdentityCredential(null,
                    Map.of(IdentityCredential.SUBJECT, "alice@example.com"));
            SignerIdentity expected = signerWith(entry).withIssuersResolved(List.of(GOOGLE));
            try (var tool = (SigstoreTool) factory.createSigning(Map.of("staging", "true"), expected)) {
                assertThat(tool.allowedIdentities()).containsExactly(
                        new IdentityCredential(GOOGLE, Map.of(IdentityCredential.SUBJECT, "alice@example.com")));
            }
        }

        @Test
        void anOidcEntryWithoutSubjectBuildsAnIssuerOnlyMatcher() throws Exception {
            var entry = new IdentityCredential(GITHUB,
                    Map.of("source-repository-uri", "https://github.com/acme/app"));
            try (var tool = (SigstoreTool) factory.createSigning(
                    Map.of("staging", "true"), signerWith(entry))) {
                assertThat(tool.allowedIdentities()).containsExactly(entry);
                assertThat(tool.signingInfo().get(0).userId()).isNull();
            }
        }

        @Test
        void aMixedSignerBuildsAMatcherForEveryOidcEntry() throws Exception {
            var person = new IdentityCredential(GOOGLE,
                    Map.of(IdentityCredential.SUBJECT, "alice@example.com"));
            var workflow = new IdentityCredential(GITHUB,
                    Map.of("source-repository-uri", "https://github.com/acme/app"));
            SignerIdentity expected = new SignerIdentity("alice", List.of(person, workflow));
            try (var tool = (SigstoreTool) factory.createSigning(Map.of("staging", "true"), expected)) {
                assertThat(tool.allowedIdentities()).containsExactly(person, workflow);
                assertThat(tool.signingInfo().get(0).userId()).isEqualTo("alice@example.com");
            }
        }

        @Test
        void anEntryResolvedToADirectoryBuildsNoMatcher() throws Exception {
            var entry = new IdentityCredential(null,
                    Map.of(IdentityCredential.EMAIL, "alice@example.com"));
            SignerIdentity expected = signerWith(entry).withIssuersResolved(List.of(IssuerKind.KEYS_OPENPGP_ORG));
            try (var tool = (SigstoreTool) factory.createSigning(Map.of("staging", "true"), expected)) {
                assertThat(tool.allowedIdentities()).isEmpty();
            }
        }
    }

    @Nested
    class Matchers {
        private static final String GOOGLE = "https://accounts.google.com";

        @Test
        void aSubjectEntryMatchesItsIssuerAndSubjectOnly() {
            OidcTokenMatcher matcher = SigstoreToolFactory.matcherFor(new IdentityCredential(GOOGLE,
                    Map.of(IdentityCredential.SUBJECT, "alice@example.com")));

            assertThat(matcher.test(token("alice@example.com", GOOGLE))).isTrue();
            assertThat(matcher.test(token("mallory@example.com", GOOGLE))).isFalse();
            assertThat(matcher.test(token("alice@example.com", GITHUB))).isFalse();
        }

        @Test
        void anEntryWithoutSubjectMatchesAnySubjectOfItsIssuer() {
            OidcTokenMatcher matcher = SigstoreToolFactory.matcherFor(new IdentityCredential(GITHUB,
                    Map.of("source-repository-uri", "https://github.com/acme/app")));

            assertThat(matcher.test(token("https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main",
                    GITHUB))).isTrue();
            assertThat(matcher.test(token("alice@example.com", GOOGLE))).isFalse();
        }

        private OidcToken token(String subject, String issuer) {
            return new OidcToken() {
                @Override
                public String getSubjectAlternativeName() {
                    return subject;
                }

                @Override
                public String getIssuer() {
                    return issuer;
                }

                @Override
                public String getIdToken() {
                    return "token";
                }
            };
        }
    }
}
