package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class IdentityCredentialTest {

    static final String ACTIONS = "https://token.actions.githubusercontent.com";
    static final String DIRECTORY = IssuerKind.KEYS_OPENPGP_ORG;
    static final String REPO = "https://github.com/acme/widget";
    static final String WORKFLOW = "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1";

    static IdentityCredential provenWorkflow() {
        return new IdentityCredential(ACTIONS, Map.of(
                IdentityCredential.SUBJECT, WORKFLOW,
                "source-repository-uri", REPO,
                "build-config-uri", WORKFLOW));
    }

    @Nested
    class Construction {

        @Test
        void requiresAnAttribute() {
            assertThatThrownBy(() -> new IdentityCredential(ACTIONS, Map.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void blankIssuerMeansNone() {
            assertThat(new IdentityCredential("  ", Map.of("email", "a@example.org")).issuer())
                    .isNull();
        }

        @Test
        void emailIsNormalizedToLowerCase() {
            assertThat(IdentityCredential.email(DIRECTORY, "Release@Apache.ORG").attributes())
                    .containsEntry(IdentityCredential.EMAIL, "release@apache.org");
        }

        @Test
        void otherAttributesKeepTheirCase() {
            var credential = new IdentityCredential(ACTIONS, Map.of("source-repository-uri",
                    "https://github.com/Acme/Widget"));
            assertThat(credential.attributes())
                    .containsEntry("source-repository-uri", "https://github.com/Acme/Widget");
        }

        @Test
        void rejectsBlankAttributeValue() {
            assertThatThrownBy(() -> new IdentityCredential(ACTIONS, Map.of("subject", " ")))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class Matching {

        @Test
        void sameIssuerAndSubsetOfAttributesMatches() {
            var entry = new IdentityCredential(ACTIONS, Map.of("source-repository-uri", REPO));
            assertThat(entry.matches(provenWorkflow())).isTrue();
        }

        @Test
        void differentIssuerDoesNotMatch() {
            var entry = new IdentityCredential("https://gitlab.com",
                    Map.of("source-repository-uri", REPO));
            assertThat(entry.matches(provenWorkflow())).isFalse();
        }

        @Test
        void missingAttributeDoesNotMatch() {
            var entry = new IdentityCredential(ACTIONS, Map.of("build-trigger", "push"));
            assertThat(entry.matches(provenWorkflow())).isFalse();
        }

        @Test
        void differentValueDoesNotMatch() {
            var entry = new IdentityCredential(ACTIONS,
                    Map.of("source-repository-uri", "https://github.com/evil/widget"));
            assertThat(entry.matches(provenWorkflow())).isFalse();
        }

        @Test
        void entryWithoutIssuerMatchesNothingOnItsOwn() {
            var entry = new IdentityCredential(null, Map.of("source-repository-uri", REPO));
            assertThat(entry.matches(provenWorkflow())).isFalse();
        }

        @Test
        void entryWithoutIssuerMatchesADefaultIssuer() {
            var entry = new IdentityCredential(null, Map.of("source-repository-uri", REPO));
            assertThat(entry.matches(provenWorkflow(), List.of(DIRECTORY, ACTIONS))).isTrue();
        }

        @Test
        void entryWithoutIssuerRejectsAnUnlistedIssuer() {
            var entry = new IdentityCredential(null, Map.of("source-repository-uri", REPO));
            assertThat(entry.matches(provenWorkflow(), List.of(DIRECTORY))).isFalse();
        }

        @Test
        void inlineIssuerIgnoresDefaults() {
            var entry = new IdentityCredential("https://gitlab.com",
                    Map.of("source-repository-uri", REPO));
            assertThat(entry.matches(provenWorkflow(), List.of(ACTIONS))).isFalse();
        }

        @Test
        void provenCredentialWithoutIssuerNeverMatches() {
            var entry = IdentityCredential.email(null, "alice@example.org");
            var unvouched = IdentityCredential.email(null, "alice@example.org");
            assertThat(entry.matches(unvouched, List.of(DIRECTORY))).isFalse();
        }

        @Test
        void emailComparesCaseInsensitively() {
            var entry = IdentityCredential.email(DIRECTORY, "Release@Apache.org");
            var proven = IdentityCredential.email(DIRECTORY, "release@apache.ORG");
            assertThat(entry.matches(proven)).isTrue();
        }

        @Test
        void neverMatchesKeyMaterial() {
            var entry = IdentityCredential.email(DIRECTORY, "alice@example.org");
            assertThat(entry.matches(KeyCredential.openPgp(KeyCredentialTest.V4))).isFalse();
        }
    }
}
