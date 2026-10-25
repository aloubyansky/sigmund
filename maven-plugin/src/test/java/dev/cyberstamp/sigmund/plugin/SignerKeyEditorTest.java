package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignerKeyEditorTest {

    private static final String OLD = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final String NEW = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";
    private static final String V6 = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";
    private static final String NOTE = "pinned by update: https://keys.openpgp.org confirmed alice@example.com";

    private static List<String> lines(String text) {
        return new ArrayList<>(text.lines().toList());
    }

    /**
     * Each key keeps its own comment, so once a signer has several keys of a version they are
     * written as a block list, one key per line, each with what is known about it.
     */
    @Nested
    class AddingAKey {

        @Test
        void aSingleFingerprintBecomesABlockListWithTheNoteOnTheNewKey() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: "%s"
                        email: "alice@example.com"
                    rules:
                      - match: com.example:lib
                        requires: alice
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isTrue();

            assertThat(lines).containsExactly(
                    "signers:",
                    "  alice:",
                    "    pgp4:",
                    "      - \"" + OLD + "\"",
                    "      - \"" + NEW + "\"  # " + NOTE,
                    "    email: \"alice@example.com\"",
                    "rules:",
                    "  - match: com.example:lib",
                    "    requires: alice");
        }

        @Test
        void aCommentedFingerprintKeepsItsCommentOnItsOwnItem() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: "%s"  # user ID on the key, unverified: Alice <alice@example.com>
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isTrue();

            assertThat(lines).containsExactly(
                    "signers:",
                    "  alice:",
                    "    pgp4:",
                    "      - \"" + OLD + "\"  # user ID on the key, unverified: Alice <alice@example.com>",
                    "      - \"" + NEW + "\"  # " + NOTE);
        }

        @Test
        void aBlockListGainsAnItem() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4:
                          - "%s"  # first
                          - "%s"
                        email: "alice@example.com"
                    """.formatted(OLD, V6.substring(0, 40)));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isTrue();

            assertThat(lines).containsSubsequence(
                    "      - \"" + V6.substring(0, 40) + "\"",
                    "      - \"" + NEW + "\"  # " + NOTE,
                    "    email: \"alice@example.com\"");
        }

        @Test
        void aListAnEarlierPinWroteTakesTheNextOne() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: "%s"
                    """.formatted(OLD));
            SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE);

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", V6.substring(0, 40), NOTE)).isTrue();

            assertThat(lines).endsWith("      - \"" + NEW + "\"  # " + NOTE,
                    "      - \"" + V6.substring(0, 40) + "\"  # " + NOTE);
        }

        @Test
        void aFlowListGainsTheKeyWithoutANote() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: ["%s"]
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isTrue();

            assertThat(lines.get(2)).isEqualTo("    pgp4: [\"" + OLD + "\", \"" + NEW + "\"]");
        }

        @Test
        void aSignerWithoutKeysOfThatVersionGetsTheLine() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: "%s"
                        identities:
                          - issuer: "https://keys.openpgp.org"
                            email: "alice@example.com"
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp6", V6, NOTE)).isTrue();

            assertThat(lines).containsSubsequence(
                    "    pgp4: \"" + OLD + "\"",
                    "    pgp6: \"" + V6 + "\"  # " + NOTE,
                    "    identities:");
        }

        @Test
        void aSignerNamedOnlyByAddressGetsItsFirstKey() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        email: "alice@example.com"
                    """);

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, null)).isTrue();

            assertThat(lines).containsExactly(
                    "signers:",
                    "  alice:",
                    "    pgp4: \"" + NEW + "\"",
                    "    email: \"alice@example.com\"");
        }

        @Test
        void aCommentOnTheSignersHeaderIsKept() {
            List<String> lines = lines("""
                    signers:  # publishers we trust
                      alice:
                        pgp4: "%s"
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, null)).isTrue();

            assertThat(lines).containsExactly(
                    "signers:  # publishers we trust",
                    "  alice:",
                    "    pgp4:",
                    "      - \"" + OLD + "\"",
                    "      - \"" + NEW + "\"");
        }

        @Test
        void otherSignersAreLeftAsWritten() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: "%s"
                      bob:
                        pgp4: "%s"
                    """.formatted(OLD, OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "bob", "pgp4", NEW, null)).isTrue();

            assertThat(lines).containsExactly(
                    "signers:",
                    "  alice:",
                    "    pgp4: \"" + OLD + "\"",
                    "  bob:",
                    "    pgp4:",
                    "      - \"" + OLD + "\"",
                    "      - \"" + NEW + "\"");
        }
    }

    /**
     * Only the shapes bootstrap and update write are edited; anything else is left for a person,
     * because a line-based edit of hand-formatted YAML is where an update goes wrong.
     */
    @Nested
    class LeavingAlone {

        @Test
        void aSignerWrittenAsAnAddress() {
            List<String> lines = lines("""
                    signers:
                      alice: "alice@example.com"
                    """);

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isFalse();
            assertThat(lines).containsExactly("signers:", "  alice: \"alice@example.com\"");
        }

        @Test
        void anOrganizationWithMembers() {
            List<String> lines = lines("""
                    signers:
                      apache:
                        members:
                          - pgp4: "%s"
                            email: "dev@maven.apache.org"
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "apache", "pgp4", NEW, NOTE)).isFalse();
        }

        @Test
        void aBlockListWithAnItemThatIsNotAFingerprint() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4:
                          - "%s"
                          - fingerprint: "%s"
                    """.formatted(OLD, OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isFalse();
        }

        @Test
        void aFlowListWithAComment() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: ["%s"]  # laptop key
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "alice", "pgp4", NEW, NOTE)).isFalse();
        }

        @Test
        void aSignerTheFileDoesNotDefine() {
            List<String> lines = lines("""
                    signers:
                      alice:
                        pgp4: "%s"
                    """.formatted(OLD));

            assertThat(SignerKeyEditor.addFingerprint(lines, "bob", "pgp4", NEW, NOTE)).isFalse();
        }
    }
}
