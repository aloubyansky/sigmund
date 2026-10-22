package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class RuleListEditorTest {

    private static List<String> lines(String text) {
        return new ArrayList<>(text.lines().toList());
    }

    @Nested
    class RemovingPatterns {

        @Test
        void removesOnePatternAndKeepsTheRest() {
            List<String> lines = lines("""
                    rules:
                      - match: [com.example:lib]
                        requires: [alice]
                      - match: [com.example:a, com.example:b, com.example:c]
                        on-no-claim: ignore
                    """);

            assertThat(RuleListEditor.removeFromMatch(lines, 1, Set.of("com.example:b"))).isTrue();

            assertThat(lines).containsExactly(
                    "rules:",
                    "  - match: [com.example:lib]",
                    "    requires: [alice]",
                    "  - match: [com.example:a, com.example:c]",
                    "    on-no-claim: ignore");
        }

        @Test
        void removesTheWholeRuleWhenNothingWouldRemain() {
            List<String> lines = lines("""
                    signers:
                      alice: "alice@example.com"

                    rules:
                      - match: [com.example:a]
                        on-no-claim: ignore

                      - match: [com.example:lib]
                        requires: [alice]

                    defaults:
                      on-no-claim: warn
                    """);

            assertThat(RuleListEditor.removeFromMatch(lines, 0, Set.of("com.example:a"))).isTrue();

            assertThat(lines).containsExactly(
                    "signers:",
                    "  alice: \"alice@example.com\"",
                    "",
                    "rules:",
                    "",
                    "  - match: [com.example:lib]",
                    "    requires: [alice]",
                    "",
                    "defaults:",
                    "  on-no-claim: warn");
        }

        @Test
        void keepsTheQuotingOfTheEntriesItLeaves() {
            List<String> lines = lines("""
                    rules:
                      - match: ["*", "com.example:a"]
                        on-no-claim: ignore
                    """);

            assertThat(RuleListEditor.removeFromMatch(lines, 0, Set.of("com.example:a"))).isTrue();

            assertThat(lines.get(1)).isEqualTo("  - match: [\"*\"]");
        }

        @Test
        void findsAMatchKeyThatIsNotTheItemsFirstKey() {
            List<String> lines = lines("""
                    rules:
                      - on-no-claim: ignore
                        match: [com.example:a, com.example:b]
                    """);

            assertThat(RuleListEditor.removeFromMatch(lines, 0, Set.of("com.example:a"))).isTrue();

            assertThat(lines.get(2)).isEqualTo("    match: [com.example:b]");
        }
    }

    @Nested
    class LeavingHandWrittenShapesAlone {

        @Test
        void aBlockStyleListIsNotEdited() {
            List<String> lines = lines("""
                    rules:
                      - match:
                          - com.example:a
                        on-no-claim: ignore
                    """);
            List<String> before = List.copyOf(lines);

            assertThat(RuleListEditor.removeFromMatch(lines, 0, Set.of("com.example:a"))).isFalse();
            assertThat(lines).isEqualTo(before);
        }

        @Test
        void aListWithACommentIsNotEdited() {
            List<String> lines = lines("""
                    rules:
                      - match: [com.example:a, com.example:b]  # legacy modules
                        on-no-claim: ignore
                    """);
            List<String> before = List.copyOf(lines);

            assertThat(RuleListEditor.removeFromMatch(lines, 0, Set.of("com.example:a"))).isFalse();
            assertThat(lines).isEqualTo(before);
        }

        @Test
        void anArtifactSetReferenceIsNotExpandedOrEdited() {
            List<String> lines = lines("""
                    rules:
                      - match: [legacy]
                        on-no-claim: ignore
                    """);
            List<String> before = List.copyOf(lines);

            assertThat(RuleListEditor.removeFromMatch(lines, 0, Set.of("com.example:a"))).isFalse();
            assertThat(lines).isEqualTo(before);
        }

        @Test
        void nothingIsRemovedUnlessEveryPatternIsFound() {
            List<String> lines = lines("""
                    rules:
                      - match: [com.example:a, com.example:b]
                        on-no-claim: ignore
                    """);
            List<String> before = List.copyOf(lines);

            assertThat(RuleListEditor.removeFromMatch(lines, 0,
                    Set.of("com.example:a", "com.example:x"))).isFalse();
            assertThat(lines).isEqualTo(before);
        }

        @Test
        void aMissingRuleIsReportedNotInvented() {
            List<String> lines = lines("""
                    rules:
                      - match: [com.example:a]
                        on-no-claim: ignore
                    """);

            assertThat(RuleListEditor.removeFromMatch(lines, 3, Set.of("com.example:a"))).isFalse();
        }
    }

    @Test
    void readsTheRuleIndexFromItsLocation() {
        assertThat(RuleListEditor.ruleIndex("rules[12]")).isEqualTo(12);
        assertThat(RuleListEditor.ruleIndex("defaults")).isEqualTo(-1);
    }
}
