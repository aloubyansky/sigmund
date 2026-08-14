package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactPatternMatcherTest {

    @Nested
    class FindBestMatch {

        @Test
        void exactNamespace() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "1.0"),
                    List.of("org.example"));
            assertThat(match).isEqualTo("org.example");
        }

        @Test
        void wildcardName() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "any-lib", "1.0"),
                    List.of("org.example:*"));
            assertThat(match).isEqualTo("org.example:*");
        }

        @Test
        void exactNameAndNamespace() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "1.0"),
                    List.of("org.example:lib"));
            assertThat(match).isEqualTo("org.example:lib");
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "other", "1.0"),
                    List.of("org.example:lib"))).isNull();
        }

        @Test
        void threePartPattern() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "2.0"),
                    List.of("org.example:lib:2.0"));
            assertThat(match).isEqualTo("org.example:lib:2.0");
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "1.0"),
                    List.of("org.example:lib:2.0"))).isNull();
        }

        @Test
        void moreSpecificWins() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "special-lib", "1.0"),
                    List.of("org.example:*", "org.example:special-lib"));
            assertThat(match).isEqualTo("org.example:special-lib");
        }

        @Test
        void noMatch() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("com.other", "lib", "1.0"),
                    List.of("org.example:*"))).isNull();
        }

        @Test
        void namespaceWildcard() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example.sub", "lib", "1.0"),
                    List.of("org.example.*"));
            assertThat(match).isEqualTo("org.example.*");
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.other", "lib", "1.0"),
                    List.of("org.example.*"))).isNull();
        }

        @Test
        void unsignedExactMatch() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "unsigned-lib", "1.0"),
                    List.of("org.example:unsigned-lib"))).isEqualTo("org.example:unsigned-lib");
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "other", "1.0"),
                    List.of("org.example:unsigned-lib"))).isNull();
        }

        @Test
        void unsignedWildcardMatch() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.test", "anything", "1.0"),
                    List.of("org.test:*"))).isEqualTo("org.test:*");
        }
    }

    @Nested
    class MatchScore {

        @Test
        void exactNamespaceScoresHigherThanWildcard() {
            var a = artifact("org.example", "lib", "1.0");
            assertThat(ArtifactPatternMatcher.matchScore(a, "org.example") > ArtifactPatternMatcher.matchScore(a, "org.*"))
                    .isTrue();
        }

        @Test
        void deeperNamespaceScoresHigher() {
            var a = artifact("org.example.sub", "lib", "1.0");
            assertThat(ArtifactPatternMatcher.matchScore(a, "org.example.sub") > ArtifactPatternMatcher.matchScore(a,
                    "org.example.*")).isTrue();
        }

        @Test
        void noMatchReturnsNegative() {
            assertThat(ArtifactPatternMatcher.matchScore(
                    artifact("com.other", "lib", "1.0"), "org.example")).isEqualTo(-1);
        }

        @Test
        void fourPartsInvalid() {
            assertThat(ArtifactPatternMatcher.matchScore(
                    artifact("org", "lib", "1.0"), "a:b:c:d")).isEqualTo(-1);
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
