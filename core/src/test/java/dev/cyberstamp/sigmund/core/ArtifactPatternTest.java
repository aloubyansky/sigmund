package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ArtifactPatternTest {

    private static ArtifactCoords coords(String namespace, String name, String version) {
        return new ArtifactCoords(namespace, name, "", "jar", version);
    }

    @Nested
    class Parsing {

        @Test
        void namespaceOnly() {
            assertThat(ArtifactPattern.parse("org.example").toString()).isEqualTo("org.example");
        }

        @Test
        void namespaceAndName() {
            assertThat(ArtifactPattern.parse("org.example:lib").toString())
                    .isEqualTo("org.example:lib");
        }

        @Test
        void namespaceNameAndVersion() {
            assertThat(ArtifactPattern.parse("org.example:lib:1.0").toString())
                    .isEqualTo("org.example:lib:1.0");
        }

        @Test
        void classifierScopedPatternIsRejected() {
            assertThatThrownBy(() -> ArtifactPattern.parse("org.example:lib:jar:sources"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("group, artifact and version");
        }

        @Test
        void blankPatternIsRejected() {
            assertThatThrownBy(() -> ArtifactPattern.parse(" "))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class ForModule {

        @Test
        void dropsVersionClassifierAndExtension() {
            ArtifactCoords sources = new ArtifactCoords("org.example", "lib", "sources", "jar", "1.0");
            assertThat(ArtifactPattern.forModule(sources).toString())
                    .isEqualTo("org.example:lib");
        }

        @Test
        void matchesEveryFileOfThatModule() {
            ArtifactCoords jar = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");
            ArtifactPattern pattern = ArtifactPattern.forModule(jar);
            assertThat(pattern.matches(jar)).isTrue();
            assertThat(pattern.matches(
                    new ArtifactCoords("org.example", "lib", "", "pom", "2.0"))).isTrue();
            assertThat(pattern.matches(
                    new ArtifactCoords("org.example", "other", "", "jar", "1.0"))).isFalse();
        }
    }

    @Nested
    class Matching {

        @Test
        void exactNamespaceMatchesAnyArtifactInIt() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.other", "lib", "1.0"))).isFalse();
        }

        @Test
        void namespacePrefixWildcardMatchesSubNamespaces() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example.*");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.example.sub", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.examplefoo", "lib", "1.0"))).isFalse();
        }

        @Test
        void nameWildcardMatchesAnyName() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:*");
            assertThat(pattern.matches(coords("org.example", "anything", "1.0"))).isTrue();
        }

        @Test
        void versionIsMatchedWhenGiven() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:lib:1.0");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.example", "lib", "2.0"))).isFalse();
        }

        @Test
        void trailingStarOnVersionIsAPlainPrefixDotIncluded() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:lib:1.*");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.example", "lib", "1.2.3"))).isTrue();
            assertThat(pattern.matches(coords("org.example", "lib", "10.0"))).isFalse();
            assertThat(pattern.matches(coords("org.example", "lib", "1"))).isFalse();
        }

        @Test
        void trailingStarOnArtifactIsAPlainPrefixDotIncluded() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:foo.*");
            assertThat(pattern.matches(coords("org.example", "foo.bar", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.example", "foobar", "1.0"))).isFalse();
        }

        @Test
        void classifierAndExtensionAreIgnored() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:lib");
            ArtifactCoords sources = new ArtifactCoords("org.example", "lib", "sources", "jar", "1.0");
            ArtifactCoords pom = new ArtifactCoords("org.example", "lib", "", "pom", "1.0");
            assertThat(pattern.matches(sources)).isTrue();
            assertThat(pattern.matches(pom)).isTrue();
        }
    }

    @Nested
    class Specificity {

        @Test
        void longerNamespaceWinsOverShorter() {
            assertThat(ArtifactPattern.parse("org.example.sub").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example").specificity());
        }

        @Test
        void exactNamespaceWinsOverPrefixWildcard() {
            assertThat(ArtifactPattern.parse("org.example").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example.*").specificity());
        }

        @Test
        void namedArtifactWinsOverNameWildcard() {
            assertThat(ArtifactPattern.parse("org.example:lib").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example:*").specificity());
        }

        @Test
        void versionedPatternWinsOverUnversioned() {
            assertThat(ArtifactPattern.parse("org.example:lib:1.0").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example:lib").specificity());
        }

        @Test
        void catchAllIsLeastSpecific() {
            assertThat(ArtifactPattern.parse("*").specificity()).isZero();
        }
    }

    @Nested
    class Overlap {

        @ParameterizedTest(name = "{0} overlaps {1}: {2}")
        @CsvSource({
                "*,                  org.example,          true",
                "org.example,        org.example,          true",
                "org.example,        org.other,            false",
                "org.example,        org.example.*,        true",
                "org.example.sub,    org.example.*,        true",
                "org.examplefoo,     org.example.*,        false",
                "org.example.*,      org.example.*,        true",
                "org.example.*,      org.example.sub.*,    true",
                "org.example.*,      org.examplefoo.*,     false",
                "org.example:*,      org.example:lib,      true",
                "org.example:lib,    org.example:lib,      true",
                "org.example:lib,    org.example:other,    false",
                "org.example:lib,    org.example:li*,      true",
                "org.example:lib,    org.example:x*,       false",
                "org.example:lib-*,  org.example:lib-a*,   true",
                "org.example:lib-*,  org.example:core-*,   false",
                "org.example:lib:1.*, org.example:lib:10.0, false",
                "org.example:lib:1.*, org.example:lib:1.0, true",
                "com.acme:*:1.0,     com.acme:lib,         true",
                "com.acme:a,         com.acme:b,           false",
                "com.acme:a:1.0,     com.acme.*:a:2.0,     false"
        })
        void decidesWhetherTwoPatternsShareACoordinate(String a, String b, boolean expected) {
            ArtifactPattern left = ArtifactPattern.parse(a);
            ArtifactPattern right = ArtifactPattern.parse(b);
            assertThat(left.overlaps(right)).isEqualTo(expected);
            assertThat(right.overlaps(left)).isEqualTo(expected);
        }

        @ParameterizedTest(name = "{0} and {1} both match {2}")
        @CsvSource({
                "com.acme:*:1.0,     com.acme:lib,         com.acme:lib:1.0",
                "com.acme.*:lib,     com.acme.*:*:1.0,     com.acme:lib:1.0",
                "org.example.*,      org.example.sub.*,    org.example.sub:*:*",
                "org.example:li*,    org.example:lib-*,    org.example:lib-:*",
                "*,                  *,                    *:*:*"
        })
        void commonCoordinateIsMatchedByBoth(String a, String b, String expected) {
            ArtifactPattern left = ArtifactPattern.parse(a);
            ArtifactPattern right = ArtifactPattern.parse(b);
            assertThat(left.commonCoordinate(right)).isEqualTo(expected);
        }
    }

    @Test
    void catchAllMatchesAnythingAtLowestSpecificity() {
        var star = ArtifactPattern.parse("*");
        assertThat(star.matches(new ArtifactCoords("any.ns", "x", "", "jar", "9"))).isTrue();
        assertThat(star.specificity()).isEqualTo(0);
    }

    @Test
    void fourSegmentPatternRejected() {
        assertThatThrownBy(() -> ArtifactPattern.parse("a:b:c:d"))
                .isInstanceOf(PolicyConfigException.class);
    }
}
