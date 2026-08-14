package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TrustPatternCollapseTest {

    // -- Within-group collapsing -----------------------------------------

    @Nested
    class WithinGroupTests {

        @Test
        void singleArtifactNotCollapsed() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.example:lib", Set.of("alice")));
            assertThat(result).isEqualTo(expected("com.example:lib", List.of("alice")));
        }

        @Test
        void twoArtifactsSameSignerCollapsed() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.example:lib-a", Set.of("alice"),
                    "com.example:lib-b", Set.of("alice")));
            assertThat(result).isEqualTo(expected("com.example.*", List.of("alice")));
        }

        @Test
        void majoritySignerCollapseWithException() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.example:lib-a", Set.of("alice"),
                    "com.example:lib-b", Set.of("alice"),
                    "com.example:lib-c", Set.of("bob")));
            assertThat(result).isEqualTo(expected(
                    "com.example.*", List.of("alice"),
                    "com.example:lib-c", List.of("bob")));
        }

        @Test
        void multipleSignersPerArtifact() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.example:lib-a", Set.of("alice", "bob"),
                    "com.example:lib-b", Set.of("alice", "bob")));
            assertThat(result.size()).isEqualTo(1);
            var signers = result.get("com.example.*");
            assertThat(signers).isNotNull();
            assertThat(signers.size()).isEqualTo(2);
            assertThat(signers.containsAll(List.of("alice", "bob"))).isTrue();
        }

        @Test
        void differentGroupsNotMixed() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.foo:lib-a", Set.of("alice"),
                    "com.foo:lib-b", Set.of("alice"),
                    "com.bar:lib-x", Set.of("bob"),
                    "com.bar:lib-y", Set.of("bob")));
            assertThat(result).isEqualTo(expected(
                    "com.foo.*", List.of("alice"),
                    "com.bar.*", List.of("bob")));
        }
    }

    // -- Across-group collapsing -----------------------------------------

    @Nested
    class AcrossGroupTests {

        @Test
        void subgroupAbsorbedByParent() {
            var result = TrustPatternCollapse.collapse(input(
                    "io.quarkus:core", Set.of("guillaume"),
                    "io.quarkus:rest", Set.of("guillaume"),
                    "io.quarkus.arc:arc-impl", Set.of("guillaume"),
                    "io.quarkus.arc:arc-api", Set.of("guillaume")));
            assertThat(result).isEqualTo(expected("io.quarkus.*", List.of("guillaume")));
        }

        @Test
        void subgroupExceptionPreserved() {
            var result = TrustPatternCollapse.collapse(input(
                    "io.quarkus:core", Set.of("guillaume"),
                    "io.quarkus:rest", Set.of("guillaume"),
                    "io.quarkus:fs-util", Set.of("quarkus"),
                    "io.quarkus.arc:arc", Set.of("guillaume"),
                    "io.quarkus.arc:arc-api", Set.of("guillaume"),
                    "io.quarkus.security:quarkus-security", Set.of("quarkus")));
            assertThat(result).isEqualTo(expected(
                    "io.quarkus.*", List.of("guillaume"),
                    "io.quarkus:fs-util", List.of("quarkus"),
                    "io.quarkus.security:quarkus-security", List.of("quarkus")));
        }

        @Test
        void subgroupWithDifferentSignerNotAbsorbed() {
            var result = TrustPatternCollapse.collapse(input(
                    "io.quarkus:core", Set.of("guillaume"),
                    "io.quarkus:rest", Set.of("guillaume"),
                    "io.quarkus.security:sec-a", Set.of("other"),
                    "io.quarkus.security:sec-b", Set.of("other")));
            assertThat(result).isEqualTo(expected(
                    "io.quarkus.*", List.of("guillaume"),
                    "io.quarkus.security.*", List.of("other")));
        }

        @Test
        void deeplyNestedSubgroupAbsorbed() {
            var result = TrustPatternCollapse.collapse(input(
                    "org.apache:parent", Set.of("apache"),
                    "org.apache:core", Set.of("apache"),
                    "org.apache.maven:maven-api", Set.of("apache"),
                    "org.apache.maven:maven-core", Set.of("apache"),
                    "org.apache.maven.plugins:compiler", Set.of("apache"),
                    "org.apache.maven.plugins:surefire", Set.of("apache")));
            assertThat(result).isEqualTo(expected("org.apache.*", List.of("apache")));
        }
    }

    // -- Edge cases ------------------------------------------------------

    @Nested
    class EdgeCaseTests {

        @Test
        void emptyInput() {
            var result = TrustPatternCollapse.collapse(Map.of());
            assertThat(result.isEmpty()).isTrue();
        }

        @Test
        void allDifferentSigners() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.example:lib-a", Set.of("alice"),
                    "com.example:lib-b", Set.of("bob")));
            assertThat(result.containsKey("com.example.*")).isTrue();
            assertThat(result.size()).isEqualTo(2);
        }

        @Test
        void noCommonPrefix() {
            var result = TrustPatternCollapse.collapse(input(
                    "com.foo:lib", Set.of("alice"),
                    "org.bar:lib", Set.of("alice")));
            assertThat(result).isEqualTo(expected(
                    "com.foo:lib", List.of("alice"),
                    "org.bar:lib", List.of("alice")));
        }
    }

    /** Builds a {@code Map<String, Set<String>>} from alternating key/value pairs. */
    private static Map<String, Set<String>> input(Object... entries) {
        Map<String, Set<String>> map = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) {
            @SuppressWarnings("unchecked")
            Set<String> value = (Set<String>) entries[i + 1];
            map.put((String) entries[i], value);
        }
        return map;
    }

    /** Builds a {@code Map<String, List<String>>} from alternating key/value pairs. */
    private static Map<String, List<String>> expected(Object... entries) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) {
            @SuppressWarnings("unchecked")
            List<String> value = (List<String>) entries[i + 1];
            map.put((String) entries[i], value);
        }
        return map;
    }
}
