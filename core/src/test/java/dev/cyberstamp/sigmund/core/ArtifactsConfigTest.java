package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactsConfigTest {

    @Nested
    class GroupExpansion {
        @Test
        void expandsTrustMappingGroupNames() {
            var config = new ArtifactsConfig(Map.of(
                    "apache-stack", List.of("org.apache.maven.*", "org.apache.commons.*")));
            var raw = Map.of("apache-stack", List.of("apache"));
            var expanded = config.expandTrustMappings(raw);
            assertThat(expanded.containsKey("org.apache.maven.*")).isTrue();
            assertThat(expanded.containsKey("org.apache.commons.*")).isTrue();
            assertThat(expanded.containsKey("apache-stack")).isFalse();
        }

        @Test
        void preservesLiteralPatternsWhenNoGroupMatch() {
            var config = new ArtifactsConfig(Map.of());
            var raw = Map.of("com.example:mylib", List.of("alice"));
            var expanded = config.expandTrustMappings(raw);
            assertThat(expanded.containsKey("com.example:mylib")).isTrue();
        }

        @Test
        void expandsPatternList() {
            var config = new ArtifactsConfig(Map.of(
                    "internal", List.of("com.internal.*", "com.internal2.*")));
            var expanded = config.expandPatterns(List.of("internal", "com.other.*"));
            assertThat(expanded.size()).isEqualTo(3);
            assertThat(expanded.contains("com.internal.*")).isTrue();
            assertThat(expanded.contains("com.other.*")).isTrue();
        }

        @Test
        void emptyConfig() {
            assertThat(ArtifactsConfig.EMPTY.isEmpty()).isTrue();
        }
    }
}
