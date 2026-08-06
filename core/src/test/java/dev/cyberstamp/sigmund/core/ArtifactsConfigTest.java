package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

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
            assertTrue(expanded.containsKey("org.apache.maven.*"));
            assertTrue(expanded.containsKey("org.apache.commons.*"));
            assertFalse(expanded.containsKey("apache-stack"));
        }

        @Test
        void preservesLiteralPatternsWhenNoGroupMatch() {
            var config = new ArtifactsConfig(Map.of());
            var raw = Map.of("com.example:mylib", List.of("alice"));
            var expanded = config.expandTrustMappings(raw);
            assertTrue(expanded.containsKey("com.example:mylib"));
        }

        @Test
        void expandsPatternList() {
            var config = new ArtifactsConfig(Map.of(
                    "internal", List.of("com.internal.*", "com.internal2.*")));
            var expanded = config.expandPatterns(List.of("internal", "com.other.*"));
            assertEquals(3, expanded.size());
            assertTrue(expanded.contains("com.internal.*"));
            assertTrue(expanded.contains("com.other.*"));
        }

        @Test
        void emptyConfig() {
            assertTrue(ArtifactsConfig.EMPTY.isEmpty());
        }
    }
}
