package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactSetsConfigTest {

    @Nested
    class Lookup {
        @Test
        void returnsAGroupsPatternsByName() {
            var config = new ArtifactSetsConfig(Map.of(
                    "apache-stack", List.of("org.apache.maven.*", "org.apache.commons.*")));
            assertThat(config.get("apache-stack"))
                    .containsExactly("org.apache.maven.*", "org.apache.commons.*");
        }

        @Test
        void returnsNullForAnUnknownName() {
            var config = new ArtifactSetsConfig(Map.of("internal", List.of("com.internal.*")));
            assertThat(config.get("com.example:mylib")).isNull();
        }

        @Test
        void emptyConfig() {
            assertThat(ArtifactSetsConfig.EMPTY.isEmpty()).isTrue();
        }
    }
}
