package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ToolsConfigTest {

    @Test
    void getReturnsTool() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(null, Map.of("key", "val"))));
        assertThat(tc.get("bc")).isNotNull();
        assertThat(tc.get("bc").settings().get("key")).isEqualTo("val");
    }

    @Test
    void getReturnsNullForUnknown() {
        var tc = ToolsConfig.EMPTY;
        assertThat(tc.get("bc")).isNull();
    }

    @Test
    void toolNamesReturnsAllKeys() {
        var tc = new ToolsConfig(Map.of(
                "bc", new ToolConfig(null, Map.of()),
                "sq", new ToolConfig(null, Map.of())));
        assertThat(tc.toolNames().size()).isEqualTo(2);
        assertThat(tc.toolNames().contains("bc")).isTrue();
        assertThat(tc.toolNames().contains("sq")).isTrue();
    }

    @Test
    void emptyConfig() {
        assertThat(ToolsConfig.EMPTY.isEmpty()).isTrue();
        assertThat(ToolsConfig.EMPTY.size()).isEqualTo(0);
    }

    @Test
    void nonEmptyConfig() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(null, Map.of())));
        assertThat(tc.isEmpty()).isFalse();
        assertThat(tc.size()).isEqualTo(1);
    }

    @Test
    void nullMapBecomesEmpty() {
        var tc = new ToolsConfig(null);
        assertThat(tc.isEmpty()).isTrue();
        assertThat(tc.size()).isEqualTo(0);
    }
}
