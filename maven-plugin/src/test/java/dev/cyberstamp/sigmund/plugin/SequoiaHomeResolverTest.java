package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SequoiaHomeResolverTest {

    @Test
    void toolOverridesWithExplicitPath() {
        File sqHome = new File("/custom/sequoia/home");
        Map<String, Map<String, String>> overrides = SequoiaHomeResolver.toolOverrides(sqHome);
        assertThat(overrides.get("sq").get("home")).isEqualTo(sqHome.toPath().toString());
    }

    @Test
    void toolOverridesWithNullReturnsEmpty() {
        Map<String, Map<String, String>> overrides = SequoiaHomeResolver.toolOverrides(null);
        assertThat(overrides.isEmpty()).isTrue();
    }
}
