package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class DiscoveryConfigTest {

    @Test
    void defaultValues() {
        var config = DiscoveryConfig.DEFAULT;
        assertTrue(config.resolveSigners());
        assertFalse(config.importToKeyring());
        assertEquals(List.of(DiscoveryConfig.DEFAULT_KEYSERVER), config.keyservers());
        assertNull(config.toolchain());
    }

    @Test
    void effectiveToolchainFallsBackToDefault() {
        var config = DiscoveryConfig.DEFAULT;
        assertEquals(DiscoveryConfig.DEFAULT_TOOL_PRIORITY, config.effectiveToolchain());
    }

    @Test
    void effectiveToolchainUsesExplicitList() {
        var config = new DiscoveryConfig(true, false, List.of(), List.of("bc", "sq"));
        assertEquals(List.of("bc", "sq"), config.effectiveToolchain());
    }

    @Test
    void nullKeyserversFallsBackToDefault() {
        var config = new DiscoveryConfig(true, false, null, null);
        assertEquals(List.of(DiscoveryConfig.DEFAULT_KEYSERVER), config.keyservers());
    }
}
