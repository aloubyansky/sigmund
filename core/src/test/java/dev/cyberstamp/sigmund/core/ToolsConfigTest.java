package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ToolsConfigTest {

    @Test
    void getReturnsTool() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(null, Map.of("key", "val"))));
        assertNotNull(tc.get("bc"));
        assertEquals("val", tc.get("bc").settings().get("key"));
    }

    @Test
    void getReturnsNullForUnknown() {
        var tc = ToolsConfig.EMPTY;
        assertNull(tc.get("bc"));
    }

    @Test
    void toolNamesReturnsAllKeys() {
        var tc = new ToolsConfig(Map.of(
                "bc", new ToolConfig(null, Map.of()),
                "sq", new ToolConfig(null, Map.of())));
        assertEquals(2, tc.toolNames().size());
        assertTrue(tc.toolNames().contains("bc"));
        assertTrue(tc.toolNames().contains("sq"));
    }

    @Test
    void emptyConfig() {
        assertTrue(ToolsConfig.EMPTY.isEmpty());
        assertEquals(0, ToolsConfig.EMPTY.size());
    }

    @Test
    void nonEmptyConfig() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(null, Map.of())));
        assertFalse(tc.isEmpty());
        assertEquals(1, tc.size());
    }

    @Test
    void nullMapBecomesEmpty() {
        var tc = new ToolsConfig(null);
        assertTrue(tc.isEmpty());
        assertEquals(0, tc.size());
    }
}
