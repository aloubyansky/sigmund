package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ToolsConfigTest {

    @Test
    void effectiveToolPriorityFallsBackToDefault() {
        assertEquals(ToolsConfig.DEFAULT_TOOL_PRIORITY,
                ToolsConfig.DEFAULT.effectiveToolPriority());
    }

    @Test
    void effectiveToolPriorityUsesExplicitList() {
        ToolsConfig config = new ToolsConfig(true, false, List.of(), Map.of(),
                List.of("gpg", "bc"));
        assertEquals(List.of("gpg", "bc"), config.effectiveToolPriority());
    }
}
