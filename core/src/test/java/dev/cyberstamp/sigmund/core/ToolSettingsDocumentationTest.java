package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Every built-in tool accepts exactly the settings its table in {@code configuration.md} lists.
 *
 * <p>
 * Settings are checked when tools are built, so a documented setting the tool does not declare
 * is rejected the first time someone copies it, and a declared one missing from the table is a
 * setting nobody can find. Sigstore's table is checked in its own module.
 */
class ToolSettingsDocumentationTest {

    @Test
    void builtInToolsAcceptTheirDocumentedSettings() throws IOException {
        Map<String, Set<String>> documented = DocumentedToolSettings.read();

        for (SignatureToolFactory factory : List.of(new BcToolFactory(), new GpgToolFactory(),
                new SqToolFactory())) {
            assertThat(factory.acceptedSettings())
                    .as("settings of %s", factory.toolName())
                    .containsExactlyInAnyOrderElementsOf(documented.get(factory.toolName()));
        }
    }
}
