package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The tool settings documented in the Tool Settings Tables of {@code docs/configuration.md}.
 *
 * <p>
 * Each tool's section says which {@code tools.<name>} it configures and lists one setting per
 * table row, its name in backticks in the first column.
 */
final class DocumentedToolSettings {

    static final Path CONFIGURATION = Path.of("..", "docs", "configuration.md");

    private static final Pattern TOOL_SECTION = Pattern.compile(
            "(?ms)^### [^\\n]*\\n\\s*Configured in the top-level `tools\\.([\\w-]+)` section\\.(.*?)(?=^##)");
    private static final Pattern SETTING_ROW = Pattern.compile("(?m)^\\| `([\\w-]+)` \\|");

    private DocumentedToolSettings() {
    }

    /**
     * Reads the documented settings of every tool.
     *
     * @return tool names mapped to their documented settings, in document order
     * @throws IOException if the documentation cannot be read
     */
    static Map<String, Set<String>> read() throws IOException {
        String text = Files.readString(CONFIGURATION);
        Map<String, Set<String>> tools = new LinkedHashMap<>();
        Matcher section = TOOL_SECTION.matcher(text);
        while (section.find()) {
            Set<String> settings = new LinkedHashSet<>();
            Matcher row = SETTING_ROW.matcher(section.group(2));
            while (row.find()) {
                settings.add(row.group(1));
            }
            tools.put(section.group(1), settings);
        }
        return tools;
    }
}
