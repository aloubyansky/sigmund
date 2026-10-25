package dev.cyberstamp.sigmund.core;

import java.util.Map;

/**
 * One tool's settings from the top-level {@code tools} section.
 * <p>
 * Settings are single values keyed by name, as written. The parser checks only their shape;
 * which settings a tool accepts is declared by its {@link SignatureToolFactory#acceptedSettings()} and
 * checked when tools are built.
 *
 * @param settings tool-specific settings (e.g., {@code gnupg-home} for bc)
 */
public record ToolConfig(Map<String, String> settings) {

    /**
     * Creates a tool config with a defensive copy.
     */
    public ToolConfig {
        settings = settings != null ? Map.copyOf(settings) : Map.of();
    }
}
