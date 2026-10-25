package dev.cyberstamp.sigmund.core;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * One setting a tool reads from its settings map, named once.
 * <p>
 * A tool factory declares its settings as an enum implementing this interface, reads them only
 * through it and derives {@link SignatureToolFactory#acceptedSettings()} from the enum's values.
 * Reading a setting and accepting it are then the same symbol: a new setting cannot be read
 * without being declared, and one that is no longer read shows as an unused constant rather
 * than as a setting that is accepted and ignored.
 */
public interface ToolSetting {

    /**
     * Returns the setting's name as written under {@code tools.<name>} in {@code sigmund.yaml}.
     *
     * @return the key, never {@code null}
     */
    String key();

    /**
     * Reads this setting.
     *
     * @param settings the tool's settings
     * @return the value, or {@code null} when not set
     */
    default String from(Map<String, String> settings) {
        return settings.get(key());
    }

    /**
     * Reads this setting, falling back to a default.
     *
     * @param settings the tool's settings
     * @param defaultValue the value when not set
     * @return the value, or {@code defaultValue} when not set
     */
    default String from(Map<String, String> settings, String defaultValue) {
        return settings.getOrDefault(key(), defaultValue);
    }

    /**
     * Reads this setting as a flag.
     *
     * @param settings the tool's settings
     * @return {@code true} only when the value is {@code true}
     */
    default boolean isTrue(Map<String, String> settings) {
        return "true".equals(from(settings));
    }

    /**
     * Returns the keys of the given settings, for {@link SignatureToolFactory#acceptedSettings()}.
     *
     * @param settings the settings, typically an enum's {@code values()}
     * @return their keys
     */
    static Set<String> keysOf(ToolSetting... settings) {
        return Arrays.stream(settings).map(ToolSetting::key).collect(Collectors.toUnmodifiableSet());
    }
}
