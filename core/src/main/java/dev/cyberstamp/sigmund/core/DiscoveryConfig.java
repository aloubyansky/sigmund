package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * Configuration for signature discovery and verification operations,
 * parsed from the {@code discovery} section of {@code sigmund.yaml}.
 * <p>
 * Contains operational concerns: key fetching behavior, keyserver URLs,
 * and the verification toolchain. Per-tool settings live in {@link ToolsConfig}.
 *
 * @param resolveSigners whether tools should fetch missing keys to resolve signer identities
 * @param importToKeyring whether to persist fetched keys into the tool's keyring
 * @param keyservers keyserver URLs for key fetching (empty = default)
 * @param toolchain tools to use for verification and their order; {@code null} means all available
 * @see ToolsConfig
 * @see SigmundConfig
 */
public record DiscoveryConfig(
        boolean resolveSigners,
        boolean importToKeyring,
        List<String> keyservers,
        List<String> toolchain) {

    /** Default keyserver. */
    public static final String DEFAULT_KEYSERVER = "hkps://keys.openpgp.org";

    /** Default tool priority order. */
    public static final List<String> DEFAULT_TOOL_PRIORITY = List.of("bc", "sq", "gpg");

    /** Default discovery configuration. */
    public static final DiscoveryConfig DEFAULT = new DiscoveryConfig(
            true, false, List.of(DEFAULT_KEYSERVER), null);

    /**
     * Creates a discovery config with defensive copies.
     */
    public DiscoveryConfig {
        keyservers = keyservers != null && !keyservers.isEmpty()
                ? List.copyOf(keyservers)
                : List.of(DEFAULT_KEYSERVER);
        toolchain = toolchain != null && !toolchain.isEmpty()
                ? List.copyOf(toolchain)
                : null;
    }

    /**
     * Returns the toolchain for iteration, falling back to the default order
     * when {@link #toolchain()} is {@code null}.
     *
     * @return the effective toolchain list, never {@code null}
     */
    public List<String> effectiveToolchain() {
        return toolchain != null ? toolchain : DEFAULT_TOOL_PRIORITY;
    }

    /**
     * Parses a comma-separated keyservers string from tool settings.
     * Used by tool factories to read the injected {@code "keyservers"} setting.
     *
     * @param value comma-separated keyserver URLs, or {@code null}
     * @return the parsed list, or an empty list if the input is null or blank
     */
    public static List<String> parseKeyserversSetting(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.of(value.split(","));
    }
}
