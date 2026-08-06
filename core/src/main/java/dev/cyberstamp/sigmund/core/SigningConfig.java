package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Configures which identity to sign as and which signing tools to use.
 * <p>
 * References a signer from the shared {@code signers} registry by name.
 * The {@code toolchain} specifies which tools to use for signing and their
 * priority order. Profiles select subsets of credential types for different
 * signing scenarios.
 *
 * <h2>Toolchain resolution</h2>
 * <p>
 * The {@code toolchain} list defines which signing tools to use and in what order.
 * If empty or {@code null}, the default toolchain from {@link DiscoveryConfig} is used.
 * Each tool name must have a corresponding entry in the top-level {@code tools} registry
 * for configuration lookup during initialization.
 *
 * @param signer the signer identity name (e.g., {@code "alice"}), or {@code null}
 * @param toolchain tools to use for signing and their priority order; empty means use default
 * @param profiles named profiles mapping to credential type lists
 * @param defaultProfile the default profile name, or {@code null} to use all credentials
 * @see DiscoveryConfig#effectiveToolchain()
 * @see ToolsConfig
 */
public record SigningConfig(
        String signer,
        List<String> toolchain,
        Map<String, List<String>> profiles,
        String defaultProfile) {

    /**
     * Default signing configuration: no signer, empty toolchain, no profiles.
     */
    public static final SigningConfig DEFAULT = new SigningConfig(null, List.of(), Map.of(), null);

    /**
     * Creates a signing config with defensive copies.
     */
    public SigningConfig {
        toolchain = toolchain != null ? List.copyOf(toolchain) : List.of();
        profiles = profiles != null ? Map.copyOf(profiles) : Map.of();
    }
}
