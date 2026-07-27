package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Configuration for tool initialization, key fetching, and per-tool settings.
 * <p>
 * Separated from {@link TrustPolicy} because these are transport/infrastructure
 * concerns, not trust decisions. A trust policy backed by OPA or a database does
 * not need to know about keyservers or tool-specific settings.
 *
 * <h3>Key fetching behavior</h3>
 * <p>
 * When {@link #resolveSigners()} is {@code true} (the default), tools attempt to
 * fetch missing keys from keyservers to resolve signer identities (names and emails).
 * The behavior depends on {@link #importToKeyring()}:
 * <ul>
 * <li>{@code importToKeyring = false} (default) — BC fetches keys to an in-memory
 * cache, used for verification, and discarded when the JVM exits. Not persisted to disk.
 * GnuPG requires keys in its on-disk keyring and cannot do ephemeral imports — key
 * fetch is skipped when {@code importToKeyring} is {@code false}.</li>
 * <li>{@code importToKeyring = true} — keys are permanently imported into the tool's
 * keyring (BC cert-d, GPG keyring).</li>
 * </ul>
 * <p>
 * When {@link #resolveSigners()} is {@code false}, no key fetching is attempted by any tool.
 * <p>
 * When {@link #keyservers()} is empty, {@code hkps://keys.openpgp.org} is used as the default.
 *
 * @param resolveSigners whether tools should attempt to fetch missing keys to resolve signer identities
 * @param importToKeyring whether to persist fetched keys into the tool's keyring
 * @param keyservers keyserver URLs for key fetching (empty = default)
 * @param tools per-tool settings, keyed by tool name
 * @param toolPriority tools to use and their order; {@code null} means all available
 *        tools in the default order; an explicit list restricts to only those tools
 */
public record ToolsConfig(
        boolean resolveSigners,
        boolean importToKeyring,
        List<String> keyservers,
        Map<String, Map<String, String>> tools,
        List<String> toolPriority) {

    public static final String DEFAULT_KEYSERVER = "hkps://keys.openpgp.org";
    public static final List<String> DEFAULT_TOOL_PRIORITY = List.of("bc", "sq", "gpg");

    public static final ToolsConfig DEFAULT = new ToolsConfig(true, false, List.of(DEFAULT_KEYSERVER), Map.of(),
            null);

    /**
     * Creates a new tools configuration with defensive copies.
     * <p>
     * A {@code null} {@code toolPriority} means "initialize all available tools"
     * in the default order. An explicit list restricts to only those tools.
     */
    public ToolsConfig {
        keyservers = keyservers != null && !keyservers.isEmpty() ? List.copyOf(keyservers) : List.of(DEFAULT_KEYSERVER);
        tools = tools != null ? Map.copyOf(tools) : Map.of();
        toolPriority = toolPriority != null && !toolPriority.isEmpty() ? List.copyOf(toolPriority) : null;
    }

    /**
     * Returns the tool priority list for iteration, falling back to the default
     * order when {@link #toolPriority()} is {@code null}.
     *
     * @return the effective tool priority list, never {@code null}
     */
    public List<String> effectiveToolPriority() {
        return toolPriority != null ? toolPriority : DEFAULT_TOOL_PRIORITY;
    }

    /**
     * Parses a comma-separated keyservers string from the internal settings map.
     * Used by tool factories to read the injected {@code "keyservers"} setting.
     *
     * @param value comma-separated keyserver URLs, or {@code null}
     * @return the parsed list, or an empty list if the input is null or blank
     */
    static List<String> parseKeyserversSetting(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.of(value.split(","));
    }
}
