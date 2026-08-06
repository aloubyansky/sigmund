package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;

/**
 * Unified configuration parsed from a single YAML file ({@code sigmund.yaml}).
 * <p>
 * Produces separate typed objects for different consumers while keeping the
 * user's configuration in one place. {@code signers} is a top-level shared
 * registry of known identities — referenced by both {@link TrustPolicy}
 * (via trust mappings) and {@link SigningConfig} (via signer name).
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * SigmundConfig config = SigmundConfig.parse(Path.of("sigmund.yaml"));
 * TrustPolicy policy = config.trustPolicy();
 * SigningConfig signing = config.signingConfig();
 * ToolsConfig tools = config.toolsConfig();
 * DiscoveryConfig discovery = config.discoveryConfig();
 * }</pre>
 *
 * @param version the schema version (currently 1)
 * @param signers shared identity registry
 * @param artifacts named groups of artifact patterns for reuse in trust/unsigned sections
 * @param trustPolicy the trust policy parsed from trust/unsigned/policy sections
 * @param signingConfig the signing configuration parsed from the signing section
 * @param toolsConfig the per-tool configuration registry parsed from the top-level tools section
 * @param discoveryConfig the discovery configuration parsed from the discovery section
 * @see SigmundConfigParser
 */
public record SigmundConfig(
        int version,
        SignersConfig signers,
        ArtifactsConfig artifacts,
        TrustPolicy trustPolicy,
        SigningConfig signingConfig,
        ToolsConfig toolsConfig,
        DiscoveryConfig discoveryConfig) {

    /**
     * Creates a config with defensive defaults for null fields.
     */
    public SigmundConfig {
        if (signers == null) {
            signers = SignersConfig.EMPTY;
        }
        if (artifacts == null) {
            artifacts = ArtifactsConfig.EMPTY;
        }
        if (trustPolicy == null) {
            trustPolicy = DefaultTrustPolicy.EMPTY;
        }
        if (signingConfig == null) {
            signingConfig = SigningConfig.DEFAULT;
        }
        if (toolsConfig == null) {
            toolsConfig = ToolsConfig.EMPTY;
        }
        if (discoveryConfig == null) {
            discoveryConfig = DiscoveryConfig.DEFAULT;
        }
    }

    /**
     * Parses a {@code sigmund.yaml} configuration file.
     *
     * @param file the path to the YAML file
     * @return the parsed configuration
     * @throws PolicyConfigException if the file cannot be read or contains invalid configuration
     */
    public static SigmundConfig parse(Path file) {
        return SigmundConfigParser.parse(file);
    }
}
