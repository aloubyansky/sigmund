package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.logging.Logger;

/**
 * Utility class providing helper methods for constructing Sigmund instances
 * and tool configurations in Gradle tasks.
 * <p>
 * This class centralizes the logic for building tool configurations from Gradle
 * properties and creating properly configured Sigmund instances for signing operations.
 */
final class SigmundHelper {

    private SigmundHelper() {
    }

    /**
     * Builds a ToolsConfig from optional Gradle file properties.
     * <p>
     * Configures tool home directories for Sequoia (sq), GPG, and Bouncy Castle (bc)
     * based on the provided Gradle file properties. If gpgHome is set, it also configures
     * cert-d and bc-private directories relative to the GPG home.
     *
     * @param sqHome optional Sequoia home directory property
     * @param gpgHome optional GPG home directory property
     * @return a ToolsConfig containing the configured tools, or ToolsConfig.EMPTY if no properties are set
     */
    static ToolsConfig buildToolsConfig(RegularFileProperty sqHome,
            RegularFileProperty gpgHome) {
        Map<String, ToolConfig> configs = new HashMap<>();
        addSequoiaConfig(configs, sqHome);
        addGpgConfigs(configs, gpgHome);
        return configs.isEmpty() ? ToolsConfig.EMPTY : new ToolsConfig(configs);
    }

    /**
     * Adds Sequoia tool configuration if the sqHome property is present.
     *
     * @param configs the map to add the configuration to
     * @param sqHome the optional Sequoia home directory property
     */
    private static void addSequoiaConfig(Map<String, ToolConfig> configs,
            RegularFileProperty sqHome) {
        if (sqHome.isPresent()) {
            String path = sqHome.get().getAsFile().toPath().toString();
            configs.put("sq", new ToolConfig(null, Map.of("home", path)));
        }
    }

    /**
     * Adds GPG and Bouncy Castle tool configurations if the gpgHome property is present.
     * <p>
     * Configures GPG with the provided home directory and also sets up Bouncy Castle
     * with gnupg-home, cert-d-home, and bc-private-home settings relative to the GPG home.
     *
     * @param configs the map to add the configurations to
     * @param gpgHome the optional GPG home directory property
     */
    private static void addGpgConfigs(Map<String, ToolConfig> configs,
            RegularFileProperty gpgHome) {
        if (gpgHome.isPresent()) {
            String path = gpgHome.get().getAsFile().toPath().toString();
            configs.put("gpg", new ToolConfig(null, Map.of("home", path)));
            configs.put("bc", new ToolConfig(null, Map.of(
                    "gnupg-home", path,
                    "cert-d-home", path + "/cert-d",
                    "bc-private-home", path + "/bc-private")));
        }
    }

    /**
     * Builds a Sigmund instance configured for signing operations.
     * <p>
     * This method creates a Sigmund instance with signing tools from the configuration's
     * toolchain (or default tools: bc, gpg, sq). It merges settings from the configuration
     * with any overrides from Gradle properties. Tools that fail to initialize are logged
     * and skipped unless explicitly required by the toolchain.
     *
     * @param config the Sigmund configuration to use
     * @param sqHome optional Sequoia home directory override
     * @param gpgHome optional GPG home directory override
     * @param logger the Gradle logger for debug output
     * @return a configured Sigmund instance with available signing tools
     * @throws SigmundException if a required tool from the toolchain fails to initialize
     */
    static Sigmund buildSigningSigmund(SigmundConfig config,
            RegularFileProperty sqHome, RegularFileProperty gpgHome,
            Logger logger) {
        Sigmund.Builder builder = Sigmund.builder().config(config);
        List<String> explicitToolchain = config.signingConfig().toolchain();
        List<String> toolNames = explicitToolchain.isEmpty()
                ? List.of("bc", "gpg", "sq")
                : explicitToolchain;
        ToolsConfig overrides = buildToolsConfig(sqHome, gpgHome);
        addSigningTools(builder, toolNames, config.toolsConfig(), overrides, explicitToolchain, logger);
        return builder.build();
    }

    /**
     * Adds signing tools to the Sigmund builder.
     * <p>
     * For each tool, merges settings from the base configuration and overrides,
     * then attempts to add it to the builder. If a tool fails to initialize,
     * throws an exception if it's in the explicit toolchain, otherwise logs
     * a debug message and continues.
     *
     * @param builder the Sigmund builder to add tools to
     * @param toolNames the list of tool names to add
     * @param baseConfig the base tool configuration from the Sigmund config
     * @param overrides the override tool configuration from Gradle properties
     * @param explicitToolchain the original explicit toolchain (before defaulting)
     * @param logger the Gradle logger for debug output
     * @throws SigmundException if a required tool from the toolchain fails to initialize
     */
    private static void addSigningTools(Sigmund.Builder builder, List<String> toolNames,
            ToolsConfig baseConfig, ToolsConfig overrides, List<String> explicitToolchain, Logger logger) {
        for (String toolName : toolNames) {
            Map<String, String> settings = mergeToolSettings(toolName, baseConfig, overrides);
            tryAddSigningTool(builder, toolName, settings, explicitToolchain, logger);
        }
    }

    /**
     * Merges tool settings from base configuration and overrides.
     *
     * @param toolName the name of the tool
     * @param baseConfig the base tool configuration
     * @param overrides the override tool configuration
     * @return a map containing the merged settings
     */
    private static Map<String, String> mergeToolSettings(String toolName,
            ToolsConfig baseConfig, ToolsConfig overrides) {
        Map<String, String> settings = new LinkedHashMap<>();
        ToolConfig tc = baseConfig.get(toolName);
        if (tc != null) {
            settings.putAll(tc.settings());
        }
        ToolConfig override = overrides.get(toolName);
        if (override != null) {
            settings.putAll(override.settings());
        }
        return settings;
    }

    /**
     * Attempts to add a signing tool to the builder.
     * <p>
     * If the tool fails to initialize and is part of an explicit toolchain,
     * the exception is propagated. Otherwise, logs a debug message and continues.
     *
     * @param builder the Sigmund builder
     * @param toolName the name of the tool to add
     * @param settings the merged settings for the tool
     * @param explicitToolchain the original explicit toolchain (before defaulting)
     * @param logger the Gradle logger for debug output
     * @throws SigmundException if the tool is in the explicit toolchain and fails to initialize
     */
    private static void tryAddSigningTool(Sigmund.Builder builder, String toolName,
            Map<String, String> settings, List<String> explicitToolchain, Logger logger) {
        try {
            builder.addSigningTool(toolName, settings);
        } catch (SigmundException e) {
            if (explicitToolchain.contains(toolName)) {
                throw e;
            }
            logger.debug("Signing tool '{}' not available, skipping", toolName);
        }
    }
}
