package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.plugin.MojoExecutionException;

/**
 * Base class for signing-related goals, providing shared parameters and
 * signer creation logic.
 */
abstract class AbstractSigningMojo extends AbstractSigmundMojo {

    protected Sigmund buildSigningSigmund() throws MojoExecutionException {
        try {
            SigmundConfig config = loadConfig();
            Sigmund.Builder builder = Sigmund.builder().config(config);

            List<String> toolchain = config.signingConfig().toolchain();
            ToolsConfig toolsConfig = config.toolsConfig();
            List<String> toolNames = toolchain.isEmpty()
                    ? DiscoveryConfig.DEFAULT_TOOL_PRIORITY
                    : toolchain;

            for (String toolName : toolNames) {
                Map<String, String> settings = mergeToolSettings(toolName, toolsConfig);
                try {
                    builder.addSigningTool(toolName, settings);
                } catch (SigmundException e) {
                    if (toolchain.contains(toolName)) {
                        throw e;
                    }
                    getLog().debug("Signing tool '" + toolName + "' not available, skipping");
                }
            }

            return builder.build();
        } catch (SigmundException e) {
            throw new MojoExecutionException("Failed to initialize signing tools", e);
        }
    }

    private Map<String, String> mergeToolSettings(String toolName,
            ToolsConfig toolsConfig) {
        Map<String, String> settings = new LinkedHashMap<>();
        ToolConfig toolConfig = toolsConfig.get(toolName);
        if (toolConfig != null) {
            settings.putAll(toolConfig.settings());
        }
        if ("sq".equals(toolName) && sqHome != null) {
            settings.put("home", sqHome.toPath().toString());
        }
        return settings;
    }
}
