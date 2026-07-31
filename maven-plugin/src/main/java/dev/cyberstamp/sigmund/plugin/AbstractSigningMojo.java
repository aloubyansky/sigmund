package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.util.HashMap;
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

            Map<String, ToolConfig> configuredTools = config.signingConfig().tools();
            List<String> toolNames = configuredTools.isEmpty()
                    ? ToolsConfig.DEFAULT_TOOL_PRIORITY
                    : List.copyOf(configuredTools.keySet());

            for (String toolName : toolNames) {
                Map<String, String> settings = mergeToolSettings(toolName, configuredTools);
                try {
                    builder.addSigningTool(toolName, settings);
                } catch (SigmundException e) {
                    if (configuredTools.containsKey(toolName)) {
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

    protected Signer createSigner() throws MojoExecutionException {
        return buildSigningSigmund().signer();
    }

    protected Signer createSigner(String profile) throws MojoExecutionException {
        return buildSigningSigmund().signer(profile);
    }

    private Map<String, String> mergeToolSettings(String toolName,
            Map<String, ToolConfig> configuredTools) {
        Map<String, String> settings = new HashMap<>();
        ToolConfig toolConfig = configuredTools.get(toolName);
        if (toolConfig != null) {
            settings.putAll(toolConfig.settings());
        }
        if ("sq".equals(toolName) && sqHome != null) {
            settings.put("home", sqHome.toPath().toString());
        }
        return settings;
    }
}
