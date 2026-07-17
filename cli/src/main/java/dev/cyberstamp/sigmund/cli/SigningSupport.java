package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared logic for CLI commands that build a signing-capable Sigmund instance.
 */
final class SigningSupport {

    private SigningSupport() {
    }

    static Sigmund buildSigningSigmund(SigmundConfig config, SqHomeMixin sqHomeMixin) {
        Sigmund.Builder builder = Sigmund.builder().config(config);

        Map<String, ToolConfig> configuredTools = config.signingConfig().tools();
        List<String> toolNames = configuredTools.isEmpty()
                ? ToolsConfig.DEFAULT_TOOL_PRIORITY
                : List.copyOf(configuredTools.keySet());

        for (String toolName : toolNames) {
            Map<String, String> settings = mergeToolSettings(
                    toolName, configuredTools, sqHomeMixin);
            try {
                builder.addSigningTool(toolName, settings);
            } catch (SigmundException e) {
                if (configuredTools.containsKey(toolName)) {
                    throw e;
                }
                System.err.println("Note: signing tool '" + toolName + "' not available, skipping");
            }
        }

        return builder.build();
    }

    private static Map<String, String> mergeToolSettings(String toolName,
            Map<String, ToolConfig> configuredTools, SqHomeMixin sqHomeMixin) {
        Map<String, String> settings = new HashMap<>();
        ToolConfig toolConfig = configuredTools.get(toolName);
        if (toolConfig != null) {
            settings.putAll(toolConfig.settings());
        }
        if ("sq".equals(toolName) && sqHomeMixin != null && sqHomeMixin.hasExplicitHome()) {
            settings.put("home", sqHomeMixin.resolveSequoiaHome().toString());
        }
        return settings;
    }
}
