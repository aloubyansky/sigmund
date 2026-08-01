package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Base class for mojos that need a configured {@link Sigmund} instance but do
 * not require Maven dependency resolution.
 *
 * <p>
 * Provides shared parameter handling (Sequoia home, GPG home, skip flag),
 * configuration loading, tool-override merging, and {@link Sigmund} builder
 * construction. Subclasses like {@link InspectSignerMojo} extend this directly;
 * mojos that also need dependency resolution extend {@link AbstractDependencyMojo}
 * instead.
 */
abstract class AbstractSigmundMojo extends AbstractMojo {

    @Parameter(property = "sigmund.sqHome")
    protected File sqHome;

    @Parameter(property = "sigmund.gpgHome")
    protected File gpgHome;

    @Parameter(property = "sigmund.skip", defaultValue = "false")
    protected boolean skip;

    /**
     * Loads the sigmund configuration from the default location.
     *
     * @return the parsed configuration
     * @throws MojoExecutionException if the configuration cannot be loaded
     */
    protected SigmundConfig loadConfig() throws MojoExecutionException {
        try {
            return ConfigLoader.load(null);
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to load config", e);
        }
    }

    /**
     * Builds tool-specific configuration overrides from Maven properties.
     *
     * <p>
     * Merges Sequoia home ({@code sqHome}) and GnuPG home ({@code gpgHome})
     * overrides into a map keyed by tool name. When {@code gpgHome} is set,
     * it also configures the BC tool's GnuPG home, cert-d, and private key
     * store paths relative to it.
     *
     * @return tool overrides map, possibly empty but never null
     */
    protected Map<String, Map<String, String>> toolOverrides() {
        var overrides = new HashMap<>(SequoiaHomeResolver.toolOverrides(sqHome));
        if (gpgHome != null) {
            String gpgHomePath = gpgHome.toPath().toString();
            overrides.put("gpg", Map.of("home", gpgHomePath));
            overrides.put("bc", Map.of(
                    "gnupg-home", gpgHomePath,
                    "cert-d-home", gpgHomePath + "/cert-d",
                    "bc-private-home", gpgHomePath + "/bc-private"));
        }
        return overrides;
    }

    /**
     * Merges file-based {@link ToolsConfig} with Maven property overrides.
     *
     * <p>
     * Each parameter, when non-null, takes precedence over the file configuration.
     * If signer resolution is enabled but no keyservers are configured, the
     * {@link ToolsConfig#DEFAULT_KEYSERVER default keyserver} is used. Tool
     * overrides from {@link #toolOverrides()} are merged into the file config's
     * per-tool settings.
     *
     * @param fileConfig base configuration from the config file
     * @param resolveSigners override for signer resolution, or {@code null} to use file config
     * @param keyservers comma-separated keyserver list override, or {@code null} to use file config
     * @param importToKeyring override for key import behavior, or {@code null} to use file config
     * @return the resolved tools configuration
     */
    protected ToolsConfig resolveToolsConfig(ToolsConfig fileConfig,
            Boolean resolveSigners, String keyservers, Boolean importToKeyring) {
        if (keyservers == null) {
            keyservers = System.getProperty("sigmund.keyserver");
        }
        List<String> effectiveKeyservers = keyservers != null
                ? SignatureInspector.parseKeyservers(keyservers)
                : fileConfig.keyservers();
        boolean effectiveResolve = resolveSigners != null
                ? resolveSigners
                : (keyservers != null || fileConfig.resolveSigners());
        if (effectiveResolve && effectiveKeyservers.isEmpty()) {
            effectiveKeyservers = List.of(ToolsConfig.DEFAULT_KEYSERVER);
        }
        boolean effectiveImport = importToKeyring != null
                ? importToKeyring
                : fileConfig.importToKeyring();
        Map<String, Map<String, String>> mergedTools = new HashMap<>(fileConfig.tools());
        for (var override : toolOverrides().entrySet()) {
            mergedTools.merge(override.getKey(), override.getValue(), (existing, incoming) -> {
                var merged = new HashMap<>(existing);
                merged.putAll(incoming);
                return Map.copyOf(merged);
            });
        }
        return new ToolsConfig(
                effectiveResolve, effectiveImport,
                effectiveKeyservers, mergedTools, fileConfig.toolPriority());
    }

    /**
     * Builds a {@link Sigmund} instance with the given tools configuration.
     *
     * @param toolsConfig the resolved tools configuration
     * @return a configured Sigmund instance
     * @throws MojoExecutionException if Sigmund construction fails
     */
    protected Sigmund buildSigmund(ToolsConfig toolsConfig) throws MojoExecutionException {
        return Sigmund.builder()
                .toolsConfig(toolsConfig)
                .build();
    }
}
