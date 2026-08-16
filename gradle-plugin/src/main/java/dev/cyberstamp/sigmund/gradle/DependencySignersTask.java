package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignatureVerificationReport;
import dev.cyberstamp.sigmund.core.VerifyResult;
import java.nio.file.Path;
import java.util.List;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;

/**
 * Reports signer information for all dependencies in a configuration.
 * <p>
 * This task inspects all dependencies, identifies which are signed,
 * verifies their signatures, and reports the signers. It can optionally
 * generate a trust configuration based on the findings.
 */
public abstract class DependencySignersTask extends DefaultTask {

    /**
     * The path to the sigmund.yaml configuration file.
     *
     * @return the configuration file property
     */
    @Internal
    public abstract RegularFileProperty getConfigFile();

    /**
     * The home directory for Sequoia (sq) tool.
     *
     * @return the Sequoia home directory property
     */
    @Internal
    public abstract RegularFileProperty getSqHome();

    /**
     * The home directory for GPG tool.
     *
     * @return the GPG home directory property
     */
    @Internal
    public abstract RegularFileProperty getGpgHome();

    /**
     * The name of the Gradle configuration to inspect (e.g., "runtimeClasspath").
     * Defaults to "runtimeClasspath".
     *
     * @return the configuration name property
     */
    @Input
    public abstract Property<String> getConfigurationName();

    /**
     * Whether to generate a trust configuration file from the findings.
     * Defaults to false.
     *
     * @return the generate trust config property
     */
    @Input @Optional
    public abstract Property<Boolean> getGenerateTrustConfig();

    /**
     * Constructs a new DependencySignersTask with default configuration.
     */
    public DependencySignersTask() {
        getConfigurationName().convention("runtimeClasspath");
        getGenerateTrustConfig().convention(false);
    }

    /**
     * Executes the dependency signers reporting task.
     * <p>
     * This method resolves all dependencies from the specified configuration,
     * inspects their signatures, verifies signers, and reports the findings.
     */
    @TaskAction
    public void report() {
        SigmundConfig config = loadConfig();
        DiscoveryConfig discoveryConfig = config != null
                ? config.discoveryConfig() : DiscoveryConfig.DEFAULT;

        var gradleConfig = getProject().getConfigurations()
                .getByName(getConfigurationName().get());

        try (Sigmund sigmund = Sigmund.builder()
                .discoveryConfig(discoveryConfig)
                .toolsConfig(SigmundHelper.buildToolsConfig(getSqHome(), getGpgHome()))
                .build()) {

            GradleArtifactResolver resolver = new GradleArtifactResolver(
                    getLogger(), sigmund.signatureFileExtensions());
            List<GradleArtifactResolver.ResolvedArtifactFiles> artifacts =
                    resolver.resolve(gradleConfig);

            getLogger().lifecycle("Inspecting signatures for {} dependency(ies)...",
                    artifacts.size());

            int signed = 0;
            int unsigned = 0;
            for (var artifact : artifacts) {
                if (artifact.evidenceFiles().isEmpty()) {
                    unsigned++;
                    getLogger().warn("  UNSIGNED: {}", artifact.coordinates());
                    continue;
                }
                signed++;
                for (Path sigFile : artifact.evidenceFiles()) {
                    SignatureVerificationReport report = sigmund.verify(
                            artifact.artifactFile(), sigFile);
                    for (var fileReport : report.files()) {
                        for (VerifyResult vr : fileReport.results()) {
                            String signer = vr.signerDisplayName() != null
                                    ? vr.signerDisplayName() : "unknown";
                            String algo = vr.algorithm() != null
                                    ? " (" + vr.algorithm() + ")" : "";
                            getLogger().lifecycle("  {}: {} — {}{}",
                                    vr.verdict(), artifact.coordinates(), signer, algo);
                        }
                    }
                }
            }

            getLogger().lifecycle("");
            getLogger().lifecycle("Summary: {} signed, {} unsigned, {} total",
                    signed, unsigned, artifacts.size());
        }
    }

    /**
     * Loads the Sigmund configuration from the specified file or default location.
     *
     * @return the loaded SigmundConfig, or null if no config is found
     */
    private SigmundConfig loadConfig() {
        if (getConfigFile().isPresent()) {
            return ConfigLoader.load(getConfigFile().get().getAsFile().toPath());
        }
        Path located = ConfigLoader.locate(null);
        return located != null ? ConfigLoader.load(located) : null;
    }
}
