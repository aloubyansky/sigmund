package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.AssessmentRequest;
import dev.cyberstamp.sigmund.core.ArtifactIdentity;
import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustResult;
import dev.cyberstamp.sigmund.core.TrustVerdict;
import dev.cyberstamp.sigmund.core.TrustVerifier;
import dev.cyberstamp.sigmund.core.UntrustedPolicy;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;

/**
 * Verifies dependency signatures against the trust policy defined in sigmund.yaml.
 * <p>
 * This task resolves all dependencies from a specified Gradle configuration,
 * locates their signature files, and verifies them against the trust policy.
 * It reports trusted, untrusted, and unsigned artifacts and can fail the build
 * based on the configured policy.
 */
public abstract class VerifyTask extends DefaultTask {

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
     * The name of the Gradle configuration to verify (e.g., "runtimeClasspath").
     * Defaults to "runtimeClasspath".
     *
     * @return the configuration name property
     */
    @Input
    public abstract Property<String> getConfigurationName();

    /**
     * The policy for handling untrusted artifacts ("fail" or "warn").
     * Defaults to "warn" if not specified.
     *
     * @return the untrusted policy property
     */
    @Input @Optional
    public abstract Property<String> getOnUntrusted();

    /**
     * Constructs a new VerifyTask with default configuration.
     */
    public VerifyTask() {
        getConfigurationName().convention("runtimeClasspath");
    }

    /**
     * Executes the verification task.
     * <p>
     * This method loads the Sigmund configuration, resolves dependencies from
     * the specified Gradle configuration, verifies their signatures against the
     * trust policy, and reports the results.
     *
     * @throws GradleException if the configuration is not found or if verification
     *         fails and the untrusted policy is set to "fail"
     */
    @TaskAction
    public void verify() {
        SigmundConfig config = loadConfig();
        TrustPolicy trustPolicy = config.trustPolicy();
        DiscoveryConfig discoveryConfig = config.discoveryConfig();

        Configuration gradleConfig = getProject().getConfigurations()
                .getByName(getConfigurationName().get());

        try (Sigmund sigmund = Sigmund.builder()
                .discoveryConfig(discoveryConfig)
                .toolsConfig(SigmundHelper.buildToolsConfig(getSqHome(), getGpgHome()))
                .build()) {

            GradleArtifactResolver resolver = new GradleArtifactResolver(
                    getLogger(), sigmund.signatureFileExtensions());
            List<GradleArtifactResolver.ResolvedArtifactFiles> artifacts =
                    resolver.resolve(gradleConfig);

            TrustVerifier verifier = sigmund.verifier(trustPolicy);

            List<AssessmentRequest> requests = new ArrayList<>();
            List<String> coords = new ArrayList<>();
            List<String> skipped = new ArrayList<>();

            for (var artifact : artifacts) {
                ArtifactIdentity id = new GradleArtifactIdentity(
                        artifact.groupId(), artifact.artifactId(), artifact.version());
                if (trustPolicy.isUnsignedAllowed(id)) {
                    skipped.add(artifact.coordinates());
                    continue;
                }
                requests.add(new AssessmentRequest(
                        id, artifact.artifactFile(), artifact.evidenceFiles()));
                coords.add(artifact.coordinates());
            }

            getLogger().lifecycle("Verifying signers for {} dependency(ies)...",
                    requests.size());

            List<TrustResult> results = verifier.assessAll(requests);
            reportAndFail(results, coords, skipped);
        }
    }

    /**
     * Reports verification results and fails the build if necessary.
     *
     * @param results the list of trust verification results
     * @param coords the list of artifact coordinates corresponding to the results
     * @param skipped the list of artifact coordinates that were skipped
     * @throws GradleException if the untrusted policy is "fail" and there are failures
     */
    private void reportAndFail(List<TrustResult> results, List<String> coords,
            List<String> skipped) {
        int passed = 0;
        List<String> failures = new ArrayList<>();
        for (int i = 0; i < results.size(); i++) {
            TrustResult result = results.get(i);
            if (result.verdict() == TrustVerdict.TRUSTED) {
                passed++;
                getLogger().lifecycle("  TRUSTED: {}", coords.get(i));
            } else {
                getLogger().error("  {}: {}", result.verdict(), coords.get(i));
                failures.add(coords.get(i) + ": " + result.verdict().name().toLowerCase());
            }
        }
        if (!skipped.isEmpty()) {
            getLogger().lifecycle("  {} dependency(ies) skipped (unsigned allowed)", skipped.size());
        }
        getLogger().lifecycle("Summary: {} passed, {} failed, {} skipped",
                passed, failures.size(), skipped.size());

        UntrustedPolicy policy = parseUntrustedPolicy();
        if (policy == UntrustedPolicy.FAIL && !failures.isEmpty()) {
            throw new GradleException(
                    failures.size() + " artifact(s) failed signer verification:\n"
                            + String.join("\n", failures));
        }
    }

    /**
     * Parses the untrusted policy from the task property.
     *
     * @return the parsed UntrustedPolicy
     * @throws GradleException if the policy value is invalid
     */
    private UntrustedPolicy parseUntrustedPolicy() {
        if (!getOnUntrusted().isPresent()) {
            return UntrustedPolicy.WARN;
        }
        return switch (getOnUntrusted().get().toLowerCase()) {
            case "fail" -> UntrustedPolicy.FAIL;
            case "warn" -> UntrustedPolicy.WARN;
            default -> throw new GradleException(
                    "Invalid onUntrusted value: " + getOnUntrusted().get());
        };
    }

    /**
     * Loads the Sigmund configuration from the specified file or default location.
     *
     * @return the loaded SigmundConfig
     * @throws GradleException if the configuration file is not found
     */
    private SigmundConfig loadConfig() {
        Path configPath = getConfigFile().isPresent()
                ? getConfigFile().get().getAsFile().toPath()
                : null;
        Path located = ConfigLoader.locate(configPath);
        if (located == null) {
            throw new GradleException("sigmund.yaml not found. "
                    + "Create one or set sigmund.configFile in build.gradle");
        }
        return ConfigLoader.load(located);
    }
}
