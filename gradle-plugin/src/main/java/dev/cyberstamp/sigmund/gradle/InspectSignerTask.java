package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.CredentialParser;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignerInspectionReport;
import dev.cyberstamp.sigmund.core.SignerInspectionReportFormatter;
import java.nio.file.Path;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;

/**
 * Gradle task for inspecting signer identity information.
 * <p>
 * This task inspects a signer's identity across configured public key discovery sources
 * (keyservers, web key directories, etc.) and verification tools. It can identify a
 * signer by:
 * <ul>
 *   <li>PGP fingerprint</li>
 *   <li>Email address</li>
 *   <li>Sigstore issuer and subject</li>
 * </ul>
 * <p>
 * The inspection report shows where the signer's credentials are found and their
 * verification status across different tools and key sources.
 * <p>
 * Example usage:
 * <pre>
 * sigmundInspectSigner {
 *     fingerprint = "1234567890ABCDEF"
 *     tool = "gpg" // optional: restrict to a specific tool
 * }
 * </pre>
 */
public abstract class InspectSignerTask extends DefaultTask {

    /**
     * Gets the optional configuration file for Sigmund.
     *
     * @return the configuration file property
     */
    @Internal
    public abstract RegularFileProperty getConfigFile();

    /**
     * Gets the optional Sequoia home directory.
     *
     * @return the Sequoia home directory property
     */
    @Internal
    public abstract RegularFileProperty getSqHome();

    /**
     * Gets the optional GPG home directory.
     *
     * @return the GPG home directory property
     */
    @Internal
    public abstract RegularFileProperty getGpgHome();

    /**
     * Gets the PGP fingerprint to inspect.
     * <p>
     * If set, this takes precedence over email and Sigstore credentials.
     *
     * @return the fingerprint property
     */
    @Input @Optional
    public abstract Property<String> getFingerprint();

    /**
     * Gets the email address to inspect.
     * <p>
     * Used if fingerprint is not set, takes precedence over Sigstore credentials.
     *
     * @return the email property
     */
    @Input @Optional
    public abstract Property<String> getEmail();

    /**
     * Gets the Sigstore issuer.
     * <p>
     * Must be used together with sigstoreSubject. Only used if fingerprint
     * and email are not set.
     *
     * @return the Sigstore issuer property
     */
    @Input @Optional
    public abstract Property<String> getSigstoreIssuer();

    /**
     * Gets the Sigstore subject.
     * <p>
     * Must be used together with sigstoreIssuer. Only used if fingerprint
     * and email are not set.
     *
     * @return the Sigstore subject property
     */
    @Input @Optional
    public abstract Property<String> getSigstoreSubject();

    /**
     * Gets the optional tool name to use for inspection.
     * <p>
     * If not set, all available tools will be used for inspection.
     *
     * @return the tool name property
     */
    @Input @Optional
    public abstract Property<String> getTool();

    /**
     * Performs signer inspection.
     * <p>
     * This method:
     * <ol>
     *   <li>Builds a credential from the provided properties</li>
     *   <li>Loads the Sigmund configuration</li>
     *   <li>Inspects the signer across discovery sources and tools</li>
     *   <li>Formats and logs the inspection report</li>
     * </ol>
     *
     * @throws GradleException if no valid credential is provided
     */
    @TaskAction
    public void inspect() {
        Credential credential = buildCredential();
        SigmundConfig config = loadConfig();

        try (Sigmund sigmund = createSigmund(config)) {
            SignerInspectionReport report = performInspection(sigmund, credential);
            logReport(report);
        }
    }

    /**
     * Builds a credential from the task properties.
     * <p>
     * Checks properties in order of precedence:
     * <ol>
     *   <li>Fingerprint</li>
     *   <li>Email</li>
     *   <li>Sigstore issuer + subject</li>
     * </ol>
     *
     * @return the credential to inspect
     * @throws GradleException if no valid credential is provided
     */
    private Credential buildCredential() {
        if (hasFingerprint()) {
            return CredentialParser.fromFingerprint(getFingerprint().get());
        }
        if (hasEmail()) {
            return CredentialParser.fromEmail(getEmail().get());
        }
        if (hasSigstoreCredentials()) {
            return CredentialParser.fromSigstore(
                    getSigstoreIssuer().get(), getSigstoreSubject().get());
        }
        throw new GradleException(
                "At least one of fingerprint, email, "
                        + "or sigstoreIssuer+sigstoreSubject is required");
    }

    /**
     * Checks if a fingerprint is present and not blank.
     *
     * @return true if fingerprint is available
     */
    private boolean hasFingerprint() {
        return getFingerprint().isPresent() && !getFingerprint().get().isBlank();
    }

    /**
     * Checks if an email is present and not blank.
     *
     * @return true if email is available
     */
    private boolean hasEmail() {
        return getEmail().isPresent() && !getEmail().get().isBlank();
    }

    /**
     * Checks if both Sigstore issuer and subject are present.
     *
     * @return true if Sigstore credentials are available
     */
    private boolean hasSigstoreCredentials() {
        return getSigstoreIssuer().isPresent() && getSigstoreSubject().isPresent();
    }

    /**
     * Loads the Sigmund configuration.
     * <p>
     * If a config file is specified, loads from that file.
     * Otherwise, loads the default configuration.
     *
     * @return the loaded Sigmund configuration
     */
    private SigmundConfig loadConfig() {
        if (getConfigFile().isPresent()) {
            Path path = getConfigFile().get().getAsFile().toPath();
            return ConfigLoader.load(path);
        }
        return ConfigLoader.load(null);
    }

    /**
     * Creates a Sigmund instance configured for inspection.
     *
     * @param config the Sigmund configuration
     * @return a configured Sigmund instance
     */
    private Sigmund createSigmund(SigmundConfig config) {
        DiscoveryConfig discoveryConfig = config.discoveryConfig();
        return Sigmund.builder()
                .discoveryConfig(discoveryConfig)
                .toolsConfig(SigmundHelper.buildToolsConfig(getSqHome(), getGpgHome()))
                .build();
    }

    /**
     * Performs the signer inspection.
     *
     * @param sigmund the Sigmund instance
     * @param credential the credential to inspect
     * @return the inspection report
     */
    private SignerInspectionReport performInspection(Sigmund sigmund, Credential credential) {
        String toolName = getTool().getOrNull();
        return sigmund.inspectSigner(credential, toolName);
    }

    /**
     * Logs the inspection report.
     *
     * @param report the report to log
     */
    private void logReport(SignerInspectionReport report) {
        SignerInspectionReportFormatter.format(report, msg -> getLogger().lifecycle(msg));
    }
}
