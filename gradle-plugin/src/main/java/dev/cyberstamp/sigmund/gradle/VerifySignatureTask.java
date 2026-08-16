package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SignatureVerificationReport;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.nio.file.Path;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.TaskAction;

/**
 * Gradle task for verifying detached PGP signatures (ASC files) against artifacts.
 * <p>
 * This task verifies that a detached signature file matches the artifact it signs.
 * It supports both strict and lenient verification modes:
 * <ul>
 *   <li>Strict mode (default): requires all signatures to be valid</li>
 *   <li>Lenient mode: accepts partial verification (at least one valid signature)</li>
 * </ul>
 * <p>
 * Example usage:
 * <pre>
 * sigmundVerifySignature {
 *     file = file('my-artifact.jar')
 *     signature = file('my-artifact.jar.asc')
 *     lenient = false
 * }
 * </pre>
 */
public abstract class VerifySignatureTask extends DefaultTask {

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
     * Gets the artifact file to verify.
     *
     * @return the artifact file property
     */
    @InputFile
    public abstract RegularFileProperty getFile();

    /**
     * Gets the detached signature file (ASC).
     *
     * @return the signature file property
     */
    @InputFile
    public abstract RegularFileProperty getSignature();

    /**
     * Gets the lenient verification mode flag.
     * <p>
     * When true, verification passes if at least one signature is valid (lenient mode).
     * When false (default), all signatures must be valid (strict mode).
     *
     * @return the lenient mode property, defaults to false
     */
    @Input
    public abstract Property<Boolean> getLenient();

    /**
     * Constructs a new VerifySignatureTask and sets default property values.
     */
    public VerifySignatureTask() {
        getLenient().convention(false);
    }

    /**
     * Verifies the signature of the artifact.
     * <p>
     * This method:
     * <ol>
     *   <li>Reads the artifact and signature files</li>
     *   <li>Configures Sigmund with discovery and tool settings</li>
     *   <li>Performs signature verification</li>
     *   <li>Logs the verification report</li>
     *   <li>Throws an exception if verification fails</li>
     * </ol>
     *
     * @throws GradleException if signature verification fails
     */
    @TaskAction
    public void verify() {
        Path artifactFile = getFile().get().getAsFile().toPath();
        Path signatureFile = getSignature().get().getAsFile().toPath();

        logVerificationStart(artifactFile, signatureFile);

        try (Sigmund sigmund = createSigmund()) {
            SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);
            logReport(report);
            checkVerificationResult(report);
            logSuccess();
        }
    }

    /**
     * Logs the start of the verification process.
     *
     * @param artifactFile the artifact file being verified
     * @param signatureFile the signature file being used
     */
    private void logVerificationStart(Path artifactFile, Path signatureFile) {
        getLogger().lifecycle("Verifying signature for: {}", artifactFile.getFileName());
        getLogger().lifecycle("Using signature file: {}", signatureFile.getFileName());
    }

    /**
     * Creates and configures a Sigmund instance for verification.
     * <p>
     * Enables public key discovery and configures tool home directories
     * from the task properties.
     *
     * @return a configured Sigmund instance
     */
    private Sigmund createSigmund() {
        ToolsConfig toolsConfig = SigmundHelper.buildToolsConfig(getSqHome(), getGpgHome());
        return Sigmund.builder()
                .discoveryConfig(new DiscoveryConfig(true, false, null, null))
                .toolsConfig(toolsConfig)
                .build();
    }

    /**
     * Logs the verification report.
     *
     * @param report the verification report to log
     */
    private void logReport(SignatureVerificationReport report) {
        for (String line : report.format().split("\n")) {
            getLogger().lifecycle(line);
        }
    }

    /**
     * Checks the verification result and throws an exception if it failed.
     * <p>
     * Uses lenient or strict verification based on the lenient property.
     *
     * @param report the verification report
     * @throws GradleException if verification failed
     */
    private void checkVerificationResult(SignatureVerificationReport report) {
        boolean pass = getLenient().get() ? report.isLenientPass() : report.isPass();
        if (!pass) {
            throw new GradleException("Signature verification failed: " + report.verdict());
        }
    }

    /**
     * Logs a success message.
     */
    private void logSuccess() {
        getLogger().lifecycle("Verification successful!");
    }
}
