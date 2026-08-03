package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SignatureVerificationReport;
import java.io.File;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Maven plugin goal that verifies all signatures in an ASC file.
 * <p>
 * By default all signatures must pass. In lenient mode
 * at least one signature must pass and none may fail.
 *
 * @see Sigmund
 * @see SignatureVerificationReport
 */
@Mojo(name = "verify-signature", requiresProject = false, threadSafe = true)
public class VerifySignatureMojo extends AbstractSigmundMojo {

    @Parameter(property = "file", required = true)
    private File file;

    @Parameter(property = "signature", required = true)
    private File signature;

    @Parameter(property = "sigmund.lenient", defaultValue = "false")
    private boolean lenient;

    @Override
    public void execute() throws MojoExecutionException {
        validateInputFiles();

        getLog().info("Verifying signature for: " + file.getName());
        getLog().info("Using signature file: " + signature.getName());

        try (Sigmund sigmund = createSigmund()) {
            SignatureVerificationReport report = performVerification(sigmund);

            logReport(report);
            checkVerdict(report);
        } catch (Exception e) {
            if (e instanceof MojoExecutionException mee) {
                throw mee;
            }
            throw new MojoExecutionException("Signature verification failed", e);
        }
    }

    private void validateInputFiles() throws MojoExecutionException {
        if (!file.exists()) {
            throw new MojoExecutionException("File does not exist: " + file.getAbsolutePath());
        }
        if (!signature.exists()) {
            throw new MojoExecutionException(
                    "Signature file does not exist: " + signature.getAbsolutePath());
        }
    }

    private Sigmund createSigmund() throws MojoExecutionException {
        try {
            return buildSigmund(
                    new DiscoveryConfig(true, false, null, null),
                    mergeToolOverrides(SequoiaHomeResolver.toolsConfigOverrides(sqHome)));
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to create verifier", e);
        }
    }

    private SignatureVerificationReport performVerification(Sigmund sigmund)
            throws MojoExecutionException {
        try {
            return sigmund.verify(file.toPath(), signature.toPath());
        } catch (Exception e) {
            throw new MojoExecutionException("Verification failed", e);
        }
    }

    private void logReport(SignatureVerificationReport report) {
        getLog().info("");
        getLog().info("========================================");
        for (String line : report.format().split("\n")) {
            getLog().info(line);
        }
        getLog().info("========================================");
        getLog().info("");
    }

    private void checkVerdict(SignatureVerificationReport report)
            throws MojoExecutionException {
        boolean pass = lenient ? report.isLenientPass() : report.isPass();
        if (!pass) {
            throw new MojoExecutionException(failureMessage(report));
        }
        getLog().info("Verification successful!");
    }

    private String failureMessage(SignatureVerificationReport report) {
        boolean hasResults = report.files().stream()
                .anyMatch(f -> !f.results().isEmpty());
        return switch (report.verdict()) {
            case NONE_PASSED -> !hasResults
                    ? "No signatures found in signature file"
                    : "No signatures could be verified - check that the required keys are available";
            case PASS_WITH_FAILURES ->
                "Signature verification failed - one or more signatures are invalid";
            case PASS_WITH_SKIPS ->
                "Not all signatures could be verified - use sigmund.lenient=true to tolerate skipped signatures";
            case ALL_PASS ->
                throw new IllegalStateException("failureMessage called with ALL_PASS outcome");
        };
    }
}
