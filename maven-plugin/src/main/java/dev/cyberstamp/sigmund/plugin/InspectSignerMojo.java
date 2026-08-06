package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.CredentialParser;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignerInspectionReport;
import dev.cyberstamp.sigmund.core.SignerInspectionReportFormatter;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Maven goal that inspects a signer identity across all available sources.
 *
 * <p>
 * Does not require dependency resolution — only needs tool configuration and
 * a signer credential. The credential is specified via Maven properties:
 * {@code sigmund.fingerprint}, {@code sigmund.email}, or
 * {@code sigmund.oidcIssuer} + {@code sigmund.oidcSubject}.
 *
 * <p>
 * Output is printed to the Maven logger, grouped into local and remote
 * sources with per-source key metadata.
 *
 * <p>
 * Usage: {@code mvn sigmund:inspect-signer -Dsigmund.fingerprint=...}
 *
 * @see SignerInspectionReportFormatter
 */
@Mojo(name = "inspect-signer", requiresProject = false, threadSafe = true)
public class InspectSignerMojo extends AbstractSigmundMojo {

    @Parameter(property = "sigmund.fingerprint")
    String fingerprint;

    @Parameter(property = "sigmund.email")
    String email;

    @Parameter(property = "sigmund.oidcIssuer")
    String oidcIssuer;

    @Parameter(property = "sigmund.oidcSubject")
    String oidcSubject;

    @Parameter(property = "sigmund.tool")
    String tool;

    @Parameter(property = "sigmund.keyservers")
    String keyservers;

    @Parameter(property = "sigmund.resolveSigners")
    Boolean resolveSigners;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping inspect-signer");
            return;
        }
        try {
            Credential credential = buildCredential();
            try (Sigmund sigmund = createSigmund()) {
                SignerInspectionReport report = sigmund.inspectSigner(credential, tool);
                SignerInspectionReportFormatter.format(report, msg -> getLog().info(msg));
            }
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        } catch (Exception e) {
            throw new MojoExecutionException(
                    "Signer inspection failed: " + e.getMessage(), e);
        }
    }

    /**
     * Builds a {@link Credential} from the Maven properties.
     *
     * <p>
     * Priority: fingerprint → email → OIDC (issuer + subject).
     *
     * @return the parsed credential
     * @throws IllegalArgumentException if no credential properties are set
     */
    Credential buildCredential() {
        if (fingerprint != null && !fingerprint.isBlank()) {
            return CredentialParser.fromFingerprint(fingerprint);
        }
        if (email != null && !email.isBlank()) {
            return CredentialParser.fromEmail(email);
        }
        if (oidcIssuer != null && !oidcIssuer.isBlank()
                && oidcSubject != null && !oidcSubject.isBlank()) {
            return CredentialParser.fromOidc(oidcIssuer, oidcSubject);
        }
        throw new IllegalArgumentException(
                "At least one of sigmund.fingerprint, sigmund.email, "
                        + "or sigmund.oidcIssuer+sigmund.oidcSubject is required");
    }

    private Sigmund createSigmund() throws MojoExecutionException {
        SigmundConfig config = loadConfig();
        DiscoveryConfig discoveryConfig = resolveDiscoveryConfig(
                config.discoveryConfig(), resolveSigners, keyservers, null);
        return buildSigmund(discoveryConfig, mergeToolOverrides(config.toolsConfig()));
    }
}
