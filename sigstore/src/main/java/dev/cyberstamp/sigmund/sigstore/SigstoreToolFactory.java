package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.OidcCredential;
import dev.cyberstamp.sigmund.core.SignatureTool;
import dev.cyberstamp.sigmund.core.SignatureToolFactory;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import dev.sigstore.KeylessSigner;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.oidc.client.GithubActionsOidcClient;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcTokenMatcher;
import dev.sigstore.strings.StringMatcher;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Factory for creating {@link SigstoreTool} instances.
 * <p>
 * Discovered via {@link java.util.ServiceLoader} when {@code sigmund-sigstore}
 * is on the classpath. Supports three settings:
 * <ul>
 * <li>{@code staging} (boolean, default false) — use {@code sigstage.dev}
 * instead of production {@code sigstore.dev}</li>
 * <li>{@code trusted-root} (path) — custom trusted root JSON file for
 * air-gapped environments</li>
 * <li>{@code interactive} (boolean, default false) — enable browser-based
 * OIDC flow for desktop signing</li>
 * </ul>
 *
 * @see SigstoreTool
 * @see SignatureToolFactory
 */
public class SigstoreToolFactory implements SignatureToolFactory {

    private static final String TOOL_NAME = "sigstore";

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_OIDC);
    }

    /**
     * Creates a signing-capable {@link SigstoreTool}.
     * <p>
     * When {@code credential} is an {@link OidcCredential}, configures
     * {@code allowedOidcIdentities} to validate the OIDC token at signing time.
     * When {@code credential} is {@code null}, accepts any ambient OIDC identity.
     * <p>
     * When {@code interactive} is {@code true}, the browser-based OIDC flow
     * is enabled as a fallback after ambient providers.
     *
     * @param credential the matched OIDC credential, or {@code null} for ambient identity
     * @param settings tool settings from the {@code tools.sigstore} config section
     * @return a signing-capable Sigstore tool
     * @throws ToolExecutionException if the signer cannot be constructed
     */
    @Override
    public SignatureTool createSigning(Credential credential, Map<String, String> settings) {
        boolean staging = "true".equals(settings.get("staging"));
        boolean interactive = "true".equals(settings.get("interactive"));
        try {
            KeylessSigner.Builder signerBuilder = staging
                    ? KeylessSigner.builder().sigstoreStagingDefaults()
                    : KeylessSigner.builder().sigstorePublicDefaults();

            if (!interactive) {
                signerBuilder.oidcClients(
                        OidcClients.of(GithubActionsOidcClient.builder().build()));
            }

            String oidcSubject = null;
            if (credential instanceof OidcCredential oidc) {
                signerBuilder.allowedOidcIdentities(List.of(
                        OidcTokenMatcher.of(
                                StringMatcher.string(oidc.subject()),
                                StringMatcher.string(oidc.issuer()))));
                oidcSubject = oidc.subject();
            }

            KeylessSigner signer = signerBuilder.build();
            KeylessVerifier verifier = buildVerifier(settings, staging);
            return new SigstoreTool(format, signer, verifier, oidcSubject);
        } catch (IOException | GeneralSecurityException e) {
            throw new ToolExecutionException(
                    "Failed to create Sigstore signing tool: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a verify-only {@link SigstoreTool}.
     *
     * @param settings tool settings from the {@code tools.sigstore} config section
     * @return a verify-only Sigstore tool
     * @throws ToolExecutionException if the verifier cannot be constructed
     */
    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        boolean staging = "true".equals(settings.get("staging"));
        try {
            KeylessVerifier verifier = buildVerifier(settings, staging);
            return new SigstoreTool(format, null, verifier, null);
        } catch (IOException | GeneralSecurityException e) {
            throw new ToolExecutionException(
                    "Failed to create Sigstore verification tool: " + e.getMessage(), e);
        }
    }

    private KeylessVerifier buildVerifier(Map<String, String> settings, boolean staging)
            throws IOException, GeneralSecurityException {
        String trustedRoot = settings.get("trusted-root");
        if (trustedRoot != null && !trustedRoot.isBlank()) {
            return KeylessVerifier.builder()
                    .trustedRootProvider(TrustedRootProvider.from(Path.of(trustedRoot)))
                    .build();
        }
        return staging
                ? KeylessVerifier.builder().sigstoreStagingDefaults().build()
                : KeylessVerifier.builder().sigstorePublicDefaults().build();
    }
}
