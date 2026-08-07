package dev.cyberstamp.sigmund.core;

/**
 * Verification result for a Sigstore signature bundle.
 * <p>
 * Carries Sigstore-specific fields: the OIDC issuer URL, the Rekor
 * transparency log index, and the SAN subject type from the Fulcio
 * certificate. The {@code subjectType} uses RFC 5280 {@code GeneralName}
 * tag values (1 = rfc822Name for email, 6 = uniformResourceIdentifier
 * for CI workflow URIs).
 *
 * @see VerifyResult
 */
public final class SigstoreVerifyResult extends VerifyResult {

    private final String issuer;
    private final String logIndex;
    private final int subjectType;

    /**
     * Creates a new Sigstore verification result.
     *
     * @param verdict the verification outcome
     * @param signerDisplayName human-readable signer (typically the OIDC subject), or {@code null}
     * @param algorithm the algorithm name, or {@code null}
     * @param issuer the OIDC issuer URL, or {@code null}
     * @param logIndex the Rekor transparency log entry index, or {@code null}
     * @param subjectType the SAN type from the Fulcio certificate ({@code GeneralName} tag value),
     *        or {@code -1} if unknown
     */
    public SigstoreVerifyResult(Verdict verdict, String signerDisplayName,
            String algorithm, String issuer, String logIndex, int subjectType) {
        super(verdict, signerDisplayName, algorithm);
        this.issuer = issuer;
        this.logIndex = logIndex;
        this.subjectType = subjectType;
    }

    /**
     * Returns the OIDC issuer URL.
     *
     * @return the issuer URL, or {@code null}
     */
    public String issuer() {
        return issuer;
    }

    /**
     * Returns the Rekor transparency log entry index.
     *
     * @return the log index, or {@code null}
     */
    public String logIndex() {
        return logIndex;
    }

    /**
     * Returns the SAN subject type from the Fulcio certificate.
     * <p>
     * Uses RFC 5280 {@code GeneralName} tag values:
     * 1 = rfc822Name (email), 6 = uniformResourceIdentifier (CI workflow URI).
     * Returns {@code -1} if the type could not be determined.
     *
     * @return the GeneralName tag value
     */
    public int subjectType() {
        return subjectType;
    }

    /**
     * Returns the OIDC subject as the signer identifier.
     * <p>
     * For Sigstore, the most meaningful identifier is the OIDC subject
     * (email or workflow URI), paralleling how OpenPGP returns the key
     * fingerprint.
     *
     * @return the OIDC subject, or {@code null}
     */
    @Override
    public String signerIdentifier() {
        return signerDisplayName();
    }
}
