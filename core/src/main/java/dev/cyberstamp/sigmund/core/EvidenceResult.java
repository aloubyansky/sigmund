package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * The output of verifying a piece of evidence.
 * <p>
 * Carries the full {@link VerifyResult} (with format-specific details like
 * signer display name, algorithm, and key metadata) alongside the proven
 * {@link Credential}s for identity matching.
 * <p>
 * The trust layer only needs {@link #outcome()} and {@link #provenCredentials()}
 * for policy decisions. Consumers that need richer display info (signer names,
 * key fingerprints, algorithms) access {@link #verifyResult()} directly.
 *
 * @param verifyResult the full verification result
 * @param provenCredentials the credentials proven by this evidence
 * @param provider the evidence provider name (e.g., {@code "openpgp"}, {@code "sigstore"})
 * @see EvidenceProvider
 * @see TrustResult
 */
public record EvidenceResult(VerifyResult verifyResult, List<Credential> provenCredentials, String provider) {

    /** Validates arguments and defensively copies the credential list. */
    public EvidenceResult {
        if (verifyResult == null) {
            throw new IllegalArgumentException("verifyResult must not be null");
        }
        provenCredentials = provenCredentials != null ? List.copyOf(provenCredentials) : List.of();
    }

    /**
     * Returns the verification outcome.
     *
     * @return the claim outcome
     */
    public ClaimOutcome outcome() {
        return verifyResult.outcome();
    }

    /**
     * Returns why verification could not complete.
     *
     * @return the reason, or {@code null} when the outcome is conclusive
     */
    public IndeterminateReason reason() {
        return verifyResult.reason();
    }

    /**
     * Indicates whether the claim verified.
     *
     * @return {@code true} when the claim's outcome is {@link ClaimOutcome#VERIFIED}
     */
    public boolean isVerified() {
        return verifyResult.isVerified();
    }

    /**
     * Indicates whether cryptographic verification failed.
     *
     * @return {@code true} when the claim's outcome is {@link ClaimOutcome#FAILED}
     */
    public boolean isFailed() {
        return verifyResult.isFailed();
    }

    /**
     * Indicates whether verification could not complete for a particular reason.
     *
     * @param expected the reason to test for
     * @return {@code true} when the claim is indeterminate for that reason
     */
    public boolean isIndeterminate(IndeterminateReason expected) {
        return verifyResult.isIndeterminate(expected);
    }
}
