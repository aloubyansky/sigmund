package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Default {@link TrustPolicy} implementation backed by parsed configuration.
 * <p>
 * Pattern matching uses a colon-separated format with 1–3 parts:
 * {@code namespace}, {@code namespace:name}, or {@code namespace:name:version}.
 * Wildcards ({@code *}) match any value. When multiple patterns match,
 * the most specific one wins (exact matches score higher than wildcards,
 * and more segments score higher than fewer).
 */
public class DefaultTrustPolicy implements TrustPolicy {

    static final DefaultTrustPolicy EMPTY = new DefaultTrustPolicy(
            Map.of(), List.of(), ListedEvidencePolicy.ALL, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);

    private final Map<String, List<SignerIdentity>> trustMappings;
    private final List<String> unsignedPatterns;
    private final ListedEvidencePolicy listedEvidence;
    private final UnlistedEvidencePolicy unlistedEvidence;
    private final UntrustedPolicy untrustedPolicy;

    /**
     * Creates a new default trust policy.
     *
     * @param trustMappings artifact patterns mapped to expected signers
     * @param unsignedPatterns patterns for artifacts allowed to be unsigned
     * @param listedEvidence policy for evaluating listed evidence
     * @param unlistedEvidence policy for handling unlisted evidence
     * @param untrustedPolicy how to handle untrusted artifacts
     */
    public DefaultTrustPolicy(
            Map<String, List<SignerIdentity>> trustMappings,
            List<String> unsignedPatterns,
            ListedEvidencePolicy listedEvidence,
            UnlistedEvidencePolicy unlistedEvidence,
            UntrustedPolicy untrustedPolicy) {
        this.trustMappings = Map.copyOf(trustMappings);
        this.unsignedPatterns = List.copyOf(unsignedPatterns);
        this.listedEvidence = listedEvidence;
        this.unlistedEvidence = unlistedEvidence;
        this.untrustedPolicy = untrustedPolicy;
    }

    @Override
    public List<SignerIdentity> expectedSigners(ArtifactIdentity artifact) {
        String bestPattern = ArtifactPatternMatcher.findBestMatch(artifact, trustMappings.keySet());
        if (bestPattern == null) {
            return List.of();
        }
        return trustMappings.get(bestPattern);
    }

    @Override
    public boolean isUnsignedAllowed(ArtifactIdentity artifact) {
        return ArtifactPatternMatcher.findBestMatch(artifact, unsignedPatterns) != null;
    }

    @Override
    public ListedEvidencePolicy listedEvidence() {
        return listedEvidence;
    }

    @Override
    public UnlistedEvidencePolicy unlistedEvidence() {
        return unlistedEvidence;
    }

    @Override
    public UntrustedPolicy onUntrusted() {
        return untrustedPolicy;
    }

}
