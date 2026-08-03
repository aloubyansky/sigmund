package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * Defines who should produce what and how strictly to verify.
 * <p>
 * The trust policy is the identity-first model's answer to "who do I trust for this artifact?"
 * rather than "does this signature verify?" It maps artifact patterns to expected signer
 * identities and controls how strictly evidence must match.
 * <p>
 * Declared as an interface to allow pluggable policy sources beyond YAML — for example,
 * OPA, a database, or hardcoded configuration. The default implementation is parsed from
 * {@code sigmund.yaml}.
 *
 * <h2>Separation of concerns</h2>
 * <p>
 * {@code TrustPolicy} is purely about trust decisions — who to trust and how strict to be.
 * Operational concerns like key fetching and keyserver configuration live in
 * {@link ToolsConfig}. This means a policy backed by OPA or a database does not need
 * to implement key-fetching logic.
 *
 * @see SignerIdentity
 * @see ToolsConfig
 */
public interface TrustPolicy {

    /**
     * Looks up expected signers for an artifact.
     * <p>
     * Returns an empty list if the artifact has no trust mapping ({@link TrustVerdict#NOT_CONFIGURED}).
     * A trust mapping with zero signers is a configuration error caught at parse time.
     *
     * @param artifact the artifact to look up
     * @return the expected signers, or an empty list if not configured
     */
    List<SignerIdentity> expectedSigners(ArtifactIdentity artifact);

    /**
     * Checks whether this artifact is explicitly marked as unsigned-ok.
     *
     * @param artifact the artifact to check
     * @return {@code true} if the artifact is allowed to be unsigned
     */
    boolean isUnsignedAllowed(ArtifactIdentity artifact);

    /**
     * Returns the policy for evaluating listed evidence.
     *
     * @return the listed evidence policy
     * @see ListedEvidencePolicy
     */
    ListedEvidencePolicy listedEvidence();

    /**
     * Returns the policy for handling unlisted evidence.
     *
     * @return the unlisted evidence policy
     * @see UnlistedEvidencePolicy
     */
    UnlistedEvidencePolicy unlistedEvidence();

    /**
     * Returns the policy for handling untrusted or unconfigured artifacts.
     *
     * @return the untrusted policy
     * @see UntrustedPolicy
     */
    UntrustedPolicy onUntrusted();
}
