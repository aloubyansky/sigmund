package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * Decides which rule applies to an artifact, what its verified claims must satisfy, and how
 * strictly each outcome is enforced.
 * <p>
 * The trust policy is the identity-first model's answer to "who do I trust for this artifact?"
 * rather than "does this signature verify?" It selects the most specific {@link Rule} for an
 * artifact, whose {@link Requirement} the shared roll-up evaluates, and maps each
 * {@link ArtifactOutcome} to an {@link EnforcementAction}.
 * <p>
 * Declared as an interface to allow pluggable policy sources beyond YAML — for example, OPA, a
 * database, or hardcoded configuration. The default implementation, {@link RulePolicy}, is
 * compiled from a {@link TrustPolicySpec} on the verification path.
 *
 * <h2>Separation of concerns</h2>
 * <p>
 * {@code TrustPolicy} is purely about trust decisions — which rule applies and how strict to be.
 * Operational concerns like key fetching and keyserver configuration live in {@link ToolsConfig}.
 * This means a policy backed by OPA or a database does not need to implement key-fetching logic.
 *
 * @see Rule
 * @see RulePolicy
 * @see SignerIdentity
 */
public interface TrustPolicy {

    /**
     * Returns the most specific rule that applies to an artifact, or {@code null} when none does.
     * <p>
     * When several rules match, the one with the highest specificity wins. Ties on specificity are
     * a configuration error caught when the policy is compiled, so matching never has to break a
     * tie. A {@code null} result means no rule covers the artifact
     * ({@link ArtifactOutcome#NOT_CONFIGURED}).
     *
     * @param coords the artifact to match
     * @return the matched rule, or {@code null} if no rule applies
     */
    Rule matchRule(ArtifactCoords coords);

    /**
     * Returns what to do with verified claims beyond those the applicable rule's requirements
     * accepted.
     *
     * @return the claim-set mode
     */
    ClaimSetMode claimSetMode();

    /**
     * Returns the issuers trusted for identity entries that do not name their own.
     * <p>
     * This is the default grant for identities; an entry that names an issuer is trusted from that
     * issuer only, whether or not it is listed here.
     *
     * @return canonical issuer names, empty when no default issuer is trusted
     */
    List<String> issuers();

    /**
     * Returns whether this policy was declared, as opposed to standing in for its absence.
     * <p>
     * A configuration declares a policy only when it has a {@code rules} or {@code defaults}
     * section; one that only sets up signing, tools or signers declares none. Without a declared
     * policy verification observes: every artifact is verified and reported, and only
     * {@link ArtifactOutcome#FAILED} blocks. Being declared is what makes coverage enforced — see
     * {@link #enforcementFor(ArtifactOutcome, MatchedRule)}. It is carried by the policy itself
     * so that no caller can pair a policy with a contradicting flag.
     *
     * @return {@code true} if the configuration declares this policy
     */
    boolean declared();

    /**
     * Resolves the enforcement action for an outcome, given the rule that matched the artifact.
     * <p>
     * The resolution order is: the matched rule's per-outcome override, then the policy's defaults,
     * then the code default. Two outcomes are special:
     * <ul>
     * <li>{@link ArtifactOutcome#FAILED} is always {@link EnforcementAction#FAIL}; any override is
     * ignored, because a cryptographically failing signature is an attack signal rather than a
     * coverage question.</li>
     * <li>{@link ArtifactOutcome#NOT_CONFIGURED} is {@link EnforcementAction#FAIL} when the policy is
     * {@linkplain #declared() declared} and {@link EnforcementAction#IGNORE} otherwise, the single
     * observe/enforce switch applied to coverage.</li>
     * </ul>
     *
     * @param outcome the artifact's outcome
     * @param matchedRule the rule that matched the artifact, or {@code null} when none did
     * @return the enforcement action to apply
     */
    EnforcementAction enforcementFor(ArtifactOutcome outcome, MatchedRule matchedRule);
}
