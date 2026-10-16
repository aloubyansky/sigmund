package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Derives an {@link ArtifactOutcome} from the results of the claims found for an artifact.
 *
 * <p>
 * One implementation, used by every insertion point, so that a goal and a resolver-level
 * extension cannot reach different verdicts from the same policy and the same evidence.
 *
 * <p>
 * The rules apply in a fixed order, each deciding only if the earlier ones did not:
 *
 * <ol>
 * <li>any failed claim wins — a valid claim alongside a failing one does not mask it;</li>
 * <li>claims no installed tool supports are set aside: they cannot satisfy a requirement, and
 * cannot block one that the other claims meet;</li>
 * <li>no applicable rule means {@link ArtifactOutcome#NOT_CONFIGURED};</li>
 * <li>requirements met, honouring the claim-set mode, means
 * {@link ArtifactOutcome#SATISFIED};</li>
 * <li>otherwise whichever remaining state is most informative decides: an unresolved claim
 * first; then requirements that set-aside claims would meet, had the keys they name made them,
 * which are {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}; then a rejected claim; then
 * set-aside claims alone; and last no evidence at all.</li>
 * </ol>
 */
final class OutcomeRollup {

    private OutcomeRollup() {
    }

    /**
     * Derives the outcome for one artifact.
     *
     * @param claims every claim found for the artifact, in the order they were parsed
     * @param evaluator the requirement of the rule that matched the artifact, or {@code null}
     *        when no rule did
     * @param mode what to do with claims beyond those that satisfied the requirements
     * @return the outcome and, where one applies, the reason it could not be decided
     */
    public static Result derive(List<ClaimResult> claims, RequirementEvaluator evaluator,
            ClaimSetMode mode) {
        List<ClaimResult> found = claims == null ? List.of() : claims;

        // One pass: a failed claim ends it, an unsupported one is set aside before
        // requirements are evaluated - which is what lets a hybrid signature verify on its
        // classic block when the post-quantum tooling is absent - and the rest are sorted
        // into what verified and why anything else did not.
        List<ClaimResult> setAside = null;
        List<ClaimResult> verified = null;
        IndeterminateReason unresolvedReason = null;
        for (ClaimResult claim : found) {
            switch (claim.outcome()) {
                case FAILED -> {
                    // an attack signal is never masked by evidence that did verify
                    return new Result(ArtifactOutcome.FAILED, null);
                }
                case VERIFIED -> verified = append(verified, claim);
                case INDETERMINATE -> {
                    if (claim.reason() == IndeterminateReason.UNSUPPORTED_ALGORITHM) {
                        setAside = append(setAside, claim);
                    } else if (unresolvedReason == null) {
                        unresolvedReason = claim.reason();
                    }
                }
                // A claim outcome nobody accounted for must not be skipped into a pass:
                // an unhandled state silently dropped here is how a verdict stops meaning
                // what it says.
                default -> throw new IllegalStateException(
                        "unhandled claim outcome: " + claim.outcome());
            }
        }

        // no rule applies to this artifact
        RequirementEvaluator.Evaluation evaluation = evaluator == null ? null
                : evaluator.evaluate(verified == null ? List.of() : verified);
        if (evaluation == null) {
            return new Result(ArtifactOutcome.NOT_CONFIGURED, null);
        }

        // requirements met, subject to what the claim-set mode says about the rest
        if (evaluation.satisfied()) {
            if (mode == ClaimSetMode.ANY_CLAIM) {
                return new Result(ArtifactOutcome.SATISFIED, null);
            }
            if (!evaluation.unaccepted().isEmpty()) {
                return new Result(ArtifactOutcome.UNSATISFIED, null);
            }
            if (unresolvedReason != null) {
                return indeterminate(unresolvedReason);
            }
            return new Result(ArtifactOutcome.SATISFIED, null);
        }

        // requirements unmet: report whichever remaining state tells an operator the most
        if (unresolvedReason != null) {
            return indeterminate(unresolvedReason);
        }
        if (setAside != null && couldBeMetBy(evaluator, verified, setAside)) {
            return indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        if (verified != null) {
            return new Result(ArtifactOutcome.UNSATISFIED, null);
        }
        if (setAside != null) {
            return indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return new Result(ArtifactOutcome.NO_CLAIM, null);
    }

    /**
     * Asks whether the requirements would be met had the claims no installed tool can check been
     * made by the keys they name.
     *
     * <p>
     * When they would, the requirement is unmet only for want of a tool, and the outcome is
     * {@link IndeterminateReason#UNSUPPORTED_ALGORITHM} rather than {@code UNSATISFIED}: an
     * artifact co-signed with a post-quantum key reads as "install a tool that can check this",
     * not as the wrong signer. This cannot turn a wrong signer into an excusable one — a clause
     * that a verified claim fails is not one a named but unchecked key could fill — and a claim
     * whose named key could fill it is exactly what the verifier cannot tell from the real thing.
     */
    private static boolean couldBeMetBy(RequirementEvaluator evaluator,
            List<ClaimResult> verified, List<ClaimResult> setAside) {
        List<ClaimResult> hypothetical = verified == null ? new ArrayList<>() : new ArrayList<>(verified);
        for (ClaimResult claim : setAside) {
            ClaimResult asNamed = claim.asIfVerifiedByDeclaredIssuer();
            if (asNamed != null) {
                hypothetical.add(asNamed);
            }
        }
        RequirementEvaluator.Evaluation evaluation = evaluator.evaluate(hypothetical);
        return evaluation != null && evaluation.satisfied();
    }

    private static Result indeterminate(IndeterminateReason reason) {
        return new Result(ArtifactOutcome.INDETERMINATE, reason);
    }

    private static List<ClaimResult> append(List<ClaimResult> claims, ClaimResult claim) {
        List<ClaimResult> target = claims == null ? new ArrayList<>() : claims;
        target.add(claim);
        return target;
    }

    /**
     * What the roll-up decided.
     *
     * <p>
     * Claims set aside for an unsupported algorithm are not repeated here: they stay in the
     * artifact's claim list, where {@link ClaimResult#isIndeterminateBecause} identifies them.
     *
     * @param outcome the artifact's outcome
     * @param reason why it could not be decided, {@code null} unless indeterminate
     */
    public record Result(ArtifactOutcome outcome, IndeterminateReason reason) {
    }
}
