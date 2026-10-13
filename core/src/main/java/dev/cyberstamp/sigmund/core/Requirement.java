package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * A policy requirement expressed in conjunctive normal form (CNF): a conjunction of disjunctive clauses.
 * <p>
 * Each {@link Clause} is a disjunction (OR) of acceptable signers. A requirement holds multiple
 * clauses in a list, forming a conjunction (AND). For the requirement to be satisfied, every
 * clause must be satisfied by at least one claim.
 * <p>
 * Example: if the requirement has two clauses {@code [Clause(alice, bob), Clause(carol)]},
 * then the artifact must be signed by (alice OR bob) AND carol.
 * <p>
 * The CNF form allows expressive policies while keeping evaluation straightforward: each clause
 * independently checks whether any of its signers appears in the verified claims, and all clauses
 * must succeed.
 *
 * @param clauses the clauses that must all be satisfied
 * @param defaultIssuers the issuers trusted for identity credentials that do not name their own
 */
public record Requirement(List<Clause> clauses, List<String> defaultIssuers) {

    /**
     * Creates a requirement with defensive copies.
     *
     * @param clauses the clauses in CNF form
     * @param defaultIssuers the trusted default issuers
     */
    public Requirement {
        clauses = clauses == null ? List.of() : List.copyOf(clauses);
        defaultIssuers = defaultIssuers == null ? List.of() : List.copyOf(defaultIssuers);
    }

    /**
     * Evaluates the verified claims against this requirement.
     * <p>
     * The requirement is satisfied when it has at least one clause and every clause is satisfied by
     * at least one claim (conjunction). A requirement with no clauses — a catch-all rule that states
     * no signer — is never satisfied, so an unsigned artifact rolls up to
     * {@link ArtifactOutcome#NO_CLAIM} and the rule's enforcement decides, rather than reading as
     * full coverage. A claim is accepted when any clause accepts it, and unaccepted when none do.
     *
     * @param verifiedClaims the claims that verified for the artifact
     * @return the evaluation result indicating whether the requirement was satisfied
     */
    public RequirementEvaluator.Evaluation evaluate(List<ClaimResult> verifiedClaims) {
        if (verifiedClaims == null) {
            verifiedClaims = List.of();
        }

        boolean satisfied = !clauses.isEmpty();
        for (Clause clause : clauses) {
            boolean clauseSatisfied = false;
            for (ClaimResult claim : verifiedClaims) {
                if (clause.accepts(claim, defaultIssuers)) {
                    clauseSatisfied = true;
                    break;
                }
            }
            if (!clauseSatisfied) {
                satisfied = false;
                break;
            }
        }

        List<ClaimResult> accepted = verifiedClaims.stream()
                .filter(claim -> clauses.stream().anyMatch(clause -> clause.accepts(claim, defaultIssuers)))
                .toList();
        List<ClaimResult> unaccepted = verifiedClaims.stream()
                .filter(claim -> clauses.stream().noneMatch(clause -> clause.accepts(claim, defaultIssuers)))
                .toList();

        return new RequirementEvaluator.Evaluation(satisfied, accepted, unaccepted);
    }
}
