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
 */
public record Requirement(List<Clause> clauses) {

    /**
     * Creates a requirement with defensive copies.
     *
     * @param clauses the clauses in CNF form
     */
    public Requirement {
        clauses = clauses == null ? List.of() : List.copyOf(clauses);
    }

    /**
     * Evaluates the verified claims against this requirement.
     * <p>
     * This is a temporary stub for Task 3. The actual CNF evaluation logic will be implemented
     * in Task 4.
     *
     * @param verifiedClaims the claims that verified for the artifact
     * @return the evaluation result indicating whether the requirement was satisfied
     * @throws UnsupportedOperationException always, until Task 4 implements the logic
     */
    public RequirementEvaluator.Evaluation evaluate(List<ClaimResult> verifiedClaims) {
        throw new UnsupportedOperationException("Task 4: CNF evaluation not yet implemented");
    }
}
