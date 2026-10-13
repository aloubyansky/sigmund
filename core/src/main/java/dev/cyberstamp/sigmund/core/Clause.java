package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * A single disjunctive clause in a policy requirement: a set of acceptable signers.
 * <p>
 * A clause is satisfied when at least one of its signers attested to the artifact. Multiple
 * clauses are combined into a {@link Requirement}, which forms conjunctive normal form (CNF):
 * every clause must be satisfied.
 * <p>
 * Example: {@code Clause(alice, bob)} means "signed by alice OR bob". When combined with
 * another clause {@code Clause(carol)}, the requirement becomes "signed by (alice OR bob) AND carol".
 * <p>
 * A clause must have at least one signer. An empty clause would mean "no one is acceptable",
 * which is a configuration error rather than a valid policy statement.
 *
 * @param signers the acceptable signers for this clause
 * @throws PolicyConfigException if the signer list is empty
 */
public record Clause(List<SignerIdentity> signers) {

    /**
     * Creates a clause with defensive copies and validates that it is non-empty.
     *
     * @param signers the acceptable signers
     * @throws PolicyConfigException if the signer list is empty
     */
    public Clause {
        if (signers == null || signers.isEmpty()) {
            throw new PolicyConfigException("A clause must have at least one signer");
        }
        signers = List.copyOf(signers);
    }
}
