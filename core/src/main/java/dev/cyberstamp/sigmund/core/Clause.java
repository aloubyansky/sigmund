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
 */
public record Clause(List<SignerIdentity> signers) {

    /**
     * Creates a clause with defensive copies and validates that it is non-empty.
     *
     * @throws PolicyConfigException if the signer list is empty
     */
    public Clause {
        if (signers == null || signers.isEmpty()) {
            throw new PolicyConfigException("A clause must have at least one signer");
        }
        signers = List.copyOf(signers);
    }

    /**
     * Checks whether any of this clause's signers' credentials match the claim's proven credentials.
     * <p>
     * A claim is accepted when at least one of the clause's signers has at least one credential
     * that matches one of the claim's proven credentials. For identity credentials, the default
     * issuers are consulted when the credential does not name an issuer.
     *
     * @param claim the verified claim to check
     * @param defaultIssuers the issuers trusted for identity credentials that do not name their own
     * @return {@code true} if any signer accepts the claim
     */
    boolean accepts(ClaimResult claim, List<String> defaultIssuers) {
        for (SignerIdentity signer : signers) {
            for (Credential expected : signer.credentials()) {
                for (Credential proven : claim.attesterCredentials()) {
                    if (matches(expected, proven, defaultIssuers)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Checks whether an expected credential matches a proven one.
     * <p>
     * For identity credentials, this delegates to
     * {@link IdentityCredential#matches(Credential, java.util.Collection)} with the default
     * issuers. For all other credentials, it calls {@link Credential#matches(Credential)}.
     *
     * @param expected the credential from policy
     * @param proven the credential a claim proved
     * @param defaultIssuers the issuers trusted for identity credentials that do not name their own
     * @return {@code true} if the proven credential satisfies the expected one
     */
    static boolean matches(Credential expected, Credential proven, List<String> defaultIssuers) {
        return expected instanceof IdentityCredential identity
                ? identity.matches(proven, defaultIssuers)
                : expected.matches(proven);
    }
}
