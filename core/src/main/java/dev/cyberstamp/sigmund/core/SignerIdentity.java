package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * A signer named in policy, and the credentials that identify it.
 * <p>
 * A signer identity represents a person, team, or service account that signs artifacts.
 * It carries multiple {@link Credential}s — for example, the fingerprints of keys already seen
 * and an email address that lets keys generated later be accepted. During verification,
 * identity matching checks for overlap between the signer's credential bag and the
 * proven credentials from evidence verification.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * var alice = new SignerIdentity("alice", List.of(
 *         KeyCredential.openPgp("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"),
 *         IdentityCredential.email(null, "alice@example.com")));
 * }</pre>
 *
 * @param id the name trust configuration refers to the signer by, and reports show it as
 *        (e.g., {@code "alice"})
 * @param credentials the extensible credential bag
 * @see Credential
 * @see TrustPolicy
 */
public record SignerIdentity(
        String id,
        List<Credential> credentials) {

    /**
     * Creates a new signer identity.
     *
     * @throws IllegalArgumentException if id is {@code null} or blank, or credentials is {@code null}
     */
    public SignerIdentity {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be null or blank");
        }
        if (credentials == null) {
            throw new IllegalArgumentException("credentials must not be null");
        }
        credentials = List.copyOf(credentials);
    }
}
