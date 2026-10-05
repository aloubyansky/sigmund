package dev.cyberstamp.sigmund.core;

/**
 * Factory methods for creating {@link Credential} instances from raw user input, such as a
 * command-line argument naming a signer to inspect.
 *
 * <p>
 * Fingerprints must be full — 40 hex characters for an OpenPGP v4 key, 64 for v6 — and the
 * key version is inferred from the length. Key IDs are rejected: they can collide, so they
 * cannot identify key material.
 *
 * @see Credential
 * @see KeyCredential
 * @see IdentityCredential
 */
public final class CredentialParser {

    private CredentialParser() {
    }

    /**
     * Creates OpenPGP key material from a full fingerprint.
     *
     * @param fingerprint the full v4 or v6 fingerprint
     * @return the key credential
     * @throws IllegalArgumentException if the value is not a full fingerprint
     */
    public static KeyCredential fromFingerprint(String fingerprint) {
        return KeyCredential.openPgp(fingerprint);
    }

    /**
     * Creates an email identity with no issuer, suitable as a lookup query.
     *
     * @param email the email address
     * @return the identity
     * @throws IllegalArgumentException if the email is null or blank
     */
    public static IdentityCredential fromEmail(String email) {
        return IdentityCredential.email(null, email);
    }

    /**
     * Auto-detects the credential kind from a raw identifier: anything containing {@code @}
     * is an email address, anything else must be a full fingerprint.
     *
     * @param identifier the raw identifier to parse
     * @return the parsed credential
     * @throws IllegalArgumentException if the identifier is blank, or neither an address nor
     *         a full fingerprint
     */
    public static Credential parse(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException("Identifier must not be empty");
        }
        if (identifier.contains("@")) {
            return fromEmail(identifier);
        }
        return fromFingerprint(identifier);
    }
}
