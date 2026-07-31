package dev.cyberstamp.sigmund.core;

/**
 * Factory methods for creating {@link Credential} instances from raw user input.
 *
 * <p>
 * Handles validation and normalization of identifiers. Fingerprints are
 * uppercased and checked for valid hex characters; the OpenPGP key version
 * is inferred from the fingerprint length (40 hex chars → v4, 64 → v6).
 *
 * <p>
 * The {@link #parse(String)} method performs auto-detection: identifiers
 * containing {@code @} are treated as emails, otherwise they are validated
 * as hex fingerprints with a length check (16, 40, or 64 characters).
 *
 * @see Credential
 * @see FingerprintCredential
 * @see EmailCredential
 * @see OidcCredential
 */
public final class CredentialParser {

    private CredentialParser() {
    }

    /**
     * Creates a {@link FingerprintCredential} from a hex fingerprint string.
     *
     * <p>
     * The fingerprint is uppercased and validated as hexadecimal. The credential
     * type is inferred from length: strings longer than 40 characters are treated
     * as OpenPGP v6 fingerprints, otherwise v4.
     *
     * @param fingerprint hex fingerprint string
     * @return a fingerprint credential with the inferred key version
     * @throws IllegalArgumentException if the fingerprint is null, blank, or not valid hex
     */
    public static FingerprintCredential fromFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isBlank()) {
            throw new IllegalArgumentException("Fingerprint must not be empty");
        }
        String upper = fingerprint.toUpperCase();
        if (!upper.matches("[0-9A-F]+")) {
            throw new IllegalArgumentException(
                    "Fingerprint must be a hex string: " + fingerprint);
        }
        String type = upper.length() > 40
                ? Credential.TYPE_OPENPGP_V6
                : Credential.TYPE_OPENPGP_V4;
        return new FingerprintCredential(type, upper);
    }

    /**
     * Creates an {@link EmailCredential} from an email address.
     *
     * @param email the email address
     * @return an email credential
     * @throws IllegalArgumentException if the email is null or blank
     */
    public static EmailCredential fromEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email must not be empty");
        }
        return new EmailCredential(email);
    }

    /**
     * Creates an {@link OidcCredential} from an issuer URL and subject.
     *
     * @param issuer OIDC issuer URL (e.g. {@code "https://token.actions.githubusercontent.com"})
     * @param subject OIDC subject (e.g. a GitHub Actions workflow reference)
     * @return an OIDC credential
     * @throws IllegalArgumentException if either parameter is null or blank
     */
    public static OidcCredential fromOidc(String issuer, String subject) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("OIDC issuer must not be empty");
        }
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("OIDC subject must not be empty");
        }
        return new OidcCredential(issuer, subject);
    }

    /**
     * Auto-detects the credential type from a raw identifier string.
     *
     * <p>
     * Detection rules:
     * <ul>
     * <li>Contains {@code @} → {@link EmailCredential}</li>
     * <li>16 hex chars → {@link FingerprintCredential} (short key ID, assumed v4)</li>
     * <li>40 hex chars → {@link FingerprintCredential} (v4 fingerprint)</li>
     * <li>64 hex chars → {@link FingerprintCredential} (v6 fingerprint)</li>
     * </ul>
     *
     * @param identifier the raw identifier to parse
     * @return the parsed credential
     * @throws IllegalArgumentException if the identifier is null, blank, not valid hex,
     *         or has an unrecognized hex length
     */
    public static Credential parse(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException(
                    "Identifier must not be empty");
        }
        if (identifier.contains("@")) {
            return new EmailCredential(identifier);
        }
        String upper = identifier.toUpperCase();
        if (!upper.matches("[0-9A-F]+")) {
            throw new IllegalArgumentException(
                    "Identifier '" + identifier + "' is not a valid hex fingerprint or email.");
        }
        if (upper.length() != 16 && upper.length() != 40 && upper.length() != 64) {
            throw new IllegalArgumentException(
                    "Fingerprint must be 16, 40, or 64 hex characters (got "
                            + upper.length() + ").");
        }
        String type = upper.length() > 40
                ? Credential.TYPE_OPENPGP_V6
                : Credential.TYPE_OPENPGP_V4;
        return new FingerprintCredential(type, upper);
    }
}
