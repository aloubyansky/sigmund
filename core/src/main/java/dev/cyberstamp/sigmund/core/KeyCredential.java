package dev.cyberstamp.sigmund.core;

import java.util.Locale;
import java.util.Map;

/**
 * Key material, identified by its full fingerprint and proven by the signature itself.
 *
 * <p>
 * Only full fingerprints are accepted — 40 hex characters for an OpenPGP v4 key, 64 for v6 —
 * and they match exactly. A 64-bit key ID is not a fingerprint: colliding key IDs can be
 * generated, so a policy naming one would accept every key that ends in the same bits. Values
 * are normalized to upper case, so comparison ignores the case they were written in.
 *
 * <p>
 * The type is named after the key version ({@code openpgp4}, {@code openpgp6}), not the tool
 * or algorithm, so policy written for a v4 key does not silently accept a v6 one. Types other
 * than the OpenPGP ones are accepted with any hex fingerprint, for backends that bring their
 * own key material.
 *
 * @param type the key type, such as {@link Credential#TYPE_OPENPGP_V4}
 * @param fingerprint the full fingerprint, upper-case hex
 */
public record KeyCredential(String type, String fingerprint) implements Credential {

    private static final Map<String, Integer> OPENPGP_LENGTHS = Map.of(
            TYPE_OPENPGP_V4, 40,
            TYPE_OPENPGP_V6, 64);

    /**
     * Validates and normalizes the fingerprint.
     *
     * @throws IllegalArgumentException if the type is blank, or the fingerprint is not hex or
     *         not a full fingerprint for its type
     */
    public KeyCredential {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("key type must not be blank");
        }
        fingerprint = normalize(fingerprint);
        Integer expected = OPENPGP_LENGTHS.get(type);
        if (expected != null && fingerprint.length() != expected) {
            throw notAFullFingerprint(fingerprint, type + " expects " + expected + " hex characters");
        }
    }

    /**
     * Creates OpenPGP key material, inferring the key version from the fingerprint length.
     *
     * @param fingerprint a full v4 or v6 fingerprint
     * @return the credential
     * @throws IllegalArgumentException if the value is not a full v4 or v6 fingerprint
     */
    public static KeyCredential openPgp(String fingerprint) {
        String normalized = normalize(fingerprint);
        for (Map.Entry<String, Integer> entry : OPENPGP_LENGTHS.entrySet()) {
            if (normalized.length() == entry.getValue()) {
                return new KeyCredential(entry.getKey(), normalized);
            }
        }
        throw notAFullFingerprint(normalized, "expected 40 (v4) or 64 (v6) hex characters");
    }

    /**
     * Indicates whether a value is a full OpenPGP fingerprint, as opposed to a key ID.
     *
     * @param value the value to test, may be {@code null}
     * @return {@code true} for a 40 or 64 character hex string
     */
    public static boolean isOpenPgpFingerprint(String value) {
        return value != null && value.matches("[0-9A-Fa-f]+")
                && OPENPGP_LENGTHS.containsValue(value.length());
    }

    @Override
    public String displayName() {
        return fingerprint;
    }

    /**
     * Matches key material of the same type and the same full fingerprint.
     *
     * @param proven the credential a verified claim proved
     * @return {@code true} on an exact match
     */
    @Override
    public boolean matches(Credential proven) {
        return proven instanceof KeyCredential key
                && type.equals(key.type())
                && fingerprint.equals(key.fingerprint());
    }

    private static String normalize(String fingerprint) {
        if (fingerprint == null || fingerprint.isBlank()) {
            throw new IllegalArgumentException("fingerprint must not be blank");
        }
        String upper = fingerprint.trim().toUpperCase(Locale.ROOT);
        if (!upper.matches("[0-9A-F]+")) {
            throw new IllegalArgumentException("fingerprint must be hex: " + fingerprint);
        }
        return upper;
    }

    private static IllegalArgumentException notAFullFingerprint(String value, String detail) {
        return new IllegalArgumentException("'" + value + "' is not a full fingerprint ("
                + detail + "); key IDs are not accepted because they can collide");
    }
}
