package dev.cyberstamp.sigmund.core;

import java.util.Set;

/**
 * Describes a signing identity that a {@link SignatureTool} will use.
 *
 * @param toolName the tool name (e.g., {@code "bc"}, {@code "gpg"}, {@code "sq"})
 * @param fingerprint full hex fingerprint, or {@code null} if unknown
 * @param algorithm algorithm name (e.g., {@code "RSA"}, {@code "Ed25519"})
 * @param userId user ID string (e.g., {@code "Alice <alice@example.com>"}), or {@code null}
 * @param credentialTypes credential types this key can produce
 */
public record SigningInfo(
        String toolName,
        String fingerprint,
        String algorithm,
        String userId,
        Set<String> credentialTypes) {

    /**
     * Returns a human-readable summary of this signing identity.
     *
     * @return formatted string, e.g. {@code "gpg: RSA ABCDEF... (alice@example.com)"}
     */
    public String display() {
        var sb = new StringBuilder(toolName);
        if (algorithm != null) {
            sb.append(": ").append(algorithm);
        }
        if (fingerprint != null) {
            sb.append(" ").append(fingerprint);
        }
        if (userId != null) {
            sb.append(" (").append(userId).append(")");
        }
        return sb.toString();
    }
}
