package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Derives proven credentials from a verified OpenPGP signature.
 *
 * <p>
 * Every OpenPGP backend — Bouncy Castle, Sequoia and GnuPG — proves the same thing, because
 * what a verified signature establishes is a property of the signature rather than of the
 * tool that checked it: the key that made it. Each tool still owns the decision to use this
 * mapping, as the {@link SignatureTool#extractCredentials(VerifyResult)} contract requires;
 * they simply agree on the answer.
 *
 * <p>
 * A user ID proves nothing here. It is self-certified — anyone can put any address on a key —
 * so it is display text; an address becomes an identity only when a directory that verifies
 * addresses served it for this key.
 */
public final class OpenPgpCredentials {

    private OpenPgpCredentials() {
    }

    /**
     * Returns the key material a result proves.
     *
     * <p>
     * An unverified claim proves nothing, whatever metadata it carries: a signature that did
     * not verify says nothing about who made it. The credential type follows the signature
     * packet version, so a v6 signature proves a v6 credential and policy written for one does
     * not silently accept the other. Both the verifying key and, when it is a subkey, its
     * primary key are proven, by full fingerprint only: a 64-bit key ID is not proof of a key.
     *
     * @param result the verification result
     * @return the proven credentials, empty when the claim did not verify
     */
    public static List<Credential> from(VerifyResult result) {
        if (result == null || !result.isVerified()
                || !(result instanceof OpenPgpVerifyResult openPgp)) {
            return List.of();
        }
        String type = openPgp.version() < 6
                ? Credential.TYPE_OPENPGP_V4
                : Credential.TYPE_OPENPGP_V6;
        List<Credential> credentials = new ArrayList<>(2);
        addKey(credentials, type, openPgp.fingerprint());
        addKey(credentials, type, openPgp.primaryFingerprint());
        return List.copyOf(credentials);
    }

    private static void addKey(List<Credential> credentials, String type, String fingerprint) {
        if (!KeyCredential.isOpenPgpFingerprint(fingerprint)) {
            return;
        }
        KeyCredential key = KeyCredential.openPgp(fingerprint);
        if (key.type().equals(type) && !credentials.contains(key)) {
            credentials.add(key);
        }
    }

    /**
     * Extracts the email address from an OpenPGP user ID of the form {@code "Name <email>"},
     * accepting a bare address as well.
     *
     * @param userId the user ID string, may be {@code null}
     * @return the extracted email, or {@code null} when the user ID carries none
     */
    public static String email(String userId) {
        if (userId == null) {
            return null;
        }
        int open = userId.indexOf('<');
        int close = userId.indexOf('>', open + 1);
        if (open >= 0 && close > open + 1) {
            return userId.substring(open + 1, close).trim();
        }
        String trimmed = userId.trim();
        if (trimmed.contains("@") && !trimmed.contains(" ")) {
            return trimmed;
        }
        return null;
    }
}
