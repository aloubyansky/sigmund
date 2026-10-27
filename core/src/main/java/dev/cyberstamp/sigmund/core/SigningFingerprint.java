package dev.cyberstamp.sigmund.core;

import java.util.Map;

/**
 * The {@code signing-fingerprint} setting of an OpenPGP tool: the full fingerprint of the key it
 * signs with.
 *
 * <p>
 * A full fingerprint — 40 hex characters for a v4 key, 64 for v6, in either case — names one key.
 * A key ID, an address or a user ID can match several keys in a keyring and leave the tool to
 * choose, so they are rejected: the key a tool signs with is the one the setting names, which
 * {@code signing.signer} then holds to the signer's pinned fingerprints.
 */
final class SigningFingerprint {

    private SigningFingerprint() {
    }

    /**
     * Reads the setting, normalized to upper case.
     *
     * @param toolName the tool whose settings these are, named in the error
     * @param setting the tool's {@code signing-fingerprint} setting
     * @param settings the tool's settings
     * @return the fingerprint, or {@code null} when not set
     * @throws PolicyConfigException if the value is not a full v4 or v6 fingerprint
     */
    static String from(String toolName, ToolSetting setting, Map<String, String> settings) {
        String value = setting.from(settings);
        if (value == null) {
            return null;
        }
        if (!KeyCredential.isOpenPgpFingerprint(value)) {
            throw new PolicyConfigException("tools." + toolName + "." + setting.key() + ": '" + value
                    + "' is not a full fingerprint (40 hex characters for a v4 key, 64 for v6); key IDs,"
                    + " addresses and user IDs are not accepted because they can name more than one key");
        }
        return KeyCredential.openPgp(value).fingerprint();
    }
}
