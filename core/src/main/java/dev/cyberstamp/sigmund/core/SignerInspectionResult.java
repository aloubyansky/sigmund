package dev.cyberstamp.sigmund.core;

import java.time.Instant;
import java.util.List;

/**
 * Metadata extracted from an OpenPGP public key found during signer inspection.
 *
 * <p>
 * Contains the key's cryptographic properties (algorithm, version, bit strength),
 * temporal validity (creation and expiration dates), user identity information
 * (User IDs), and subkey details.
 *
 * <p>
 * User IDs may be empty even when the key is found — {@code keys.openpgp.org}
 * strips User IDs unless the email owner has explicitly verified through their
 * opt-in process.
 *
 * @param fingerprint uppercase hex fingerprint of the primary key
 * @param version key packet version (4 or 6)
 * @param algorithm human-readable algorithm name (e.g. {@code "EdDSA"}, {@code "RSA"})
 * @param bitStrength key size in bits where applicable
 * @param creationDate when the key was created
 * @param expirationDate when the key expires, or {@code null} if it does not expire
 * @param userIds User ID strings attached to the key; may be empty
 * @param subkeys metadata for each subkey in the key ring
 * @see SignerSourceResult
 */
public record SignerInspectionResult(
        String fingerprint,
        int version,
        String algorithm,
        int bitStrength,
        Instant creationDate,
        Instant expirationDate,
        List<String> userIds,
        List<SubkeyInfo> subkeys) {

    public SignerInspectionResult {
        userIds = userIds != null ? List.copyOf(userIds) : List.of();
        subkeys = subkeys != null ? List.copyOf(subkeys) : List.of();
    }
}
