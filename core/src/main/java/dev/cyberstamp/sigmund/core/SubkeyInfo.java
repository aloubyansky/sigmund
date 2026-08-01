package dev.cyberstamp.sigmund.core;

import java.util.Set;

/**
 * Metadata for a single subkey within an OpenPGP key ring.
 *
 * @param fingerprint uppercase hex fingerprint of the subkey
 * @param algorithm human-readable algorithm name (e.g. {@code "ECDH"}, {@code "EdDSA"})
 * @param bitStrength key size in bits where applicable
 * @param capabilities key usage flags extracted from the binding signature
 *        (e.g. {@code "sign"}, {@code "encrypt"}, {@code "certify"}, {@code "authenticate"})
 * @see SignerInspectionResult
 */
public record SubkeyInfo(
        String fingerprint,
        String algorithm,
        int bitStrength,
        Set<String> capabilities) {

    public SubkeyInfo {
        capabilities = capabilities != null ? Set.copyOf(capabilities) : Set.of();
    }
}
