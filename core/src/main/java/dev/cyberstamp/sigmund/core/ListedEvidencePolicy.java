package dev.cyberstamp.sigmund.core;

/**
 * Controls how evidence for formats listed in a signer's credentials is evaluated.
 * <p>
 * "Listed" evidence is evidence whose format matches a credential type in the
 * expected signer's credential bag (e.g., a {@code .sigstore.json} file is listed
 * evidence when the signer has a {@code sigstore} credential).
 */
public enum ListedEvidencePolicy {
    /** All listed evidence must match an expected signer. */
    ALL,
    /** At least one listed evidence match is sufficient. */
    ANY
}
