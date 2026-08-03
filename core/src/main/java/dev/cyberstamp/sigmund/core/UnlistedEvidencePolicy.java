package dev.cyberstamp.sigmund.core;

/**
 * Controls how evidence for formats not listed in a signer's credentials is handled.
 * <p>
 * "Unlisted" evidence is evidence found for a format that no expected signer has
 * credentials for (e.g., a {@code .sigstore.json} when the signer only has
 * {@code openpgp4} credentials).
 */
public enum UnlistedEvidencePolicy {
    /** Ignore unlisted evidence (don't probe unless no listed evidence found). */
    IGNORE,
    /** Probe all formats and log warnings for unlisted evidence. */
    WARN,
    /** Probe all formats and require unlisted evidence to match. */
    REQUIRE
}
