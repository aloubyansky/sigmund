package dev.cyberstamp.sigmund.core;

/**
 * A Sigstore verification bundle extracted from a signature file.
 * <p>
 * Holds the JSON bundle text (natural representation for Sigstore).
 * The entire bundle is a single verifiable claim — no sub-parsing is needed.
 *
 * @param jsonBundle the Sigstore bundle as a JSON string
 */
public record SigstoreClaim(
        String jsonBundle) implements Claim {
}
