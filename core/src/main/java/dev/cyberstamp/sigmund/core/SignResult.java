package dev.cyberstamp.sigmund.core;

/**
 * The result of a signing operation, carrying metadata about the produced signature.
 * <p>
 * Exists as a dedicated type (rather than a bare {@code String}) because it is
 * the return type of the {@link SignatureTool#sign} SPI — adding fields here
 * is backward-compatible.
 *
 * @param algorithm the algorithm actually used for signing
 *        (e.g., {@code "RSA"}, {@code "ML-DSA-87+Ed448"}, {@code "EC"})
 */
public record SignResult(String algorithm) {
}
