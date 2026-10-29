package dev.cyberstamp.sigmund.core;

/**
 * Capability interface for tools that can generate signing keys.
 * <p>
 * Not all backends support key generation — Sigstore is keyless, and GPG key
 * generation is typically done outside this tool. Callers can check for this
 * capability via {@code sigmund.findTool(KeyGenerator.class)}.
 *
 * @see CertExporter
 */
public interface KeyGenerator {

    /**
     * Generates a new signing key.
     *
     * @param userId the user ID for the key (e.g., {@code "Alice <alice@example.com>"})
     * @param cipherSuite the cipher suite to use (e.g., {@code "mldsa87-ed448"}); BC also accepts
     *        {@code null}, for the suite {@code tools.bc.cipher-suite} configures
     * @param credentialType the key version to generate, {@code pgp4} or {@code pgp6}, or
     *        {@code null} for the tool's default: {@code pgp4} for BC, whose v4 keys keyservers
     *        serve and GnuPG signs with, {@code pgp6} for Sequoia, whose post-quantum suites
     *        need v6
     * @return the fingerprint of the generated key
     * @throws ToolExecutionException if key generation fails, or the tool cannot produce the
     *         type with the suite
     */
    String generateKey(String userId, String cipherSuite, String credentialType);
}
