package dev.cyberstamp.sigmund.core;

/**
 * Capability interface for tools that can fetch public keys from keyservers.
 * <p>
 * Each tool that implements this interface owns its key fetching configuration:
 * keyservers, persistence mode ({@code importToKeyring}), and whether fetching
 * is enabled at all ({@code resolveSigners}). The caller simply asks the tool
 * to fetch a key by ID — the tool handles keyserver iteration, caching, circuit
 * breaking, and storage internally.
 *
 * @see KeyFetchCache
 */
public interface KeyImporter {

    /**
     * Attempts to fetch a public key from the configured keyservers.
     * <p>
     * Returns {@code true} if the key was fetched and is now available for
     * verification. Returns {@code false} if fetching is disabled
     * ({@code resolveSigners=false}), the tool cannot fetch in its current
     * mode (e.g., GPG with {@code importToKeyring=false}), the key was not
     * found, or a connection failure occurred.
     *
     * @param keyId the key ID or fingerprint to fetch
     * @return {@code true} if the key was fetched successfully
     */
    boolean fetchKey(String keyId);

    /**
     * Returns {@code true} if this tool is capable of fetching keys in its
     * current configuration.
     * <p>
     * A tool returns {@code false} when fetching is structurally impossible —
     * e.g., {@code resolveSigners} is disabled, or the tool requires
     * {@code importToKeyring=true} but it is {@code false}.
     */
    boolean canFetchKeys();
}
