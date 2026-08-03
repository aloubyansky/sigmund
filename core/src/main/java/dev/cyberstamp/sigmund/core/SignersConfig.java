package dev.cyberstamp.sigmund.core;

import java.util.Map;
import java.util.Set;

/**
 * Read-only registry of signer identities, parsed from the {@code signers}
 * section of {@code sigmund.yaml}.
 * <p>
 * Provides name-based lookup and a strict {@link #resolve(String)} that
 * throws when a referenced signer is not defined — used by trust policy
 * resolution to fail fast on typos.
 *
 * @see SignerIdentity
 * @see SigmundConfig
 */
public class SignersConfig {

    /** Empty signer registry. */
    public static final SignersConfig EMPTY = new SignersConfig(Map.of());

    private final Map<String, SignerIdentity> signers;

    /**
     * Creates a signer registry from the given map.
     *
     * @param signers signer identities keyed by signer id
     */
    public SignersConfig(Map<String, SignerIdentity> signers) {
        this.signers = signers != null ? Map.copyOf(signers) : Map.of();
    }

    /**
     * Returns the signer with the given name, or {@code null} if not found.
     *
     * @param name the signer name
     * @return the signer identity, or {@code null}
     */
    public SignerIdentity get(String name) {
        return signers.get(name);
    }

    /**
     * Returns the signer with the given name, throwing if not found.
     * <p>
     * Used by trust policy resolution to fail fast on undefined signer references.
     *
     * @param name the signer name
     * @return the signer identity
     * @throws PolicyConfigException if the signer is not defined
     */
    public SignerIdentity resolve(String name) {
        SignerIdentity signer = signers.get(name);
        if (signer == null) {
            throw new PolicyConfigException("Undefined signer: '" + name + "'");
        }
        return signer;
    }

    /**
     * Returns all signer names in this registry.
     *
     * @return an unmodifiable set of signer names
     */
    public Set<String> names() {
        return signers.keySet();
    }

    /**
     * Returns whether this registry is empty.
     *
     * @return {@code true} if no signers are defined
     */
    public boolean isEmpty() {
        return signers.isEmpty();
    }
}
