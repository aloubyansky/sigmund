package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.util.List;

/**
 * An OpenPGP directory: one that publishes an address on a key only after verifying it with
 * the address owner, and so can vouch for the address belonging to that key. It is the issuer
 * kind {@link IssuerKind#OPENPGP_DIRECTORY}.
 *
 * <p>
 * A user ID on an OpenPGP key is self-certified; the binding a directory serves is not, which
 * is what lets a policy trust a signer by address and accept keys generated after the policy
 * was written. The binding is current state, not history: a directory associates an address
 * with one key, so after a rotation the old key is served without it.
 */
interface OpenPgpDirectory extends AutoCloseable {

    /**
     * Returns the directory's canonical issuer name, as policy lists it.
     *
     * @return the name, such as {@link IssuerKind#KEYS_OPENPGP_ORG}
     */
    String name();

    /**
     * Returns the verified addresses the directory serves for the key holding a fingerprint.
     *
     * @param fingerprint the full fingerprint of the primary key or a subkey
     * @return the addresses, lower case; empty when the directory has no such key or has
     *         verified no address for it
     * @throws IOException if the directory could not be asked
     */
    List<String> verifiedAddresses(String fingerprint) throws IOException;

    /**
     * Releases anything the directory holds open, such as an HTTP client. Does nothing by
     * default.
     */
    @Override
    default void close() {
    }
}
