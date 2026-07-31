package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * Capability for inspecting a signer identity across available sources.
 * <p>
 * Tools implementing this interface can query their configured sources
 * (keyservers, local stores, WKD, Rekor) and return per-source results
 * describing what is known about the signer.
 *
 * @see BcRunner
 * @see Credential
 * @see SignerSourceResult
 */
public interface SignerInspection {

    /**
     * Inspects a signer identity across all sources available to this tool.
     *
     * @param credential the identity to look up (fingerprint, email, OIDC)
     * @return per-source results, one entry per source queried; never null
     */
    List<SignerSourceResult> inspect(Credential credential);

    /**
     * Whether this tool can inspect the given credential type.
     *
     * @param credential the credential to check
     * @return true if this tool can handle the credential type
     */
    boolean canInspect(Credential credential);
}
