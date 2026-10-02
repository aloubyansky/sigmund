package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolves who the key behind a verified OpenPGP claim belongs to, by adding the identities a
 * directory vouches for, where policy needs them.
 *
 * <p>
 * An OpenPGP signature proves a key, not who holds it. When a signer is named by address with
 * a directory as issuer, the directory is asked which verified addresses it serves for the
 * signing key, and each becomes an {@link IdentityCredential} the claim proves. That is what
 * lets policy accept a publisher's key generated after the policy was written.
 *
 * <p>
 * The directory is asked only when the answer can matter: for an artifact whose expected
 * signers include an email entry a directory can vouch for, and for a claim whose key none of
 * those signers' pinned fingerprints already accepts. A signer carrying both fingerprints and
 * an address therefore verifies offline for the keys already pinned, and only a new key costs
 * a lookup.
 *
 * <p>
 * A lookup that fails leaves the claim {@link IndeterminateReason#KEY_UNAVAILABLE}, never a
 * pass and never a rejection: whether the signer is trusted could not be decided.
 */
final class ClaimIdentityResolver {

    private final TrustPolicy policy;
    private final Map<String, OpenPgpDirectory> directories;
    private final boolean lookupsEnabled;

    /**
     * Creates the resolver for a policy.
     *
     * @param policy the policy whose signers decide when a lookup is needed
     * @param directories the known directories by canonical name
     * @param lookupsEnabled whether directories may be asked over the network; when not, a
     *        needed lookup leaves the claim indeterminate
     */
    ClaimIdentityResolver(TrustPolicy policy, Map<String, OpenPgpDirectory> directories,
            boolean lookupsEnabled) {
        this.policy = policy;
        this.directories = Map.copyOf(directories);
        this.lookupsEnabled = lookupsEnabled;
    }

    /**
     * Resolves who the keys of an artifact's claims belong to, where policy needs it, by
     * adding the identities a directory vouches for.
     *
     * @param coords the artifact, which selects the expected signers
     * @param claims the claims found for it
     * @return the claims, with directory identities added where policy needs them
     */
    List<ClaimResult> resolve(ArtifactCoords coords, List<ClaimResult> claims) {
        List<SignerIdentity> expected = policy.expectedSigners(coords);
        Set<String> needed = neededDirectories(expected);
        if (needed.isEmpty()) {
            return claims;
        }
        List<ClaimResult> resolved = new ArrayList<>(claims.size());
        for (ClaimResult claim : claims) {
            resolved.add(needsLookup(claim, expected) ? lookUp(claim, needed) : claim);
        }
        return resolved;
    }

    private Set<String> neededDirectories(List<SignerIdentity> signers) {
        Set<String> needed = new LinkedHashSet<>();
        for (SignerIdentity signer : signers) {
            for (Credential credential : signer.credentials()) {
                if (credential instanceof IdentityCredential entry
                        && IssuerKind.OPENPGP_DIRECTORY.asserts(entry.attributes().keySet())) {
                    addDirectories(needed, entry);
                }
            }
        }
        return needed;
    }

    private void addDirectories(Set<String> needed, IdentityCredential entry) {
        List<String> issuers = entry.issuer() != null ? List.of(entry.issuer()) : policy.issuers();
        for (String issuer : issuers) {
            if (directories.containsKey(issuer)) {
                needed.add(issuer);
            }
        }
    }

    private static boolean needsLookup(ClaimResult claim, List<SignerIdentity> expected) {
        List<KeyCredential> keys = keysOf(claim);
        return claim.outcome() == ClaimOutcome.VERIFIED
                && !keys.isEmpty()
                && !pinned(keys, expected);
    }

    private static boolean pinned(List<KeyCredential> keys, List<SignerIdentity> expected) {
        for (SignerIdentity signer : expected) {
            for (Credential credential : signer.credentials()) {
                for (KeyCredential key : keys) {
                    if (credential.matches(key)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private ClaimResult lookUp(ClaimResult claim, Set<String> needed) {
        if (!lookupsEnabled) {
            return claim.unresolved(IndeterminateReason.KEY_UNAVAILABLE);
        }
        String fingerprint = keysOf(claim).get(0).fingerprint();
        List<Credential> identities = new ArrayList<>();
        for (String name : needed) {
            try {
                for (String address : directories.get(name).verifiedAddresses(fingerprint)) {
                    identities.add(IdentityCredential.email(name, address));
                }
            } catch (IOException unavailable) {
                return claim.unresolved(IndeterminateReason.KEY_UNAVAILABLE);
            }
        }
        return identities.isEmpty() ? claim : claim.withAdditionalCredentials(identities);
    }

    private static List<KeyCredential> keysOf(ClaimResult claim) {
        List<KeyCredential> keys = List.of();
        for (Credential credential : claim.attesterCredentials()) {
            if (credential instanceof KeyCredential key) {
                if (keys.isEmpty()) {
                    keys = new ArrayList<>(2);
                }
                keys.add(key);
            }
        }
        return keys;
    }
}
