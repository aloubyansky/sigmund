package dev.cyberstamp.sigmund.core;

/**
 * A fact about who made a claim, classified by who vouches for it.
 *
 * <p>
 * There are two kinds, and the difference between them is what trust rests on:
 * <ul>
 * <li>{@link KeyCredential} — key material, proven by the signature itself. Nothing else has
 * to be trusted and it works offline, but it covers only keys already seen.</li>
 * <li>{@link IdentityCredential} — an identity asserted by an issuer such as an OIDC provider
 * or a directory that verifies addresses. It survives key rotation, so it is what lets a
 * policy accept keys a publisher has not generated yet, and it is only as strong as the
 * issuer's account security.</li>
 * </ul>
 *
 * <p>
 * The same types serve policy and evidence: a signer in policy lists credentials, a verified
 * claim proves credentials, and {@link #matches(Credential)} is called on the policy side with
 * the proven one. A key never matches an identity, whatever either says.
 *
 * <p>
 * The type constants double as the names of the signature types a signing tool produces, as
 * used by {@code signing.credential-types}.
 *
 * @see SignerIdentity
 */
public sealed interface Credential permits KeyCredential, IdentityCredential {

    /** OpenPGP v4 key material. */
    String TYPE_OPENPGP_V4 = "openpgp4";
    /** OpenPGP v6 key material. */
    String TYPE_OPENPGP_V6 = "openpgp6";
    /** An issuer-asserted identity. */
    String TYPE_IDENTITY = "identity";
    /** Signature type produced by Sigstore keyless signing. */
    String TYPE_SIGSTORE = "sigstore";

    /**
     * Returns the credential type: the key type for key material, {@link #TYPE_IDENTITY} for
     * an identity.
     *
     * @return the type string, never {@code null}
     */
    String type();

    /**
     * Returns a human-readable representation for reports.
     *
     * @return the display name, never {@code null}
     */
    String displayName();

    /**
     * Checks whether this credential, as written in policy, is satisfied by a proven one.
     *
     * @param proven the credential a verified claim proved
     * @return {@code true} if the proven credential satisfies this one
     */
    boolean matches(Credential proven);
}
