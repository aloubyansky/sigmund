package dev.cyberstamp.sigmund.core;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;

/**
 * An identity asserted by an issuer: who vouched, and what they attested.
 *
 * <p>
 * A proven identity always names its issuer — the OIDC provider that authenticated a Fulcio
 * certificate's subject, or the directory that verified an address before publishing it. An
 * identity with no one vouching for it proves nothing, which is why a self-certified OpenPGP
 * user ID never becomes one.
 *
 * <p>
 * In policy the issuer is optional. An entry without one is satisfied by any issuer the
 * policy lists as a default, passed to {@link #matches(Credential, Collection)}; an entry that
 * names one is satisfied by that issuer only, whether or not it is listed.
 *
 * <p>
 * {@code subject} is one attribute, not the identifier: a CI workflow's subject carries the
 * release tag and changes with every release, so stable policy names the certificate's other
 * attributes instead. The {@code email} attribute is normalized to lower case, since
 * directories and OIDC providers treat addresses case-insensitively; other attributes are
 * kept and compared exactly.
 *
 * @param issuer who vouched for the identity, or {@code null} in a policy entry that defers to
 *        the default issuers
 * @param attributes what the issuer attested, never empty
 */
public record IdentityCredential(String issuer, Map<String, String> attributes)
        implements
            Credential {

    /** The subject the issuer authenticated. */
    public static final String SUBJECT = "subject";
    /** A verified email address. */
    public static final String EMAIL = "email";

    /**
     * Normalizes the issuer and attributes.
     *
     * @throws IllegalArgumentException if there are no attributes, or one is blank
     */
    public IdentityCredential {
        issuer = issuer == null || issuer.isBlank() ? null : issuer.trim();
        attributes = normalize(attributes);
    }

    /**
     * Creates an email identity.
     *
     * @param issuer who vouched for the address, or {@code null} to defer to default issuers
     * @param address the address
     * @return the credential
     */
    public static IdentityCredential email(String issuer, String address) {
        return new IdentityCredential(issuer, Map.of(EMAIL, address));
    }

    /**
     * Returns an attribute value.
     *
     * @param name the attribute name
     * @return the value, or {@code null} when the issuer did not attest it
     */
    public String attribute(String name) {
        return attributes.get(name);
    }

    @Override
    public String type() {
        return TYPE_IDENTITY;
    }

    @Override
    public String displayName() {
        StringJoiner joiner = new StringJoiner(", ", "{", "}");
        attributes.forEach((name, value) -> joiner.add(name + "=" + value));
        return issuer == null ? joiner.toString() : joiner + " via " + issuer;
    }

    /**
     * Matches a proven identity from this entry's own issuer, with no default issuers.
     *
     * @param proven the credential a verified claim proved
     * @return {@code true} if it satisfies this entry
     * @see #matches(Credential, Collection)
     */
    @Override
    public boolean matches(Credential proven) {
        return matches(proven, List.of());
    }

    /**
     * Matches a proven identity.
     *
     * <p>
     * The proven issuer must be this entry's issuer when it names one, or otherwise one of the
     * default issuers; every attribute this entry names must be present in the proven
     * credential with an equal value. Naming fewer attributes matches more broadly.
     *
     * @param proven the credential a verified claim proved
     * @param defaultIssuers the issuers trusted for entries that name none
     * @return {@code true} if the proven credential satisfies this entry
     */
    public boolean matches(Credential proven, Collection<String> defaultIssuers) {
        if (!(proven instanceof IdentityCredential identity) || identity.issuer() == null) {
            return false;
        }
        if (!acceptsIssuer(identity.issuer(), defaultIssuers)) {
            return false;
        }
        return identity.attributes().entrySet().containsAll(attributes.entrySet());
    }

    private boolean acceptsIssuer(String provenIssuer, Collection<String> defaultIssuers) {
        return issuer != null
                ? issuer.equals(provenIssuer)
                : defaultIssuers != null && defaultIssuers.contains(provenIssuer);
    }

    private static Map<String, String> normalize(Map<String, String> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            throw new IllegalArgumentException("an identity must carry at least one attribute");
        }
        Map<String, String> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String value = entry.getValue();
            if (entry.getKey() == null || entry.getKey().isBlank()
                    || value == null || value.isBlank()) {
                throw new IllegalArgumentException(
                        "identity attributes must have a name and a value: " + attributes);
            }
            String trimmed = value.trim();
            normalized.put(entry.getKey().trim(),
                    EMAIL.equals(entry.getKey()) ? trimmed.toLowerCase(Locale.ROOT) : trimmed);
        }
        return Collections.unmodifiableMap(normalized);
    }
}
