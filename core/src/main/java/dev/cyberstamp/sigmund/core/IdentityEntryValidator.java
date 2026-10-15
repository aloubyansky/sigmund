package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Checks, at config load, that every identity entry in policy can be satisfied.
 *
 * <p>
 * An entry that no issuer can satisfy is not harmless: an ignored misspelled attribute would
 * leave an entry accepting more than intended, and an attribute nobody asserts would leave a
 * signer that silently never matches. So both are errors that name the signer and the fix:
 * <ul>
 * <li>an issuer — listed, or named on an entry — that is neither a known directory nor an
 * {@code https://} OIDC issuer URL, since its kind, and so what it can assert, is unknown;</li>
 * <li>an attribute no issuer kind asserts, with the nearest known name suggested;</li>
 * <li>an entry none of its issuers can assert — its own issuer if it names one, otherwise the
 * listed default issuers — naming the kind of issuer to add.</li>
 * </ul>
 */
final class IdentityEntryValidator {

    private IdentityEntryValidator() {
    }

    /**
     * Validates every identity entry of every signer.
     *
     * @param signers the parsed signers
     * @param defaultIssuers the canonical names of the listed issuers
     * @throws PolicyConfigException if an entry cannot be satisfied
     */
    static void validate(SignersConfig signers, List<String> defaultIssuers) {
        rejectUnclassifiableIssuers(signers, defaultIssuers);
        for (String name : signers.names()) {
            for (Credential credential : signers.get(name).credentials()) {
                if (credential instanceof IdentityCredential identity) {
                    validateEntry(name, identity, defaultIssuers);
                }
            }
        }
    }

    private static void validateEntry(String signer, IdentityCredential entry,
            List<String> defaultIssuers) {
        Set<String> names = entry.attributes().keySet();
        rejectUnknownAttributes(signer, names);
        List<IssuerKind> kinds = issuerKinds(entry, defaultIssuers);
        long assertingCount = kinds.stream().filter(kind -> kind.asserts(names)).count();
        if (assertingCount == 0) {
            throw new PolicyConfigException(unassertableMessage(signer, entry, names));
        }
        if (entry.issuer() == null) {
            long assertingKindCount = kinds.stream()
                    .filter(kind -> kind.asserts(names))
                    .distinct()
                    .count();
            if (assertingKindCount == 1 && assertingCount > 1) {
                throw new PolicyConfigException(ambiguousMessage(signer, names));
            }
        }
    }

    /**
     * Rejects issuers whose kind cannot be told from their name. Runs before anything asks an
     * issuer what it can assert, which presumes a kind.
     */
    private static void rejectUnclassifiableIssuers(SignersConfig signers,
            List<String> defaultIssuers) {
        for (String issuer : defaultIssuers) {
            requireClassifiable(issuer, "'issuers'");
        }
        for (String name : signers.names()) {
            for (Credential credential : signers.get(name).credentials()) {
                if (credential instanceof IdentityCredential identity && identity.issuer() != null) {
                    requireClassifiable(identity.issuer(), "signer '" + name + "'");
                }
            }
        }
    }

    private static void requireClassifiable(String issuer, String where) {
        if (IssuerKind.of(issuer) == null) {
            throw new PolicyConfigException("Issuer '" + issuer + "' in " + where
                    + " is neither a known directory (" + IssuerKind.KEYS_OPENPGP_ORG
                    + ") nor an https:// OIDC issuer URL");
        }
    }

    private static void rejectUnknownAttributes(String signer, Collection<String> names) {
        Set<String> known = knownAttributes();
        for (String name : names) {
            if (!known.contains(name)) {
                String suggestion = NearestName.among(name, known);
                throw new PolicyConfigException("Signer '" + signer + "': unknown attribute '"
                        + name + "'"
                        + (suggestion == null ? "; known: " + String.join(", ", known)
                                : " — did you mean '" + suggestion + "'?"));
            }
        }
    }

    private static List<IssuerKind> issuerKinds(IdentityCredential entry,
            List<String> defaultIssuers) {
        List<String> issuers = entry.issuer() != null ? List.of(entry.issuer()) : defaultIssuers;
        List<IssuerKind> kinds = new ArrayList<>(issuers.size());
        for (String issuer : issuers) {
            kinds.add(IssuerKind.of(issuer));
        }
        return kinds;
    }

    private static String unassertableMessage(String signer, IdentityCredential entry,
            Collection<String> names) {
        String attributes = String.join(", ", new TreeSet<>(names));
        if (entry.issuer() != null) {
            return "Signer '" + signer + "': issuer '" + entry.issuer()
                    + "' cannot assert " + attributes;
        }
        return "Signer '" + signer + "': no listed issuer can assert " + attributes
                + "; add one to 'issuers' (" + candidateHint(names)
                + ") or name an issuer on the entry";
    }

    private static String ambiguousMessage(String signer, Collection<String> names) {
        String attributes = String.join(", ", new TreeSet<>(names));
        return "Signer '" + signer + "': ambiguous — multiple listed issuers can assert "
                + attributes + "; name the issuer inline on the entry";
    }

    private static String candidateHint(Collection<String> names) {
        return IssuerKind.OPENPGP_DIRECTORY.asserts(names)
                ? "for example " + IssuerKind.KEYS_OPENPGP_ORG + ", or an OIDC issuer URL"
                : "an OIDC issuer URL, such as https://token.actions.githubusercontent.com";
    }

    private static Set<String> knownAttributes() {
        Set<String> known = new TreeSet<>();
        for (IssuerKind kind : IssuerKind.values()) {
            known.addAll(kind.attributes());
        }
        return known;
    }
}
