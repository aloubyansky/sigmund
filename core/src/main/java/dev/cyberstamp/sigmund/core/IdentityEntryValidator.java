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
 * <li>an attribute no issuer kind asserts, with the nearest known name suggested;</li>
 * <li>an entry none of its issuers can assert — its own issuer if it names one, otherwise the
 * listed default issuers — naming the kind of issuer to add.</li>
 * </ul>
 */
final class IdentityEntryValidator {

    private static final int MAX_SUGGESTION_DISTANCE = 3;

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
        if (kinds.stream().noneMatch(kind -> kind.asserts(names))) {
            throw new PolicyConfigException(unassertableMessage(signer, entry, names));
        }
    }

    private static void rejectUnknownAttributes(String signer, Collection<String> names) {
        Set<String> known = knownAttributes();
        for (String name : names) {
            if (!known.contains(name)) {
                String suggestion = nearest(name, known);
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

    private static String nearest(String name, Collection<String> candidates) {
        String best = null;
        int bestDistance = MAX_SUGGESTION_DISTANCE + 1;
        for (String candidate : candidates) {
            int distance = distance(name, candidate);
            if (distance < bestDistance) {
                best = candidate;
                bestDistance = distance;
            }
        }
        return best;
    }

    private static int distance(String a, String b) {
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int substitution = previous[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1);
                current[j] = Math.min(substitution, Math.min(previous[j], current[j - 1]) + 1);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }
}
