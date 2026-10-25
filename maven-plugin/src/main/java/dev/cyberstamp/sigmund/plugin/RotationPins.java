package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Clause;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IssuerKind;
import dev.cyberstamp.sigmund.core.KeyCredential;
import dev.cyberstamp.sigmund.core.Rule;
import dev.cyberstamp.sigmund.core.SignerIdentity;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The rotated keys an update pins onto the signers they belong to.
 *
 * <p>
 * A signer named by address accepts a key the publisher generates later, because the directory
 * confirms the address for it. That binding is current state: when the publisher rotates again,
 * the directory serves the key without the address, and old signatures can no longer be tied to
 * the signer. So when an update sees an artifact signed by a key its rule does not pin, and a
 * directory confirms the key for the address of a signer the rule requires, the key's
 * fingerprint is added to that signer — a reviewed change to the file that keeps proving those
 * artifacts offline and for good. A key no directory confirms stays a change for a
 * person to judge.
 */
final class RotationPins {

    /**
     * A key confirmed for a required signer's address.
     *
     * @param signerId the signer the key is pinned onto
     * @param key the key
     * @param issuer the directory that confirmed it
     * @param address the address it confirmed
     * @param modules the modules signed with the key
     */
    record Pin(String signerId, KeyCredential key, String issuer, String address, Set<String> modules) {

        /**
         * Notes, on the review line of a key that signed alongside this one, what the directory
         * confirmed — context for the reviewer, never a reason to accept the other key: a
         * signature can be added to an {@code .asc} by anyone who can change it, and a user ID by
         * anyone. It is written before the pin is applied, so it states the confirmation, not
         * that the key was added.
         */
        String alongside() {
            return "; signed alongside " + key.type() + " " + key.fingerprint() + ", which " + issuer
                    + " confirmed for " + address + " of signer '" + signerId
                    + "' — signing alongside does not show who holds this key";
        }

        /**
         * The comment written beside the pinned fingerprint, recording what it rests on.
         */
        String note() {
            return "pinned by update: " + issuer + " confirmed " + address;
        }

        String describe() {
            return String.join(", ", modules) + " — " + key.type() + " " + key.fingerprint()
                    + ", confirmed by " + issuer + " for " + address + ", added to signer '"
                    + signerId + "'";
        }
    }

    private final DirectoryLookup lookup;
    private final Map<List<String>, Pin> pins = new LinkedHashMap<>();
    private final List<Pin> applied = new ArrayList<>();

    /**
     * Creates the pins for one update.
     *
     * @param lookup asks directories for a key's verified addresses, or {@code null} when
     *        directories are not asked ({@code resolve-signers: false})
     */
    RotationPins(DirectoryLookup lookup) {
        this.lookup = lookup;
    }

    /**
     * Pins a key that signed an artifact its rule does not name, when a directory confirms it
     * for the address of a signer the rule requires. A key already pinned counts only for a rule
     * requiring the signer it was pinned onto; under a rule requiring another signer it is asked
     * about again, since the pin adds it to that other signer alone.
     *
     * @param module the artifact's module pattern
     * @param key the key
     * @param rule the rule that applies to the artifact
     * @param issuers the policy's default issuers
     * @return {@code null} when the key is pinned; otherwise a note for the review line, empty
     *         when there is nothing to add
     */
    String pin(String module, KeyCredential key, Rule rule, List<String> issuers) {
        Pin pinned = pinned(key, rule);
        if (pinned != null) {
            pinned.modules().add(module);
            return null;
        }
        String note = "";
        for (SignerIdentity signer : requiredSigners(rule)) {
            for (IdentityCredential entry : addressEntries(signer)) {
                List<String> directories = directoriesFor(entry, issuers);
                if (directories.isEmpty()) {
                    continue;
                }
                if (lookup == null) {
                    note = "; directory not asked (resolve-signers: false)";
                    continue;
                }
                try {
                    IdentityCredential confirmed = confirmed(entry, key, directories, issuers);
                    if (confirmed != null) {
                        pins.put(pinKey(signer.id(), key), new Pin(signer.id(), key, confirmed.issuer(),
                                confirmed.attribute(IdentityCredential.EMAIL),
                                new LinkedHashSet<>(List.of(module))));
                        return null;
                    }
                } catch (IOException e) {
                    note = "; directory unreachable: " + e.getMessage();
                }
            }
        }
        return note;
    }

    /**
     * Returns the pin of a key onto a signer a rule requires.
     *
     * @param key the key
     * @param rule the rule
     * @return the pin, or {@code null} when the key is not pinned onto any signer the rule
     *         requires
     */
    Pin pinned(KeyCredential key, Rule rule) {
        for (SignerIdentity signer : requiredSigners(rule)) {
            Pin pin = pins.get(pinKey(signer.id(), key));
            if (pin != null) {
                return pin;
            }
        }
        return null;
    }

    /**
     * Adds the pinned fingerprints to their signers in the config text.
     *
     * @param lines the config file lines, mutated in place
     * @return review lines for the pins whose signer cannot be edited
     */
    List<String> apply(List<String> lines) {
        List<String> review = new ArrayList<>();
        for (Pin pin : pins.values()) {
            if (SignerKeyEditor.addFingerprint(lines, pin.signerId(), pin.key().type(),
                    pin.key().fingerprint(), pin.note())) {
                applied.add(pin);
            } else {
                review.add(String.join(", ", pin.modules()) + " — " + pin.key().type() + " "
                        + pin.key().fingerprint() + " is confirmed by " + pin.issuer() + " for "
                        + pin.address() + ", but update cannot edit signer '" + pin.signerId()
                        + "'; add it to signer '" + pin.signerId() + "' by hand");
            }
        }
        return review;
    }

    /**
     * Returns the pins written into the config.
     *
     * @return the applied pins, in the order they were found
     */
    List<Pin> applied() {
        return List.copyOf(applied);
    }

    private static List<String> pinKey(String signerId, KeyCredential key) {
        return List.of(signerId, key.fingerprint());
    }

    private static List<SignerIdentity> requiredSigners(Rule rule) {
        List<SignerIdentity> signers = new ArrayList<>();
        for (Clause clause : rule.requirement().clauses()) {
            for (SignerIdentity signer : clause.signers()) {
                if (!signers.contains(signer)) {
                    signers.add(signer);
                }
            }
        }
        return signers;
    }

    private static List<IdentityCredential> addressEntries(SignerIdentity signer) {
        List<IdentityCredential> entries = new ArrayList<>();
        for (Credential credential : signer.credentials()) {
            if (credential instanceof IdentityCredential entry
                    && IssuerKind.OPENPGP_DIRECTORY.asserts(entry.attributes().keySet())) {
                entries.add(entry);
            }
        }
        return entries;
    }

    private static List<String> directoriesFor(IdentityCredential entry, List<String> issuers) {
        List<String> candidates = entry.issuer() != null ? List.of(entry.issuer()) : issuers;
        return candidates.stream()
                .filter(name -> IssuerKind.of(name) == IssuerKind.OPENPGP_DIRECTORY)
                .toList();
    }

    private IdentityCredential confirmed(IdentityCredential entry, KeyCredential key,
            List<String> directories, List<String> issuers) throws IOException {
        for (IdentityCredential identity : lookup.identities(key, directories)) {
            if (entry.matches(identity, issuers)) {
                return identity;
            }
        }
        return null;
    }
}
