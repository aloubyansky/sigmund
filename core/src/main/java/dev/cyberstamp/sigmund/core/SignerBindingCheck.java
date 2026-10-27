package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Checks that a signature Sigmund has just produced proves the signer {@code signing.signer}
 * asserts, so that a signature by the wrong key or identity is never written out.
 *
 * <p>
 * The fresh signature is checked the way verification checks a claim against a rule requiring
 * that signer: it is read as {@link Evidence#SOURCE_SIGNING} evidence, verified through a
 * {@link SignatureEvidenceAdapter} whose first tool is the producer (which holds the key)
 * followed by the format's other verifiers, and its proven credentials are completed by
 * {@link ClaimIdentityResolver} when the signer names an address a directory can vouch for.
 * Every claim in the file must then be {@link ClaimOutcome#VERIFIED} and prove the signer on its
 * own: some proven credential must match some signer credential by
 * {@link Clause#matches(Credential, Credential, List)}.
 *
 * <p>
 * Signing has no middle ground: a claim verification would call {@code INDETERMINATE} — an
 * algorithm no tool accepts, a directory that could not be asked, or a lookup the configuration
 * disables — fails signing, as does a file with no claim.
 *
 * <p>
 * The signer must already have its issuers resolved by
 * {@link SignerIdentity#withIssuersResolved(List)}: every identity entry names its issuer, so
 * matching needs no default issuers.
 */
final class SignerBindingCheck {

    private final SignerIdentity expected;
    private final ClaimIdentityResolver resolver;
    private final boolean lookupsEnabled;
    private final List<SignatureTool> verifiers;

    /**
     * Creates a check for one asserted signer.
     *
     * @param expected the signer {@code signing.signer} names, with its issuers resolved
     * @param directories the OpenPGP directories that may vouch for a key's addresses, by name
     * @param lookupsEnabled whether {@code verification.resolve-signers} lets a directory be asked
     * @param verifiers the verification tools; those of the producer's signature format are tried
     *        after the producer, in the order given
     */
    SignerBindingCheck(SignerIdentity expected, Map<String, OpenPgpDirectory> directories,
            boolean lookupsEnabled, List<SignatureTool> verifiers) {
        this.expected = expected;
        this.resolver = new ClaimIdentityResolver(directories, lookupsEnabled);
        this.lookupsEnabled = lookupsEnabled;
        this.verifiers = List.copyOf(verifiers);
    }

    /**
     * Checks that every claim in a freshly produced signature file proves the signer.
     *
     * @param artifactFile the signed artifact
     * @param producer the tool that produced the signature
     * @param signatureFile the signature the producer wrote
     * @throws SigmundException if the file holds no claim, or any claim does not verify or does
     *         not prove the signer; the message names the tool, the signer and what was proven
     */
    void check(Path artifactFile, SignatureTool producer, Path signatureFile) {
        Evidence evidence = Evidence.read(signatureFile, Evidence.SOURCE_SIGNING);
        List<ClaimResult> verified = verify(artifactFile, producer, evidence);
        if (verified.isEmpty()) {
            throw noClaim(producer);
        }
        List<ClaimResult> resolved = resolver.resolve(List.of(expected), List.of(), verified);
        for (int i = 0; i < verified.size(); i++) {
            requireProven(producer, verified.get(i), resolved.get(i));
        }
    }

    private List<ClaimResult> verify(Path artifactFile, SignatureTool producer,
            Evidence evidence) {
        SignatureEvidenceAdapter adapter = new SignatureEvidenceAdapter(
                producer.signatureFormat(), verifiersOf(producer));
        return adapter.verify(artifactFile, evidence);
    }

    private List<SignatureTool> verifiersOf(SignatureTool producer) {
        List<SignatureTool> tools = new ArrayList<>();
        tools.add(producer);
        String format = producer.signatureFormat().name();
        for (SignatureTool tool : verifiers) {
            if (tool != producer && tool.signatureFormat().name().equals(format)) {
                tools.add(tool);
            }
        }
        return tools;
    }

    private void requireProven(SignatureTool producer, ClaimResult verified,
            ClaimResult resolved) {
        if (verified.outcome() != ClaimOutcome.VERIFIED) {
            throw notVerified(producer, verified);
        }
        if (resolved.isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE)) {
            throw unresolved(producer, resolved);
        }
        if (!provesSigner(resolved)) {
            throw mismatch(producer, resolved);
        }
    }

    private boolean provesSigner(ClaimResult claim) {
        for (Credential signerCredential : expected.credentials()) {
            for (Credential proven : claim.attesterCredentials()) {
                if (Clause.matches(signerCredential, proven, List.of())) {
                    return true;
                }
            }
        }
        return false;
    }

    private SigmundException noClaim(SignatureTool producer) {
        return new SigmundException(prefix(producer) + "the file holds no signature");
    }

    private SigmundException notVerified(SignatureTool producer, ClaimResult claim) {
        String outcome = claim.reason() == null
                ? claim.outcome().name()
                : claim.outcome().name() + ": " + reportSpelling(claim.reason());
        return new SigmundException(prefix(producer) + "it did not verify (" + outcome + ")");
    }

    private SigmundException unresolved(SignatureTool producer, ClaimResult claim) {
        String key = describe(firstKey(claim));
        if (lookupsEnabled) {
            return new SigmundException(prefix(producer)
                    + "the directory could not be asked about key " + key);
        }
        return new SigmundException(prefix(producer) + "key " + key
                + " is not pinned by signer '" + expected.id()
                + "', and verification.resolve-signers is false, so no directory was asked");
    }

    private SigmundException mismatch(SignatureTool producer, ClaimResult claim) {
        return new SigmundException(prefix(producer) + "it proved "
                + describe(claim.attesterCredentials()) + "; signer '" + expected.id() + "' is "
                + describe(expected.credentials()));
    }

    private String prefix(SignatureTool producer) {
        return "Signature by " + producer.name() + " does not prove signer '" + expected.id()
                + "': ";
    }

    private static KeyCredential firstKey(ClaimResult claim) {
        for (Credential credential : claim.attesterCredentials()) {
            if (credential instanceof KeyCredential key) {
                return key;
            }
        }
        throw new IllegalStateException("an unresolved claim carries the key it was resolved by");
    }

    private static String describe(List<Credential> credentials) {
        if (credentials.isEmpty()) {
            return "no credential";
        }
        StringJoiner joiner = new StringJoiner(", ");
        for (Credential credential : credentials) {
            joiner.add(describe(credential));
        }
        return joiner.toString();
    }

    private static String describe(Credential credential) {
        return credential.type() + " " + credential.displayName();
    }

    private static String reportSpelling(IndeterminateReason reason) {
        return reason.name().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
