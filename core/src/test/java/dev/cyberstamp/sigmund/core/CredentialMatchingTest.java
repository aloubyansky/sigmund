package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CredentialMatchingTest {

    private static final ArtifactCoords COORDS = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");

    private static final EvidenceRef EVIDENCE_REF = new EvidenceRef(
            Path.of("artifact.jar.asc"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            Evidence.SOURCE_SIDECAR);

    private static final VerifyResult PGP_PASS = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 4, null,
            null);
    private static final VerifyResult SIGSTORE_PASS = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, null, null, null,
            null, -1);

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

    @Test
    void fingerprintMatchV4() {
        var signer = new SignerIdentity("alice", List.of(
                new KeyCredential("openpgp4", FP)));

        var evidence = claim(List.of(new KeyCredential("openpgp4", FP.toLowerCase())));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void fingerprintSharingOnlyAKeyIdDoesNotMatch() {
        var signer = new SignerIdentity("alice", List.of(
                new KeyCredential("openpgp4", FP)));

        var evidence = claim(List.of(new KeyCredential("openpgp4",
                "000000000000000000000000" + FP.substring(24))));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void emailFromAListedIssuerMatchesAcrossBackends() {
        var signer = new SignerIdentity("alice", List.of(
                IdentityCredential.email(null, "alice@example.com")));
        var issuers = List.of(IssuerKind.KEYS_OPENPGP_ORG, "https://accounts.google.com");

        var sigstore = claim(List.of(new IdentityCredential("https://accounts.google.com",
                Map.of(IdentityCredential.SUBJECT, "alice@example.com",
                        IdentityCredential.EMAIL, "alice@example.com"))));
        var directory = claim(List.of(
                IdentityCredential.email(IssuerKind.KEYS_OPENPGP_ORG, "Alice@Example.com")));

        assertThat(matchesAny(signer, sigstore, issuers)).isTrue();
        assertThat(matchesAny(signer, directory, issuers)).isTrue();
    }

    @Test
    void emailFromAnUnlistedIssuerDoesNotMatch() {
        var signer = new SignerIdentity("alice", List.of(
                IdentityCredential.email(null, "alice@example.com")));

        var evidence = claim(List.of(new IdentityCredential("https://evil-issuer.com",
                Map.of(IdentityCredential.EMAIL, "alice@example.com"))));

        assertThat(matchesAny(signer, evidence, List.of(IssuerKind.KEYS_OPENPGP_ORG))).isFalse();
    }

    @Test
    void inlineIssuerNeedNotBeListed() {
        var signer = new SignerIdentity("bot", List.of(
                new IdentityCredential("https://accounts.google.com",
                        Map.of(IdentityCredential.EMAIL, "bot@example.com"))));

        var evidence = claim(List.of(new IdentityCredential("https://accounts.google.com",
                Map.of(IdentityCredential.EMAIL, "bot@example.com"))));

        assertThat(matchesAny(signer, evidence, List.of())).isTrue();
    }

    @Test
    void sigstoreMatchStrictIssuer() {
        var signer = new SignerIdentity("ci", List.of(
                new IdentityCredential("https://token.actions.githubusercontent.com",
                        Map.of(IdentityCredential.SUBJECT, "https://github.com/org/repo"))));

        var evidence = claim(List.of(
                new IdentityCredential("https://token.actions.githubusercontent.com",
                        Map.of(IdentityCredential.SUBJECT, "https://github.com/org/repo"))));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void sigstoreMismatchWrongIssuer() {
        var signer = new SignerIdentity("ci", List.of(
                new IdentityCredential("https://token.actions.githubusercontent.com",
                        Map.of(IdentityCredential.SUBJECT, "https://github.com/org/repo"))));

        var evidence = claim(List.of(
                new IdentityCredential("https://evil-issuer.com",
                        Map.of(IdentityCredential.SUBJECT, "https://github.com/org/repo"))));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void noOverlapDifferentCredentialTypes() {
        var signer = new SignerIdentity("alice", List.of(
                new KeyCredential("openpgp4", "4AEE18F83AFDEB23000000000000000000000000")));

        var evidence = claim(List.of(
                IdentityCredential.email(null, "alice@example.com")));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void multipleCredentialsOneMatches() {
        var signer = new SignerIdentity("alice", List.of(
                new KeyCredential("openpgp4", "4AEE18F83AFDEB23000000000000000000000000"),
                new KeyCredential("openpgp6", "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"),
                IdentityCredential.email(null, "alice@example.com")));

        var evidence = claim(List.of(
                new KeyCredential("openpgp6", "ABCD1234ABCD1234000000000000000000000000000000000000000000000000")));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void emptyCredentialsNoMatch() {
        var signer = new SignerIdentity("empty", List.of());
        var evidence = claim(List.of(
                IdentityCredential.email(null, "alice@example.com")));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    /**
     * Runs the production matching path: a policy that expects this signer, evaluated over a
     * claim that proved these credentials.
     */
    private static boolean matchesAny(SignerIdentity signer, ClaimResult claim) {
        return matchesAny(signer, claim, List.of());
    }

    private static boolean matchesAny(SignerIdentity signer, ClaimResult claim,
            List<String> issuers) {
        TrustPolicy policy = new DefaultTrustPolicy(
                Map.of(COORDS.namespace(), List.of(signer)), List.of(),
                ListedEvidencePolicy.ALL, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL,
                issuers);

        RequirementEvaluator.Evaluation evaluation = policy.requirements().evaluate(COORDS, List.of(claim));

        return evaluation != null && evaluation.satisfied();
    }

    private static ClaimResult claim(List<Credential> provenCredentials) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null, provenCredentials, null,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), EVIDENCE_REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }
}
