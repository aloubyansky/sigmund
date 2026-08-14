package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class CredentialMatchingTest {

    private static final VerifyResult PGP_PASS = new OpenPgpVerifyResult(
            Verdict.PASS, null, null, 4, null, null);
    private static final VerifyResult SIGSTORE_PASS = new SigstoreVerifyResult(
            Verdict.PASS, null, null, null, null, -1);

    @Test
    void fingerprintMatchV4() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = new EvidenceResult(PGP_PASS, List.of(
                new FingerprintCredential("openpgp4",
                        "AB01CD23EF45678901234AEE18F83AFDEB23")),
                "openpgp");

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void emailMatchAcrossBackends() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new EmailCredential("alice@example.com")));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://accounts.google.com")
                        .subject("alice@example.com")
                        .build(),
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void sigstoreMatchStrictIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://token.actions.githubusercontent.com")
                        .subject("https://github.com/org/repo")
                        .build()));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://token.actions.githubusercontent.com")
                        .subject("https://github.com/org/repo")
                        .build()),
                "sigstore");

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void sigstoreMismatchWrongIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://token.actions.githubusercontent.com")
                        .subject("https://github.com/org/repo")
                        .build()));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://evil-issuer.com")
                        .subject("https://github.com/org/repo")
                        .build()),
                "sigstore");

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void noOverlapDifferentCredentialTypes() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void multipleCredentialsOneMatches() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"),
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234"),
                new EmailCredential("alice@example.com")));

        var evidence = new EvidenceResult(PGP_PASS, List.of(
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234")),
                "openpgp");

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void emptyCredentialsNoMatch() {
        var signer = new SignerIdentity("empty", "Empty", List.of());
        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    private static boolean matchesAny(SignerIdentity signer, EvidenceResult evidence) {
        for (Credential proven : evidence.provenCredentials()) {
            for (Credential expected : signer.credentials()) {
                if (expected.matches(proven)) {
                    return true;
                }
            }
        }
        return false;
    }
}
