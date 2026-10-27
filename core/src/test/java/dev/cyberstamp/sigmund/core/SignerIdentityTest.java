package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignerIdentityTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final String A = "https://token.actions.githubusercontent.com";
    private static final String B = "https://accounts.google.com";
    private static final String C = "https://other.example.com";

    private static IdentityCredential subject(String issuer, String subject) {
        return new IdentityCredential(issuer, Map.of(IdentityCredential.SUBJECT, subject));
    }

    @Nested
    class WithIssuersResolved {

        @Test
        void anEntryNamingItsIssuerIsKept() {
            var entry = subject(B, "alice@example.com");
            var signer = new SignerIdentity("alice", List.of(entry));

            assertThat(signer.withIssuersResolved(List.of(A)).credentials()).containsExactly(entry);
        }

        @Test
        void anEntryWithoutIssuerBecomesOnePerDefaultIssuer() {
            var signer = new SignerIdentity("alice", List.of(subject(null, "X")));

            SignerIdentity resolved = signer.withIssuersResolved(List.of(A, B));

            assertThat(resolved.id()).isEqualTo("alice");
            assertThat(resolved.credentials()).containsExactly(subject(A, "X"), subject(B, "X"));
        }

        @Test
        void anEntryWithoutIssuerAndNoDefaultsResolvesToNothing() {
            var key = KeyCredential.openPgp(FP);
            var signer = new SignerIdentity("alice", List.of(subject(null, "X"), key));

            assertThat(signer.withIssuersResolved(List.of()).credentials()).containsExactly(key);
        }

        @Test
        void keysAreKept() {
            var key = KeyCredential.openPgp(FP);
            var signer = new SignerIdentity("alice",
                    List.of(key, IdentityCredential.email(null, "alice@example.com")));

            List<Credential> resolved = signer.withIssuersResolved(List.of(A)).credentials();

            assertThat(resolved.get(0)).isEqualTo(key);
            assertThat(resolved).hasSize(2);
        }

        @Test
        void theResolvedSignerAcceptsWhatTheOriginalAccepts() {
            var signer = new SignerIdentity("alice", List.of(
                    KeyCredential.openPgp(FP),
                    subject(null, "X"),
                    subject(C, "Y")));
            List<String> defaults = List.of(A, B);
            List<Credential> resolved = signer.withIssuersResolved(defaults).credentials();

            for (String issuer : List.of(A, B, C)) {
                for (String proven : List.of("X", "Y")) {
                    Credential credential = subject(issuer, proven);
                    boolean original = signer.credentials().stream()
                            .anyMatch(c -> Clause.matches(c, credential, defaults));
                    boolean afterResolving = resolved.stream()
                            .anyMatch(c -> Clause.matches(c, credential, List.of()));
                    assertThat(afterResolving).as(issuer + " " + proven).isEqualTo(original);
                }
            }
        }
    }
}
