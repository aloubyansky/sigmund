package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyResultTest {

    @Nested
    class EvidenceResultTests {

        @Test
        void nullVerifyResultThrows() {
            assertThatThrownBy(() -> new EvidenceResult(null, List.of(), "test"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class UnverifiedResultTests {

        @Test
        void skippedVerdict() {
            var result = new UnverifiedResult(Verdict.SKIPPED);
            assertThat(result.verdict()).isEqualTo(Verdict.SKIPPED);
            assertThat(result.signerDisplayName()).isNull();
            assertThat(result.algorithm()).isNull();
            assertThat(result.signerIdentifier()).isNull();
        }

        @Test
        void failVerdict() {
            var result = new UnverifiedResult(Verdict.FAIL);
            assertThat(result.verdict()).isEqualTo(Verdict.FAIL);
        }

        @Test
        void noKeyVerdict() {
            var result = new UnverifiedResult(Verdict.NO_KEY);
            assertThat(result.verdict()).isEqualTo(Verdict.NO_KEY);
        }

        @Test
        void passVerdictThrows() {
            assertThatThrownBy(() -> new UnverifiedResult(Verdict.PASS))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class OpenPgpPreferredKeyId {

        @Test
        void prefersFingerprint() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, "SHORT", "FULL_FP");
            assertThat(result.preferredKeyId()).isEqualTo("FULL_FP");
        }

        @Test
        void fallsBackToKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, "SHORT", null);
            assertThat(result.preferredKeyId()).isEqualTo("SHORT");
        }

        @Test
        void nullWhenBothNull() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, null, null);
            assertThat(result.preferredKeyId()).isNull();
        }
    }

    @Nested
    class SignerIdentifier {

        @Test
        void openPgpReturnsPreferredKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, "SHORT", "FULL_FP");
            assertThat(result.signerIdentifier()).isEqualTo("FULL_FP");
        }

        @Test
        void openPgpFallsBackToKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 6, "SHORT", null);
            assertThat(result.signerIdentifier()).isEqualTo("SHORT");
        }

        @Test
        void sigstoreReturnsOidcSubject() {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://accounts.google.com")
                    .subject("alice@example.com")
                    .build();
            var result = new SigstoreVerifyResult(Verdict.PASS, "alice@example.com", "ECDSA",
                    sc, "12345", 1);
            assertThat(result.signerIdentifier()).isEqualTo("alice@example.com");
        }

        @Test
        void unverifiedReturnsNull() {
            var result = new UnverifiedResult(Verdict.SKIPPED);
            assertThat(result.signerIdentifier()).isNull();
        }
    }
}
