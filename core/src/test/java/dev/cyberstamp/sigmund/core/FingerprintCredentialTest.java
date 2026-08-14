package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class FingerprintCredentialTest {

    @Nested
    class Matching {

        @Test
        void exactMatch() {
            var a = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23AB01CD23");
            var b = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23AB01CD23");
            assertThat(a.matches(b)).isTrue();
            assertThat(b.matches(a)).isTrue();
        }

        @Test
        void suffixMatchShortIsSubsetOfLong() {
            var full = new FingerprintCredential("openpgp4",
                    "AB01CD23EF45678901234AEE18F83AFDEB230042");
            var shortFp = new FingerprintCredential("openpgp4",
                    "4AEE18F83AFDEB230042");
            assertThat(full.matches(shortFp)).isTrue();
            assertThat(shortFp.matches(full)).isTrue();
        }

        @Test
        void caseInsensitive() {
            var upper = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var lower = new FingerprintCredential("openpgp4", "4aee18f83afdeb23");
            assertThat(upper.matches(lower)).isTrue();
        }

        @Test
        void tooShortNoMatch() {
            var a = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var b = new FingerprintCredential("openpgp4", "3AFDEB23");
            assertThat(a.matches(b)).isFalse();
        }

        @Test
        void differentTypeNoMatch() {
            var v4 = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var v6 = new FingerprintCredential("openpgp6", "4AEE18F83AFDEB23");
            assertThat(v4.matches(v6)).isFalse();
        }

        @Test
        void differentFingerprintNoMatch() {
            var a = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var b = new FingerprintCredential("openpgp4", "AAEE18F83AFDEB23");
            assertThat(a.matches(b)).isFalse();
        }

        @Test
        void crossTypeNoMatch() {
            var fp = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var email = new EmailCredential("alice@example.com");
            assertThat(fp.matches(email)).isFalse();
        }
    }

    @Nested
    class Properties {

        @Test
        void type() {
            var cred = new FingerprintCredential("openpgp6", "ABCD1234ABCD1234");
            assertThat(cred.type()).isEqualTo("openpgp6");
        }

        @Test
        void displayNameReturnsFingerprint() {
            var cred = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            assertThat(cred.displayName()).isEqualTo("4AEE18F83AFDEB23");
        }
    }

    @Nested
    class Validation {

        @Test
        void nullTypeThrows() {
            assertThatThrownBy(() -> new FingerprintCredential(null, "4AEE18F83AFDEB23"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void blankFingerprintThrows() {
            assertThatThrownBy(() -> new FingerprintCredential("openpgp4", "  "))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
