package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class KeyCredentialTest {

    static final String V4 = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    static final String V6 = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";

    @Nested
    class Construction {

        @Test
        void normalizesToUppercase() {
            var credential = new KeyCredential(Credential.TYPE_OPENPGP_V4, V4.toLowerCase());
            assertThat(credential.fingerprint()).isEqualTo(V4);
        }

        @Test
        void rejectsKeyId() {
            assertThatThrownBy(() -> new KeyCredential(Credential.TYPE_OPENPGP_V4, "4AEE18F83AFDEB23"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("full fingerprint");
        }

        @Test
        void rejectsV6LengthForV4() {
            assertThatThrownBy(() -> new KeyCredential(Credential.TYPE_OPENPGP_V4, V6))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void rejectsNonHex() {
            assertThatThrownBy(() -> new KeyCredential(Credential.TYPE_OPENPGP_V4,
                    "ZZEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void rejectsBlankType() {
            assertThatThrownBy(() -> new KeyCredential(" ", V4))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class OpenPgpFactory {

        @Test
        void infersV4FromLength() {
            assertThat(KeyCredential.openPgp(V4).type()).isEqualTo(Credential.TYPE_OPENPGP_V4);
        }

        @Test
        void infersV6FromLength() {
            assertThat(KeyCredential.openPgp(V6).type()).isEqualTo(Credential.TYPE_OPENPGP_V6);
        }

        @Test
        void rejectsKeyId() {
            assertThatThrownBy(() -> KeyCredential.openPgp("4AEE18F83AFDEB23"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("full fingerprint");
        }
    }

    @Nested
    class Matching {

        @Test
        void sameFingerprintMatches() {
            assertThat(KeyCredential.openPgp(V4).matches(KeyCredential.openPgp(V4.toLowerCase())))
                    .isTrue();
        }

        @Test
        void suffixDoesNotMatch() {
            var other = KeyCredential.openPgp("00000000000000000000000000000000" + V4.substring(32));
            assertThat(KeyCredential.openPgp(V4).matches(other)).isFalse();
        }

        @Test
        void differentTypeDoesNotMatch() {
            var v4 = new KeyCredential(Credential.TYPE_OPENPGP_V4, V4);
            var custom = new KeyCredential("x509", V4);
            assertThat(v4.matches(custom)).isFalse();
        }

        @Test
        void neverMatchesIdentity() {
            var identity = IdentityCredential.email(null, "alice@example.org");
            assertThat(KeyCredential.openPgp(V4).matches(identity)).isFalse();
        }
    }
}
