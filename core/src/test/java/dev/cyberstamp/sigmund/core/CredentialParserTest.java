package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class CredentialParserTest {

    private static final String FP40 = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";
    private static final String FP64 = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";
    private static final String FP16 = "AABBCCDDAABBCCDD";

    @Test
    void fromFingerprintV4() {
        var cred = CredentialParser.fromFingerprint(FP40);
        assertThat(cred.type()).isEqualTo("openpgp4");
        assertThat(cred.fingerprint()).isEqualTo(FP40);
    }

    @Test
    void fromFingerprintV6() {
        var cred = CredentialParser.fromFingerprint(FP64);
        assertThat(cred.type()).isEqualTo("openpgp6");
        assertThat(cred.fingerprint()).isEqualTo(FP64);
    }

    @Test
    void fromFingerprintNormalizesCase() {
        var cred = CredentialParser.fromFingerprint(FP40.toLowerCase());
        assertThat(cred.fingerprint()).isEqualTo(FP40);
    }

    @Test
    void fromFingerprintRejectsNonHex() {
        assertThatThrownBy(() -> CredentialParser.fromFingerprint("ZZZZ"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromFingerprintRejectsBlank() {
        assertThatThrownBy(() -> CredentialParser.fromFingerprint(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromEmail() {
        var cred = CredentialParser.fromEmail("user@example.com");
        assertThat(cred.type()).isEqualTo("email");
        assertThat(cred.email()).isEqualTo("user@example.com");
    }

    @Test
    void fromEmailRejectsBlank() {
        assertThatThrownBy(() -> CredentialParser.fromEmail(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromSigstoreWithIssuerAndSubject() {
        var cred = CredentialParser.fromSigstore("https://token.actions.githubusercontent.com",
                "https://github.com/org/repo");
        assertThat(cred.type()).isEqualTo("sigstore");
        assertThat(cred.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
        assertThat(cred.subject()).isEqualTo("https://github.com/org/repo");
    }

    @Test
    void fromSigstoreNullIssuerThrows() {
        assertThatThrownBy(() -> CredentialParser.fromSigstore(null, "subject"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromSigstoreBlankSubjectThrows() {
        assertThatThrownBy(() -> CredentialParser.fromSigstore("https://issuer", "  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseDetectsEmail() {
        var cred = CredentialParser.parse("user@example.com");
        assertThat(cred).isInstanceOf(EmailCredential.class);
    }

    @Test
    void parseDetectsFingerprint40() {
        var cred = CredentialParser.parse(FP40);
        assertThat(cred).isInstanceOf(FingerprintCredential.class);
        assertThat(cred.type()).isEqualTo("openpgp4");
    }

    @Test
    void parseDetectsFingerprint64() {
        var cred = CredentialParser.parse(FP64);
        assertThat(cred).isInstanceOf(FingerprintCredential.class);
        assertThat(cred.type()).isEqualTo("openpgp6");
    }

    @Test
    void parseDetectsFingerprint16() {
        var cred = CredentialParser.parse(FP16);
        assertThat(cred).isInstanceOf(FingerprintCredential.class);
        assertThat(cred.type()).isEqualTo("openpgp4");
    }

    @Test
    void parseRejectsNonHexNonEmail() {
        assertThatThrownBy(() -> CredentialParser.parse("not-hex-not-email"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseRejectsUnrecognizedHexLength() {
        assertThatThrownBy(() -> CredentialParser.parse("AABBCCDD"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseRejectsBlank() {
        assertThatThrownBy(() -> CredentialParser.parse(""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
