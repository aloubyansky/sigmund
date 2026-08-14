package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class CredentialParserTest {

    private static final String FP40 = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";
    private static final String FP64 = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";
    private static final String FP16 = "AABBCCDDAABBCCDD";

    @Test
    void fromFingerprintV4() {
        var cred = CredentialParser.fromFingerprint(FP40);
        assertEquals("openpgp4", cred.type());
        assertEquals(FP40, cred.fingerprint());
    }

    @Test
    void fromFingerprintV6() {
        var cred = CredentialParser.fromFingerprint(FP64);
        assertEquals("openpgp6", cred.type());
        assertEquals(FP64, cred.fingerprint());
    }

    @Test
    void fromFingerprintNormalizesCase() {
        var cred = CredentialParser.fromFingerprint(FP40.toLowerCase());
        assertEquals(FP40, cred.fingerprint());
    }

    @Test
    void fromFingerprintRejectsNonHex() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.fromFingerprint("ZZZZ"));
    }

    @Test
    void fromFingerprintRejectsBlank() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.fromFingerprint(""));
    }

    @Test
    void fromEmail() {
        var cred = CredentialParser.fromEmail("user@example.com");
        assertEquals("email", cred.type());
        assertEquals("user@example.com", cred.email());
    }

    @Test
    void fromEmailRejectsBlank() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.fromEmail(""));
    }

    @Test
    void fromSigstoreWithIssuerAndSubject() {
        var cred = CredentialParser.fromSigstore("https://token.actions.githubusercontent.com",
                "https://github.com/org/repo");
        assertEquals("sigstore", cred.type());
        assertEquals("https://token.actions.githubusercontent.com", cred.issuer());
        assertEquals("https://github.com/org/repo", cred.subject());
    }

    @Test
    void fromSigstoreNullIssuerThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.fromSigstore(null, "subject"));
    }

    @Test
    void fromSigstoreBlankSubjectThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.fromSigstore("https://issuer", "  "));
    }

    @Test
    void parseDetectsEmail() {
        var cred = CredentialParser.parse("user@example.com");
        assertInstanceOf(EmailCredential.class, cred);
    }

    @Test
    void parseDetectsFingerprint40() {
        var cred = CredentialParser.parse(FP40);
        assertInstanceOf(FingerprintCredential.class, cred);
        assertEquals("openpgp4", cred.type());
    }

    @Test
    void parseDetectsFingerprint64() {
        var cred = CredentialParser.parse(FP64);
        assertInstanceOf(FingerprintCredential.class, cred);
        assertEquals("openpgp6", cred.type());
    }

    @Test
    void parseDetectsFingerprint16() {
        var cred = CredentialParser.parse(FP16);
        assertInstanceOf(FingerprintCredential.class, cred);
        assertEquals("openpgp4", cred.type());
    }

    @Test
    void parseRejectsNonHexNonEmail() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.parse("not-hex-not-email"));
    }

    @Test
    void parseRejectsUnrecognizedHexLength() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.parse("AABBCCDD"));
    }

    @Test
    void parseRejectsBlank() {
        assertThrows(IllegalArgumentException.class,
                () -> CredentialParser.parse(""));
    }
}
