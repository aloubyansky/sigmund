package dev.cyberstamp.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class InspectSignerMojoTest {

    @Test
    void buildCredentialFromFingerprint40Chars() {
        var mojo = new InspectSignerMojo();
        mojo.fingerprint = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";

        var credential = mojo.buildCredential();

        assertInstanceOf(
                dev.cyberstamp.sigmund.core.FingerprintCredential.class, credential);
        assertEquals("openpgp4", credential.type());
    }

    @Test
    void buildCredentialFromFingerprint64Chars() {
        var mojo = new InspectSignerMojo();
        mojo.fingerprint = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";

        var credential = mojo.buildCredential();

        assertInstanceOf(
                dev.cyberstamp.sigmund.core.FingerprintCredential.class, credential);
        assertEquals("openpgp6", credential.type());
    }

    @Test
    void buildCredentialFromEmail() {
        var mojo = new InspectSignerMojo();
        mojo.email = "user@example.com";

        var credential = mojo.buildCredential();

        assertInstanceOf(
                dev.cyberstamp.sigmund.core.EmailCredential.class, credential);
    }

    @Test
    void buildCredentialFromSigstore() {
        var mojo = new InspectSignerMojo();
        mojo.sigstoreIssuer = "https://issuer.example.com";
        mojo.sigstoreSubject = "https://github.com/org/repo";

        var credential = mojo.buildCredential();

        assertInstanceOf(
                dev.cyberstamp.sigmund.core.SigstoreCredential.class, credential);
    }

    @Test
    void buildCredentialThrowsWhenNoInput() {
        var mojo = new InspectSignerMojo();

        assertThrows(IllegalArgumentException.class, mojo::buildCredential);
    }
}
