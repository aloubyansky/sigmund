package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class InspectSignerMojoTest {

    @Test
    void buildCredentialFromFingerprint40Chars() {
        var mojo = new InspectSignerMojo();
        mojo.fingerprint = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";

        var credential = mojo.buildCredential();

        assertThat(credential).isInstanceOf(
                dev.cyberstamp.sigmund.core.FingerprintCredential.class);
        assertThat(credential.type()).isEqualTo("openpgp4");
    }

    @Test
    void buildCredentialFromFingerprint64Chars() {
        var mojo = new InspectSignerMojo();
        mojo.fingerprint = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";

        var credential = mojo.buildCredential();

        assertThat(credential).isInstanceOf(
                dev.cyberstamp.sigmund.core.FingerprintCredential.class);
        assertThat(credential.type()).isEqualTo("openpgp6");
    }

    @Test
    void buildCredentialFromEmail() {
        var mojo = new InspectSignerMojo();
        mojo.email = "user@example.com";

        var credential = mojo.buildCredential();

        assertThat(credential).isInstanceOf(
                dev.cyberstamp.sigmund.core.EmailCredential.class);
    }

    @Test
    void buildCredentialFromSigstore() {
        var mojo = new InspectSignerMojo();
        mojo.sigstoreIssuer = "https://issuer.example.com";
        mojo.sigstoreSubject = "https://github.com/org/repo";

        var credential = mojo.buildCredential();

        assertThat(credential).isInstanceOf(
                dev.cyberstamp.sigmund.core.SigstoreCredential.class);
    }

    @Test
    void buildCredentialThrowsWhenNoInput() {
        var mojo = new InspectSignerMojo();

        assertThatThrownBy(mojo::buildCredential)
                .isInstanceOf(IllegalArgumentException.class);
    }
}
