package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SigstoreCredentialTest {

    @Test
    void exactMatchAllFields() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0")
                .build();
        assertThat(a.matches(b)).isTrue();
    }

    @Test
    void subsetMatchConfiguredFieldsOnly() {
        var configured = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .sourceRepositoryUri("https://github.com/org/repo")
                .build();
        var extracted = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0")
                .sourceRepositoryUri("https://github.com/org/repo")
                .buildTrigger("release")
                .build();
        assertThat(configured.matches(extracted)).isTrue();
    }

    @Test
    void mismatchOnOneField() {
        var configured = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .sourceRepositoryUri("https://github.com/org/repo")
                .build();
        var extracted = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .sourceRepositoryUri("https://github.com/org/other-repo")
                .build();
        assertThat(configured.matches(extracted)).isFalse();
    }

    @Test
    void configuredFieldMissingFromExtracted() {
        var configured = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .sourceRepositoryUri("https://github.com/org/repo")
                .build();
        var extracted = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .build();
        assertThat(configured.matches(extracted)).isFalse();
    }

    @Test
    void differentIssuerNoMatch() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://issuer1.example.com")
                .subject("subject")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://issuer2.example.com")
                .subject("subject")
                .build();
        assertThat(a.matches(b)).isFalse();
    }

    @Test
    void crossTypeNoMatch() {
        var sigstoreCred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("alice@example.com")
                .build();
        var email = new EmailCredential("alice@example.com");
        assertThat(sigstoreCred.matches(email)).isFalse();
    }

    @Test
    void typeIsSigstore() {
        assertThat(new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .build().type()).isEqualTo("sigstore");
    }

    @Test
    void displayNameIncludesNonNullFields() {
        var cred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("alice@example.com")
                .build();
        String display = cred.displayName();
        assertThat(display.contains("issuer")).isTrue();
        assertThat(display.contains("alice@example.com")).isTrue();
    }

    @Test
    void noFieldsSetThrows() {
        assertThatThrownBy(() -> new SigstoreCredential.Builder().build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankFieldsNormalizedToNull() {
        assertThatThrownBy(() -> new SigstoreCredential.Builder().issuer("  ").build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankFieldAmongNonBlankIsNormalized() {
        var cred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("  ")
                .build();
        assertThat(cred.subject()).isNull();
    }

    @Test
    void equalsAndHashCode() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("alice@example.com")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("alice@example.com")
                .build();
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void notEqualsDifferentField() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://issuer1.example.com")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://issuer2.example.com")
                .build();
        assertThat(a.equals(b)).isFalse();
    }

    @Test
    void gettersReturnNullForUnsetFields() {
        var cred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .build();
        assertThat(cred.issuer()).isEqualTo("https://issuer.example.com");
        assertThat(cred.subject()).isNull();
        assertThat(cred.sourceRepositoryUri()).isNull();
        assertThat(cred.sourceRepositoryOwnerUri()).isNull();
        assertThat(cred.buildTrigger()).isNull();
        assertThat(cred.buildConfigUri()).isNull();
        assertThat(cred.runnerEnvironment()).isNull();
    }

    @Test
    void matchIsCaseSensitive() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://Issuer.Example.Com")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .build();
        assertThat(a.matches(b)).isFalse();
    }

    @Test
    void allFieldsMatch() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0")
                .sourceRepositoryUri("https://github.com/org/repo")
                .sourceRepositoryOwnerUri("https://github.com/org")
                .buildTrigger("release")
                .buildConfigUri("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main")
                .runnerEnvironment("github-hosted")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://token.actions.githubusercontent.com")
                .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0")
                .sourceRepositoryUri("https://github.com/org/repo")
                .sourceRepositoryOwnerUri("https://github.com/org")
                .buildTrigger("release")
                .buildConfigUri("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main")
                .runnerEnvironment("github-hosted")
                .build();
        assertThat(a.matches(b)).isTrue();
    }
}
