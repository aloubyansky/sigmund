package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertTrue(a.matches(b));
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
        assertTrue(configured.matches(extracted));
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
        assertFalse(configured.matches(extracted));
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
        assertFalse(configured.matches(extracted));
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
        assertFalse(a.matches(b));
    }

    @Test
    void crossTypeNoMatch() {
        var sigstoreCred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("alice@example.com")
                .build();
        var email = new EmailCredential("alice@example.com");
        assertFalse(sigstoreCred.matches(email));
    }

    @Test
    void typeIsSigstore() {
        assertEquals("sigstore",
                new SigstoreCredential.Builder()
                        .issuer("https://issuer.example.com")
                        .build().type());
    }

    @Test
    void displayNameIncludesNonNullFields() {
        var cred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("alice@example.com")
                .build();
        String display = cred.displayName();
        assertTrue(display.contains("issuer"));
        assertTrue(display.contains("alice@example.com"));
    }

    @Test
    void noFieldsSetThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new SigstoreCredential.Builder().build());
    }

    @Test
    void blankFieldsNormalizedToNull() {
        assertThrows(IllegalArgumentException.class,
                () -> new SigstoreCredential.Builder().issuer("  ").build());
    }

    @Test
    void blankFieldAmongNonBlankIsNormalized() {
        var cred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .subject("  ")
                .build();
        assertNull(cred.subject());
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
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void notEqualsDifferentField() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://issuer1.example.com")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://issuer2.example.com")
                .build();
        assertFalse(a.equals(b));
    }

    @Test
    void gettersReturnNullForUnsetFields() {
        var cred = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .build();
        assertEquals("https://issuer.example.com", cred.issuer());
        assertNull(cred.subject());
        assertNull(cred.sourceRepositoryUri());
        assertNull(cred.sourceRepositoryOwnerUri());
        assertNull(cred.buildTrigger());
        assertNull(cred.buildConfigUri());
        assertNull(cred.runnerEnvironment());
    }

    @Test
    void matchIsCaseSensitive() {
        var a = new SigstoreCredential.Builder()
                .issuer("https://Issuer.Example.Com")
                .build();
        var b = new SigstoreCredential.Builder()
                .issuer("https://issuer.example.com")
                .build();
        assertFalse(a.matches(b));
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
        assertTrue(a.matches(b));
    }
}
