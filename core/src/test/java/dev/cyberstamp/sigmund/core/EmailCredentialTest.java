package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class EmailCredentialTest {

    @Test
    void exactMatch() {
        var a = new EmailCredential("alice@example.com");
        var b = new EmailCredential("alice@example.com");
        assertThat(a.matches(b)).isTrue();
    }

    @Test
    void differentEmailNoMatch() {
        var a = new EmailCredential("alice@example.com");
        var b = new EmailCredential("bob@example.com");
        assertThat(a.matches(b)).isFalse();
    }

    @Test
    void caseSensitive() {
        var a = new EmailCredential("Alice@Example.com");
        var b = new EmailCredential("alice@example.com");
        assertThat(a.matches(b)).isFalse();
    }

    @Test
    void crossTypeNoMatch() {
        var email = new EmailCredential("alice@example.com");
        var fp = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
        assertThat(email.matches(fp)).isFalse();
    }

    @Test
    void typeIsEmail() {
        assertThat(new EmailCredential("a@b.com").type()).isEqualTo("email");
    }

    @Test
    void displayNameReturnsEmail() {
        assertThat(new EmailCredential("alice@example.com").displayName()).isEqualTo("alice@example.com");
    }

    @Test
    void nullEmailThrows() {
        assertThatThrownBy(() -> new EmailCredential(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankEmailThrows() {
        assertThatThrownBy(() -> new EmailCredential("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
