package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignersConfigTest {

    private static SignerIdentity signer(String id) {
        return new SignerIdentity(id, id, List.of(new EmailCredential(id + "@example.com")));
    }

    @Nested
    class Lookup {
        @Test
        void getReturnsSignerByName() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertThat(config.get("alice")).isNotNull();
            assertThat(config.get("alice").id()).isEqualTo("alice");
        }

        @Test
        void getReturnsNullForUnknown() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertThat(config.get("bob")).isNull();
        }

        @Test
        void resolveReturnsSignerByName() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertThat(config.resolve("alice").id()).isEqualTo("alice");
        }

        @Test
        void resolveThrowsForUnknown() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertThatThrownBy(() -> config.resolve("bob")).isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void namesReturnsAllKeys() {
            var config = new SignersConfig(Map.of("alice", signer("alice"), "bob", signer("bob")));
            assertThat(config.names().size()).isEqualTo(2);
            assertThat(config.names().contains("alice")).isTrue();
        }

        @Test
        void emptyConfig() {
            var config = SignersConfig.EMPTY;
            assertThat(config.isEmpty()).isTrue();
            assertThat(config.names().isEmpty()).isTrue();
        }
    }
}
