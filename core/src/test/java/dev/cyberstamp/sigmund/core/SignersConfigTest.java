package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

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
            assertNotNull(config.get("alice"));
            assertEquals("alice", config.get("alice").id());
        }

        @Test
        void getReturnsNullForUnknown() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertNull(config.get("bob"));
        }

        @Test
        void resolveReturnsSignerByName() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertEquals("alice", config.resolve("alice").id());
        }

        @Test
        void resolveThrowsForUnknown() {
            var config = new SignersConfig(Map.of("alice", signer("alice")));
            assertThrows(PolicyConfigException.class, () -> config.resolve("bob"));
        }

        @Test
        void namesReturnsAllKeys() {
            var config = new SignersConfig(Map.of("alice", signer("alice"), "bob", signer("bob")));
            assertEquals(2, config.names().size());
            assertTrue(config.names().contains("alice"));
        }

        @Test
        void emptyConfig() {
            var config = SignersConfig.EMPTY;
            assertTrue(config.isEmpty());
            assertTrue(config.names().isEmpty());
        }
    }
}
