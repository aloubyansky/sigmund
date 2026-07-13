package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SigningConfig} record behavior including defaults,
 * null safety, and defensive copying.
 */
class SigningConfigTest {

    @Nested
    class DefaultConstant {

        @Test
        void hasNullSigner() {
            assertNull(SigningConfig.DEFAULT.signer());
        }

        @Test
        void hasEmptyToolchain() {
            assertNotNull(SigningConfig.DEFAULT.toolchain());
            assertTrue(SigningConfig.DEFAULT.toolchain().isEmpty());
        }

        @Test
        void hasEmptyProfiles() {
            assertNotNull(SigningConfig.DEFAULT.profiles());
            assertTrue(SigningConfig.DEFAULT.profiles().isEmpty());
        }

        @Test
        void hasNullDefaultProfile() {
            assertNull(SigningConfig.DEFAULT.defaultProfile());
        }
    }

    @Nested
    class NullSafety {

        @Test
        void nullToolchainBecomesEmptyList() {
            var config = new SigningConfig("alice", null, Map.of(), null);
            assertNotNull(config.toolchain());
            assertTrue(config.toolchain().isEmpty());
        }

        @Test
        void nullProfilesBecomesEmptyMap() {
            var config = new SigningConfig("alice", List.of(), null, null);
            assertNotNull(config.profiles());
            assertTrue(config.profiles().isEmpty());
        }
    }

    @Nested
    class DefensiveCopying {

        @Test
        void toolchainIsDefensivelyCopied() {
            var toolchain = new ArrayList<>(List.of("bc", "sq"));
            var config = new SigningConfig(null, toolchain, Map.of(), null);
            toolchain.add("gpg");
            assertEquals(List.of("bc", "sq"), config.toolchain());
        }

        @Test
        void toolchainIsImmutable() {
            var config = new SigningConfig(null, List.of("bc"), Map.of(), null);
            assertThrows(UnsupportedOperationException.class,
                    () -> config.toolchain().add("gpg"));
        }

        @Test
        void profilesIsDefensivelyCopied() {
            var profiles = new HashMap<>(Map.of("hybrid", List.of("openpgp4", "openpgp6")));
            var config = new SigningConfig(null, List.of(), profiles, null);
            profiles.put("extra", List.of("sigstore"));
            assertEquals(1, config.profiles().size());
        }

        @Test
        void profilesIsImmutable() {
            var config = new SigningConfig(null, List.of(),
                    Map.of("hybrid", List.of("openpgp4")), null);
            assertThrows(UnsupportedOperationException.class,
                    () -> config.profiles().put("extra", List.of("sigstore")));
        }
    }
}
