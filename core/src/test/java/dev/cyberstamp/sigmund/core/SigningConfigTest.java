package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
            assertThat(SigningConfig.DEFAULT.signer()).isNull();
        }

        @Test
        void hasEmptyToolchain() {
            assertThat(SigningConfig.DEFAULT.toolchain()).isNotNull();
            assertThat(SigningConfig.DEFAULT.toolchain().isEmpty()).isTrue();
        }

        @Test
        void hasEmptyCredentialTypes() {
            assertThat(SigningConfig.DEFAULT.credentialTypes()).isNotNull();
            assertThat(SigningConfig.DEFAULT.credentialTypes().isEmpty()).isTrue();
        }

        @Test
        void hasEmptyProfiles() {
            assertThat(SigningConfig.DEFAULT.profiles()).isNotNull();
            assertThat(SigningConfig.DEFAULT.profiles().isEmpty()).isTrue();
        }
    }

    @Nested
    class NullSafety {

        @Test
        void nullToolchainBecomesEmptyList() {
            var config = new SigningConfig("alice", null, null, Map.of());
            assertThat(config.toolchain()).isNotNull();
            assertThat(config.toolchain().isEmpty()).isTrue();
        }

        @Test
        void nullCredentialTypesBecomesEmptyList() {
            var config = new SigningConfig("alice", List.of(), null, Map.of());
            assertThat(config.credentialTypes()).isNotNull();
            assertThat(config.credentialTypes().isEmpty()).isTrue();
        }

        @Test
        void nullProfilesBecomesEmptyMap() {
            var config = new SigningConfig("alice", List.of(), List.of(), null);
            assertThat(config.profiles()).isNotNull();
            assertThat(config.profiles().isEmpty()).isTrue();
        }
    }

    @Nested
    class DefensiveCopying {

        @Test
        void toolchainIsDefensivelyCopied() {
            var toolchain = new ArrayList<>(List.of("bc", "sq"));
            var config = new SigningConfig(null, toolchain, List.of(), Map.of());
            toolchain.add("gpg");
            assertThat(config.toolchain()).isEqualTo(List.of("bc", "sq"));
        }

        @Test
        void toolchainIsImmutable() {
            var config = new SigningConfig(null, List.of("bc"), List.of(), Map.of());
            assertThatThrownBy(() -> config.toolchain().add("gpg"))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        void profilesIsDefensivelyCopied() {
            var profiles = new HashMap<>(Map.of("hybrid", List.of("pgp4", "pgp6")));
            var config = new SigningConfig(null, List.of(), List.of(), profiles);
            profiles.put("extra", List.of("sigstore"));
            assertThat(config.profiles().size()).isEqualTo(1);
        }

        @Test
        void profilesIsImmutable() {
            var config = new SigningConfig(null, List.of(), List.of(),
                    Map.of("hybrid", List.of("pgp4")));
            assertThatThrownBy(() -> config.profiles().put("extra", List.of("sigstore")))
                    .isInstanceOf(UnsupportedOperationException.class);
        }
    }
}
