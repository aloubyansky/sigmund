package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ResolveToolsConfigTest {

    private final TestMojo mojo = new TestMojo();

    private DiscoveryConfig resolve(DiscoveryConfig fileConfig,
            Boolean resolveSigners, String keyservers, Boolean importToKeyring) {
        return mojo.resolveDiscoveryConfig(fileConfig, resolveSigners, keyservers, importToKeyring);
    }

    @Nested
    class ResolveSigners {

        @Test
        void defaultsToFileConfig() {
            var fileConfig = new DiscoveryConfig(false, false, List.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertThat(result.resolveSigners()).isFalse();
        }

        @Test
        void defaultsToTrueFromDefaultConfig() {
            var result = resolve(DiscoveryConfig.DEFAULT, null, null, null);
            assertThat(result.resolveSigners()).isTrue();
        }

        @Test
        void explicitTrueOverridesFileConfig() {
            var fileConfig = new DiscoveryConfig(false, false, List.of(), null);
            var result = resolve(fileConfig, true, null, null);
            assertThat(result.resolveSigners()).isTrue();
        }

        @Test
        void explicitFalseOverridesFileConfig() {
            var result = resolve(DiscoveryConfig.DEFAULT, false, null, null);
            assertThat(result.resolveSigners()).isFalse();
        }

        @Test
        void impliedTrueWhenKeyserversProvided() {
            var fileConfig = new DiscoveryConfig(false, false, List.of(), null);
            var result = resolve(fileConfig, null, "hkps://keys.openpgp.org", null);
            assertThat(result.resolveSigners()).isTrue();
        }

        @Test
        void explicitFalseOverridesKeyserversImplication() {
            var fileConfig = new DiscoveryConfig(false, false, List.of(), null);
            var result = resolve(fileConfig, false, "hkps://keys.openpgp.org", null);
            assertThat(result.resolveSigners()).isFalse();
        }
    }

    @Nested
    class Keyservers {

        @Test
        void defaultsToFileConfig() {
            var fileConfig = new DiscoveryConfig(true, false,
                    List.of("hkps://custom.example.com"), null);
            var result = resolve(fileConfig, null, null, null);
            assertThat(result.keyservers()).isEqualTo(List.of("hkps://custom.example.com"));
        }

        @Test
        void explicitKeyserversOverrideFileConfig() {
            var result = resolve(DiscoveryConfig.DEFAULT, null,
                    "hkps://keyserver.ubuntu.com,hkps://pgp.mit.edu", null);
            assertThat(result.keyservers()).isEqualTo(
                    List.of("hkps://keyserver.ubuntu.com", "hkps://pgp.mit.edu"));
        }

        @Test
        void defaultKeyserverUsedWhenResolveEnabledAndEmpty() {
            var fileConfig = new DiscoveryConfig(true, false, List.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertThat(result.keyservers()).isEqualTo(List.of(DiscoveryConfig.DEFAULT_KEYSERVER));
        }

        @Test
        void defaultKeyserverAlwaysPresentEvenWhenResolveFalse() {
            var fileConfig = new DiscoveryConfig(false, false, List.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertThat(result.resolveSigners()).isFalse();
            assertThat(result.keyservers()).isEqualTo(List.of(DiscoveryConfig.DEFAULT_KEYSERVER));
        }

        @Test
        void parsesCommaSeparatedList() {
            var result = resolve(DiscoveryConfig.DEFAULT, null,
                    "hkps://a.example.com, hkps://b.example.com , hkps://c.example.com", null);
            assertThat(result.keyservers()).isEqualTo(
                    List.of("hkps://a.example.com", "hkps://b.example.com",
                            "hkps://c.example.com"));
        }
    }

    @Nested
    class SingularKeyserverAlias {

        @Test
        void singularPropertyUsedWhenPluralNotSet() {
            String old = System.getProperty("sigmund.keyserver");
            try {
                System.setProperty("sigmund.keyserver", "hkps://keyserver.ubuntu.com");
                var result = resolve(DiscoveryConfig.DEFAULT, null, null, null);
                assertThat(result.keyservers()).isEqualTo(List.of("hkps://keyserver.ubuntu.com"));
                assertThat(result.resolveSigners()).isTrue();
            } finally {
                if (old != null) {
                    System.setProperty("sigmund.keyserver", old);
                } else {
                    System.clearProperty("sigmund.keyserver");
                }
            }
        }

        @Test
        void pluralPropertyTakesPrecedenceOverSingular() {
            String old = System.getProperty("sigmund.keyserver");
            try {
                System.setProperty("sigmund.keyserver", "hkps://keyserver.ubuntu.com");
                var result = resolve(DiscoveryConfig.DEFAULT, null,
                        "hkps://keys.openpgp.org", null);
                assertThat(result.keyservers()).isEqualTo(List.of("hkps://keys.openpgp.org"));
            } finally {
                if (old != null) {
                    System.setProperty("sigmund.keyserver", old);
                } else {
                    System.clearProperty("sigmund.keyserver");
                }
            }
        }

        @Test
        void singularPropertyIgnoredWhenNotSet() {
            String old = System.getProperty("sigmund.keyserver");
            try {
                System.clearProperty("sigmund.keyserver");
                var result = resolve(DiscoveryConfig.DEFAULT, null, null, null);
                assertThat(result.keyservers()).isEqualTo(
                        List.of(DiscoveryConfig.DEFAULT_KEYSERVER));
            } finally {
                if (old != null) {
                    System.setProperty("sigmund.keyserver", old);
                }
            }
        }
    }

    private static class TestMojo extends AbstractSigmundMojo {
        @Override
        public void execute() {
        }
    }
}
