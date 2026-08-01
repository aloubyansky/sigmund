package dev.cyberstamp.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ResolveToolsConfigTest {

    private final TestMojo mojo = new TestMojo();

    private ToolsConfig resolve(ToolsConfig fileConfig,
            Boolean resolveSigners, String keyservers, Boolean importToKeyring) {
        return mojo.resolveToolsConfig(fileConfig, resolveSigners, keyservers, importToKeyring);
    }

    @Nested
    class ResolveSigners {

        @Test
        void defaultsToFileConfig() {
            var fileConfig = new ToolsConfig(false, false, List.of(), Map.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertFalse(result.resolveSigners());
        }

        @Test
        void defaultsToTrueFromDefaultConfig() {
            var result = resolve(ToolsConfig.DEFAULT, null, null, null);
            assertTrue(result.resolveSigners());
        }

        @Test
        void explicitTrueOverridesFileConfig() {
            var fileConfig = new ToolsConfig(false, false, List.of(), Map.of(), null);
            var result = resolve(fileConfig, true, null, null);
            assertTrue(result.resolveSigners());
        }

        @Test
        void explicitFalseOverridesFileConfig() {
            var result = resolve(ToolsConfig.DEFAULT, false, null, null);
            assertFalse(result.resolveSigners());
        }

        @Test
        void impliedTrueWhenKeyserversProvided() {
            var fileConfig = new ToolsConfig(false, false, List.of(), Map.of(), null);
            var result = resolve(fileConfig, null, "hkps://keys.openpgp.org", null);
            assertTrue(result.resolveSigners());
        }

        @Test
        void explicitFalseOverridesKeyserversImplication() {
            var fileConfig = new ToolsConfig(false, false, List.of(), Map.of(), null);
            var result = resolve(fileConfig, false, "hkps://keys.openpgp.org", null);
            assertFalse(result.resolveSigners());
        }
    }

    @Nested
    class Keyservers {

        @Test
        void defaultsToFileConfig() {
            var fileConfig = new ToolsConfig(true, false,
                    List.of("hkps://custom.example.com"), Map.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertEquals(List.of("hkps://custom.example.com"), result.keyservers());
        }

        @Test
        void explicitKeyserversOverrideFileConfig() {
            var result = resolve(ToolsConfig.DEFAULT, null,
                    "hkps://keyserver.ubuntu.com,hkps://pgp.mit.edu", null);
            assertEquals(List.of("hkps://keyserver.ubuntu.com", "hkps://pgp.mit.edu"),
                    result.keyservers());
        }

        @Test
        void defaultKeyserverUsedWhenResolveEnabledAndEmpty() {
            var fileConfig = new ToolsConfig(true, false, List.of(), Map.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertEquals(List.of(ToolsConfig.DEFAULT_KEYSERVER), result.keyservers());
        }

        @Test
        void defaultKeyserverAlwaysPresentEvenWhenResolveFalse() {
            var fileConfig = new ToolsConfig(false, false, List.of(), Map.of(), null);
            var result = resolve(fileConfig, null, null, null);
            assertFalse(result.resolveSigners());
            assertEquals(List.of(ToolsConfig.DEFAULT_KEYSERVER), result.keyservers());
        }

        @Test
        void parsesCommaSeparatedList() {
            var result = resolve(ToolsConfig.DEFAULT, null,
                    "hkps://a.example.com, hkps://b.example.com , hkps://c.example.com", null);
            assertEquals(List.of("hkps://a.example.com", "hkps://b.example.com",
                    "hkps://c.example.com"), result.keyservers());
        }
    }

    @Nested
    class SingularKeyserverAlias {

        @Test
        void singularPropertyUsedWhenPluralNotSet() {
            String old = System.getProperty("sigmund.keyserver");
            try {
                System.setProperty("sigmund.keyserver", "hkps://keyserver.ubuntu.com");
                var result = resolve(ToolsConfig.DEFAULT, null, null, null);
                assertEquals(List.of("hkps://keyserver.ubuntu.com"), result.keyservers());
                assertTrue(result.resolveSigners());
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
                var result = resolve(ToolsConfig.DEFAULT, null,
                        "hkps://keys.openpgp.org", null);
                assertEquals(List.of("hkps://keys.openpgp.org"), result.keyservers());
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
                var result = resolve(ToolsConfig.DEFAULT, null, null, null);
                assertEquals(List.of(ToolsConfig.DEFAULT_KEYSERVER), result.keyservers());
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
