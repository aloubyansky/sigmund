package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {

    private static final String MINIMAL_CONFIG = """
            version: 1
            signers:
              alice:
                email: alice@example.com
            """;

    @Test
    void explicitPathFound(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("custom.yaml");
        Files.writeString(configFile, MINIMAL_CONFIG);

        SigmundConfig config = ConfigLoader.load(configFile);
        assertThat(config).isNotNull();
        assertThat(config.version()).isEqualTo(1);
        assertThat(config.signers().get("alice")).isNotNull();
    }

    @Test
    void explicitPathMissing(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("nonexistent.yaml");
        assertThatThrownBy(() -> ConfigLoader.load(missing))
                .isInstanceOf(PolicyConfigException.class);
    }

    @Test
    void defaultConfigValues(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("nonexistent.yaml");
        // Use locate to verify no file, then check default config shape
        assertThat(ConfigLoader.locate(null, missing)).isNull();

        SigmundConfig config = ConfigLoader.load(null, missing);
        assertThat(config).isNotNull();
        assertThat(config.version()).isEqualTo(1);
        assertThat(config.signers().isEmpty()).isTrue();
        assertThat(config.signingConfig()).isEqualTo(SigningConfig.DEFAULT);
        assertThat(config.toolsConfig().isEmpty()).isTrue();
    }

    @Test
    void locateExplicitPathFound(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("sigmund.yaml");
        Files.writeString(configFile, MINIMAL_CONFIG);

        Path located = ConfigLoader.locate(configFile);
        assertThat(located).isEqualTo(configFile);
    }

    @Test
    void locateExplicitPathMissing(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("nonexistent.yaml");
        assertThatThrownBy(() -> ConfigLoader.locate(missing))
                .isInstanceOf(PolicyConfigException.class);
    }

    @Test
    void locateFindsFileInDirectory(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("sigmund.yaml");
        Files.writeString(configFile, MINIMAL_CONFIG);

        Path located = ConfigLoader.locate(null, tempDir);
        assertThat(located).isEqualTo(configFile);
    }

    @Test
    void locateReturnsNullWhenDirHasNoConfig(@TempDir Path tempDir) {
        assertThat(ConfigLoader.locate(null, tempDir)).isNull();
    }
}
