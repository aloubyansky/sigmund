package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class VerificationConfigTest {

    @Test
    void defaultValues() {
        var config = VerificationConfig.DEFAULT;
        assertThat(config.resolveSigners()).isTrue();
        assertThat(config.importToKeyring()).isFalse();
        assertThat(config.keyservers()).isEqualTo(List.of(VerificationConfig.DEFAULT_KEYSERVER));
        assertThat(config.toolchain()).isNull();
    }

    @Test
    void effectiveToolchainFallsBackToDefault() {
        var config = VerificationConfig.DEFAULT;
        assertThat(config.effectiveToolchain()).isEqualTo(VerificationConfig.DEFAULT_TOOL_PRIORITY);
    }

    @Test
    void effectiveToolchainUsesExplicitList() {
        var config = new VerificationConfig(true, false, List.of(), List.of("bc", "sq"));
        assertThat(config.effectiveToolchain()).isEqualTo(List.of("bc", "sq"));
    }

    @Test
    void nullKeyserversFallsBackToDefault() {
        var config = new VerificationConfig(true, false, null, null);
        assertThat(config.keyservers()).isEqualTo(List.of(VerificationConfig.DEFAULT_KEYSERVER));
    }
}
