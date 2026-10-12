package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class EnforcementActionTest {

    @Test
    void parsesAndReportsBlocking() {
        assertThat(EnforcementAction.parse("fail")).isEqualTo(EnforcementAction.FAIL);
        assertThat(EnforcementAction.parse("ignore")).isEqualTo(EnforcementAction.IGNORE);
        assertThat(EnforcementAction.FAIL.blocks()).isTrue();
        assertThat(EnforcementAction.WARN.blocks()).isFalse();
        assertThatThrownBy(() -> EnforcementAction.parse("block"))
                .isInstanceOf(PolicyConfigException.class).hasMessageContaining("block");
    }

    @Test
    void parsesWithCaseInsensitivity() {
        assertThat(EnforcementAction.parse("FAIL")).isEqualTo(EnforcementAction.FAIL);
        assertThat(EnforcementAction.parse("Warn")).isEqualTo(EnforcementAction.WARN);
        assertThat(EnforcementAction.parse("IGNORE")).isEqualTo(EnforcementAction.IGNORE);
    }

    @Test
    void parsesWithLeadingAndTrailingWhitespace() {
        assertThat(EnforcementAction.parse("  fail  ")).isEqualTo(EnforcementAction.FAIL);
        assertThat(EnforcementAction.parse("  warn  ")).isEqualTo(EnforcementAction.WARN);
        assertThat(EnforcementAction.parse("\tignore\t")).isEqualTo(EnforcementAction.IGNORE);
    }

    @Test
    void rejectsEmptyInput() {
        assertThatThrownBy(() -> EnforcementAction.parse(""))
                .isInstanceOf(PolicyConfigException.class);
        assertThatThrownBy(() -> EnforcementAction.parse("   "))
                .isInstanceOf(PolicyConfigException.class);
    }

    @Test
    void rejectsNullInput() {
        assertThatThrownBy(() -> EnforcementAction.parse(null))
                .isInstanceOf(NullPointerException.class);
    }
}
