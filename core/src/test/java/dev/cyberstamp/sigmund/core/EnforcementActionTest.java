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
}
