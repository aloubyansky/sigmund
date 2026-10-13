package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class RuleTest {

    @Test
    void ruleScoresByBestMatchingPattern() {
        var rule = new Rule(
                List.of(ArtifactPattern.parse("com.acme.*"), ArtifactPattern.parse("com.acme:lib")),
                new Requirement(List.of(), List.of()), Map.of(), "rules[0]");
        var c = new ArtifactCoords("com.acme", "lib", "", "jar", "1.0");
        assertThat(rule.matches(c)).isTrue();
        assertThat(rule.specificity(c)).isEqualTo(ArtifactPattern.parse("com.acme:lib").specificity());
    }

    @Test
    void clauseRejectsEmpty() {
        assertThatThrownBy(() -> new Clause(List.of()))
                .isInstanceOf(PolicyConfigException.class).hasMessageContaining("clause");
    }
}
