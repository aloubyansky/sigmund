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
    void matchedRuleNamesThePatternThatMatchedNotTheFirst() {
        var rule = new Rule(
                List.of(ArtifactPattern.parse("org.apache.maven.*"),
                        ArtifactPattern.parse("org.apache.commons.*")),
                new Requirement(List.of(), List.of()), Map.of(), "rules[4]");
        var commons = new ArtifactCoords("org.apache.commons", "commons-lang3", "", "jar", "3.14.0");

        MatchedRule matched = rule.toMatchedRule(commons);

        assertThat(matched.pattern()).isEqualTo("org.apache.commons.*");
        assertThat(matched.location()).isEqualTo("rules[4]");
    }

    @Test
    void matchedRuleNamesTheMostSpecificOfSeveralMatchingPatterns() {
        var rule = new Rule(
                List.of(ArtifactPattern.parse("com.acme.*"), ArtifactPattern.parse("com.acme:lib")),
                new Requirement(List.of(), List.of()), Map.of(), "rules[0]");
        var lib = new ArtifactCoords("com.acme", "lib", "", "jar", "1.0");

        assertThat(rule.toMatchedRule(lib).pattern()).isEqualTo("com.acme:lib");
    }

    @Test
    void clauseRejectsEmpty() {
        assertThatThrownBy(() -> new Clause(List.of()))
                .isInstanceOf(PolicyConfigException.class).hasMessageContaining("clause");
    }
}
