package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EnforcementTest {

    private static TrustPolicySpec docWithDefaults(Map<ArtifactOutcome, EnforcementAction> defaults) {
        return new TrustPolicySpec(List.of(), ClaimSetMode.ALL_CLAIMS, defaults, List.of(), true);
    }

    @Test
    void aCompiledPolicyIsDeclaredOnlyWhenItsSpecIs() {
        assertThat(RulePolicy.compile(docWithDefaults(Map.of()), SignersConfig.EMPTY).declared())
                .isTrue();
        assertThat(RulePolicy.EMPTY.declared()).isFalse();
    }

    @Test
    void enforcementDefaultsWhenPolicyDeclared() {
        var p = RulePolicy.compile(docWithDefaults(Map.of()), SignersConfig.EMPTY);
        for (var o : List.of(ArtifactOutcome.FAILED, ArtifactOutcome.UNSATISFIED,
                ArtifactOutcome.NO_CLAIM, ArtifactOutcome.INDETERMINATE,
                ArtifactOutcome.NOT_CONFIGURED)) {
            assertThat(p.enforcementFor(o, null)).isEqualTo(EnforcementAction.FAIL);
        }
    }

    @Test
    void notConfiguredIgnoredInZeroConfig() {
        assertThat(RulePolicy.EMPTY.enforcementFor(ArtifactOutcome.NOT_CONFIGURED, null))
                .isEqualTo(EnforcementAction.IGNORE);
        assertThat(RulePolicy.EMPTY.enforcementFor(ArtifactOutcome.FAILED, null))
                .isEqualTo(EnforcementAction.FAIL);
    }

    @Test
    void ruleOverrideBeatsDefaultExceptFailed() {
        var mr = new MatchedRule("*", "rules[0]", Map.of(
                ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE,
                ArtifactOutcome.FAILED, EnforcementAction.IGNORE));
        var p = RulePolicy.EMPTY;
        assertThat(p.enforcementFor(ArtifactOutcome.NO_CLAIM, mr))
                .isEqualTo(EnforcementAction.IGNORE);
        assertThat(p.enforcementFor(ArtifactOutcome.FAILED, mr))
                .isEqualTo(EnforcementAction.FAIL);
    }

    @Test
    void defaultsRelaxBelowTheMatchedRule() {
        var p = RulePolicy.compile(
                docWithDefaults(Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.WARN)),
                SignersConfig.EMPTY);
        assertThat(p.enforcementFor(ArtifactOutcome.NO_CLAIM, null))
                .isEqualTo(EnforcementAction.WARN);
    }
}
