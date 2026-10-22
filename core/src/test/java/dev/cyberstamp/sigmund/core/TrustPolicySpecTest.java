package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TrustPolicySpecTest {

    @Test
    void emptyConstantHasExpectedValues() {
        assertThat(TrustPolicySpec.EMPTY.rules()).isEmpty();
        assertThat(TrustPolicySpec.EMPTY.extraClaims()).isEqualTo(ClaimSetMode.ALL_CLAIMS);
        assertThat(TrustPolicySpec.EMPTY.defaults()).isEmpty();
        assertThat(TrustPolicySpec.EMPTY.issuers()).isEmpty();
        assertThat(TrustPolicySpec.EMPTY.declared()).isFalse();
    }

    @Test
    void defensiveCopyOfRules() {
        var rules = new java.util.ArrayList<RuleSpec>();
        rules.add(new RuleSpec(List.of(), List.of(), Map.of(), "rules[0]"));
        var spec = new TrustPolicySpec(rules, ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
        rules.clear();
        assertThat(spec.rules()).hasSize(1);
    }

    @Test
    void defensiveCopyOfDefaults() {
        var defaults = new java.util.HashMap<ArtifactOutcome, EnforcementAction>();
        defaults.put(ArtifactOutcome.UNSATISFIED, EnforcementAction.FAIL);
        var spec = new TrustPolicySpec(List.of(), ClaimSetMode.ALL_CLAIMS, defaults, List.of(), true);
        defaults.clear();
        assertThat(spec.defaults()).hasSize(1);
    }

    @Test
    void defensiveCopyOfIssuers() {
        var issuers = new java.util.ArrayList<String>();
        issuers.add("issuer1");
        var spec = new TrustPolicySpec(List.of(), ClaimSetMode.ALL_CLAIMS, Map.of(), issuers, true);
        issuers.clear();
        assertThat(spec.issuers()).hasSize(1);
    }
}
