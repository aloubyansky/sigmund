package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * The raw representation of a trust policy as parsed from YAML, before compilation.
 * <p>
 * This is the shape that the parser produces. It holds {@link RuleSpec} instances rather than
 * compiled {@link Rule} instances, so that the parser can complete before signer resolution.
 * The compiler, {@link RulePolicy#compile}, resolves signers and builds compiled {@link Rule}
 * instances.
 * <p>
 * The {@link #present()} flag indicates whether a trust policy section was present in the YAML,
 * so that the absence of policy can be distinguished from an empty policy.
 *
 * @param rules the policy rules in their raw parsed form
 * @param extraClaims how to handle verified claims that no requirement accepted
 * @param defaults default enforcement actions for artifact outcomes
 * @param issuers the list of trusted issuers (certificate authorities)
 * @param present whether a trust policy section was present in the YAML
 */
public record TrustPolicySpec(List<RuleSpec> rules, ClaimSetMode extraClaims,
        Map<ArtifactOutcome, EnforcementAction> defaults, List<String> issuers, boolean present) {

    /**
     * The empty trust policy spec, used when no policy section is present.
     * <p>
     * Has no rules, default claim set mode, no defaults, no issuers, and {@code present = false}.
     */
    public static final TrustPolicySpec EMPTY =
            new TrustPolicySpec(List.of(), ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), false);

    /**
     * Creates a trust policy spec with defensive copies.
     *
     * @param rules the policy rules
     * @param extraClaims how to handle extra claims
     * @param defaults default enforcement actions
     * @param issuers trusted issuers
     * @param present whether policy was present in YAML
     */
    public TrustPolicySpec {
        rules = rules == null ? List.of() : List.copyOf(rules);
        defaults = defaults == null ? Map.of() : Map.copyOf(defaults);
        issuers = issuers == null ? List.of() : List.copyOf(issuers);
    }
}
