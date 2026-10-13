package dev.cyberstamp.sigmund.core;

import java.util.Map;

/**
 * The policy rule that applies to a given artifact, represented by its pattern and enforcement.
 * <p>
 * When several rules match an artifact, the most specific wins. This record holds the selected
 * rule's pattern text (for error messages and audit logs), its location in the policy file
 * (for traceability), and its enforcement overrides.
 * <p>
 * The pattern text is the first pattern from the rule's pattern list (which may contain
 * several patterns that all matched the artifact).
 *
 * @param pattern the artifact pattern text that matched, from the rule's pattern list
 * @param location the rule's location in the policy file, for diagnostic messages
 * @param enforcement the enforcement action overrides for artifact outcomes
 *
 * @see Rule#toMatchedRule()
 */
public record MatchedRule(String pattern, String location,
        Map<ArtifactOutcome, EnforcementAction> enforcement) {

    /**
     * Creates a matched rule with defensive copies.
     *
     * @param pattern the artifact pattern text that matched
     * @param location the rule's location in the policy file
     * @param enforcement the enforcement action overrides
     */
    public MatchedRule {
        enforcement = enforcement == null ? Map.of() : Map.copyOf(enforcement);
    }
}
