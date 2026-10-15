package dev.cyberstamp.sigmund.core;

import java.util.Map;

/**
 * The policy rule that applies to a given artifact, represented by its pattern and enforcement.
 * <p>
 * When several rules match an artifact, the most specific wins. This record holds the pattern
 * of the selected rule that matched the artifact (for reports and audit logs), the rule's
 * location in the policy file (for traceability), and its enforcement overrides.
 * <p>
 * Where several of the rule's patterns match — an artifact-set expands to many — the pattern
 * named is the most specific of them, the one that decided the rule won. The artifact-set a
 * pattern came from is not recorded: the location already points at the line naming it.
 *
 * @param pattern the artifact pattern text that matched, from the rule's pattern list
 * @param location the rule's location in the policy file, for diagnostic messages
 * @param enforcement the enforcement action overrides for artifact outcomes
 *
 * @see Rule#toMatchedRule(ArtifactCoords)
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
