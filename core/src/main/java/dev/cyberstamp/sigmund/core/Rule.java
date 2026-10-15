package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * A compiled policy rule: artifact patterns, a requirement, and enforcement overrides.
 * <p>
 * This is the compiled form of a {@link RuleSpec}, produced by the compiler,
 * {@link RulePolicy#compile}, after resolving signer IDs into {@link SignerIdentity} instances and
 * building {@link Clause} and {@link Requirement} structures.
 * <p>
 * A rule matches an artifact if any of its patterns matches. When several rules match, the
 * most specific wins, determined by {@link #specificity(ArtifactCoords)}.
 * <p>
 * The enforcement map holds outcome-specific overrides. When an outcome is not in the map,
 * the policy's default enforcement for that outcome applies.
 *
 * @param patterns the artifact patterns this rule applies to
 * @param requirement the compiled requirement with resolved signers
 * @param enforcement enforcement action overrides for artifact outcomes
 * @param location the rule's location in the policy file, for diagnostic messages
 */
public record Rule(List<ArtifactPattern> patterns, Requirement requirement,
        Map<ArtifactOutcome, EnforcementAction> enforcement, String location) {

    /**
     * Creates a rule with defensive copies.
     *
     * @param patterns the artifact patterns
     * @param requirement the compiled requirement
     * @param enforcement enforcement overrides
     * @param location the rule's location
     */
    public Rule {
        patterns = patterns == null ? List.of() : List.copyOf(patterns);
        enforcement = enforcement == null ? Map.of() : Map.copyOf(enforcement);
    }

    /**
     * Indicates whether this rule applies to an artifact.
     * <p>
     * Returns {@code true} if any of this rule's patterns matches the artifact.
     *
     * @param coords the artifact coordinates
     * @return {@code true} if at least one pattern matches
     */
    public boolean matches(ArtifactCoords coords) {
        if (coords == null || patterns.isEmpty()) {
            return false;
        }
        for (ArtifactPattern pattern : patterns) {
            if (pattern.matches(coords)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the specificity score for this rule when applied to an artifact.
     * <p>
     * When several rules match an artifact, the most specific wins. This method returns
     * the specificity of the best (most specific) matching pattern.
     *
     * @param coords the artifact coordinates
     * @return the best matching pattern's specificity, or 0 if no pattern matches
     * @see ArtifactPattern#specificity()
     */
    public int specificity(ArtifactCoords coords) {
        ArtifactPattern best = bestPattern(coords);
        return best == null ? 0 : best.specificity();
    }

    /**
     * Converts this rule to the {@link MatchedRule} recorded on an artifact's result.
     * <p>
     * The pattern named is the one that matched the artifact — the most specific of the rule's
     * patterns that do, which is also the one that decided this rule won — rather than the first
     * one written, so that a rule listing an artifact-set reports the entry that actually applied.
     *
     * @param coords the artifact the rule matched
     * @return the matched rule naming the pattern that applied
     */
    public MatchedRule toMatchedRule(ArtifactCoords coords) {
        ArtifactPattern best = bestPattern(coords);
        String patternText = best != null ? best.toString()
                : patterns.isEmpty() ? "" : patterns.get(0).toString();
        return new MatchedRule(patternText, location, enforcement);
    }

    private ArtifactPattern bestPattern(ArtifactCoords coords) {
        if (coords == null) {
            return null;
        }
        ArtifactPattern best = null;
        for (ArtifactPattern pattern : patterns) {
            if (pattern.matches(coords)
                    && (best == null || pattern.specificity() > best.specificity())) {
                best = pattern;
            }
        }
        return best;
    }
}
