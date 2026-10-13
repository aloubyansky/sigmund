package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The raw representation of a policy rule as parsed from YAML, before compilation.
 * <p>
 * This is the shape that the parser produces. It holds string IDs for clauses rather than
 * resolved {@link SignerIdentity} instances, so that the parser can complete before signer
 * resolution. Task 5 (the compiler) will resolve the clause IDs into {@link Clause} instances
 * and build a {@link Rule}.
 * <p>
 * The clause ID structure is a list of sets: each set is a disjunction (OR) of signer IDs,
 * and the list is a conjunction (AND) of these disjunctions, forming conjunctive normal form (CNF).
 *
 * @param patterns the artifact patterns this rule applies to
 * @param clauseIds the clause structure: list of sets of signer IDs in CNF form
 * @param enforcement enforcement action overrides for artifact outcomes
 * @param location the rule's location in the policy file, for diagnostic messages
 */
public record RuleSpec(List<ArtifactPattern> patterns, List<Set<String>> clauseIds,
        Map<ArtifactOutcome, EnforcementAction> enforcement, String location) {

    /**
     * Creates a rule spec with defensive copies.
     *
     * @param patterns the artifact patterns this rule applies to
     * @param clauseIds the clause structure in CNF form
     * @param enforcement enforcement action overrides
     * @param location the rule's location in the policy file
     */
    public RuleSpec {
        patterns = patterns == null ? List.of() : List.copyOf(patterns);
        clauseIds = clauseIds == null ? List.of() : List.copyOf(clauseIds.stream()
                .<Set<String>>map(set -> set == null ? Set.of() : Set.copyOf(set))
                .toList());
        enforcement = enforcement == null ? Map.of() : Map.copyOf(enforcement);
    }
}
