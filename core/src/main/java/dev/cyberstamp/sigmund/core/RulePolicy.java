package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The compiled {@link TrustPolicy}: a list of {@link Rule}s over resolved signers, with the
 * enforcement and extra-claims settings the parser recorded.
 * <p>
 * A {@code RulePolicy} is produced by {@link #compile(TrustPolicySpec, SignersConfig)}, which runs
 * only when the verifier is built. Compilation is where the policy's semantic validation happens —
 * signer references are resolved, identity entries are checked against the trusted issuers, and
 * specificity ties are rejected — so "fail-fast at load" means "when the verifier loads," and the
 * signing path, which never compiles, is immune to verification-only configuration errors.
 *
 * @see TrustPolicySpec
 * @see Rule
 */
public final class RulePolicy implements TrustPolicy {

    /**
     * The zero-config policy: no rules, default extra-claims, no enforcement defaults, and no
     * issuers.
     */
    public static final RulePolicy EMPTY = compile(TrustPolicySpec.EMPTY, SignersConfig.EMPTY);

    private final List<Rule> rules;
    private final ClaimSetMode extraClaims;
    private final Map<ArtifactOutcome, EnforcementAction> defaults;
    private final List<String> issuers;

    private RulePolicy(List<Rule> rules, ClaimSetMode extraClaims,
            Map<ArtifactOutcome, EnforcementAction> defaults, List<String> issuers) {
        this.rules = List.copyOf(rules);
        this.extraClaims = extraClaims;
        this.defaults = Map.copyOf(defaults);
        this.issuers = List.copyOf(issuers);
    }

    /**
     * Compiles a {@link TrustPolicySpec} against the known signers into an enforceable policy.
     * <p>
     * For each {@link RuleSpec} the clause signer ids are resolved to {@link SignerIdentity}
     * instances and assembled into a {@link Requirement}, with the policy's issuers baked into each
     * requirement so evaluation stays pure. The identity entries of every signer are validated
     * against those issuers, and two rules that tie on specificity are rejected.
     *
     * @param doc the parsed policy spec
     * @param signers the signer registry the rules reference
     * @return the compiled policy
     * @throws PolicyConfigException if a signer reference is undefined, an identity entry cannot be
     *         satisfied by the trusted issuers, or two rules tie on specificity
     */
    public static RulePolicy compile(TrustPolicySpec doc, SignersConfig signers) {
        IdentityEntryValidator.validate(signers, doc.issuers());
        List<Rule> rules = new ArrayList<>(doc.rules().size());
        for (RuleSpec spec : doc.rules()) {
            rules.add(compileRule(spec, signers, doc.issuers()));
        }
        rejectSpecificityTies(rules);
        return new RulePolicy(rules, doc.extraClaims(), doc.defaults(), doc.issuers());
    }

    private static Rule compileRule(RuleSpec spec, SignersConfig signers, List<String> issuers) {
        List<Clause> clauses = new ArrayList<>(spec.clauseIds().size());
        for (Set<String> clauseId : spec.clauseIds()) {
            List<SignerIdentity> clauseSigners = new ArrayList<>(clauseId.size());
            for (String id : clauseId) {
                clauseSigners.add(resolve(signers, id, spec.location()));
            }
            clauses.add(new Clause(clauseSigners));
        }
        Requirement requirement = new Requirement(clauses, issuers);
        return new Rule(spec.patterns(), requirement, spec.enforcement(), spec.location());
    }

    private static SignerIdentity resolve(SignersConfig signers, String id, String location) {
        SignerIdentity signer = signers.get(id);
        if (signer == null) {
            throw new PolicyConfigException(location + " references undefined signer '" + id
                    + "'; define it under 'signers' or correct the reference");
        }
        return signer;
    }

    private static void rejectSpecificityTies(List<Rule> rules) {
        Map<ArtifactPattern, String> seen = new LinkedHashMap<>();
        for (Rule rule : rules) {
            for (ArtifactPattern pattern : rule.patterns()) {
                String prior = seen.putIfAbsent(pattern, rule.location());
                if (prior != null) {
                    throw new PolicyConfigException("Two rules tie on specificity for pattern '"
                            + pattern + "' (" + prior + " and " + rule.location()
                            + "); make one more specific or merge them");
                }
            }
        }
    }

    @Override
    public Rule matchRule(ArtifactCoords coords) {
        Rule best = null;
        int bestSpecificity = -1;
        for (Rule rule : rules) {
            if (!rule.matches(coords)) {
                continue;
            }
            int specificity = rule.specificity(coords);
            if (specificity > bestSpecificity) {
                bestSpecificity = specificity;
                best = rule;
            }
        }
        return best;
    }

    @Override
    public RequirementEvaluator requirements() {
        return (coords, verifiedClaims) -> {
            Rule rule = matchRule(coords);
            return rule == null ? null : rule.requirement().evaluate(verifiedClaims);
        };
    }

    @Override
    public ClaimSetMode claimSetMode() {
        return extraClaims;
    }

    @Override
    public List<String> issuers() {
        return issuers;
    }

    @Override
    public EnforcementAction enforcementFor(ArtifactOutcome outcome, MatchedRule matchedRule,
            boolean present) {
        if (outcome == ArtifactOutcome.FAILED) {
            return EnforcementAction.FAIL;
        }
        if (matchedRule != null) {
            EnforcementAction override = matchedRule.enforcement().get(outcome);
            if (override != null) {
                return override;
            }
        }
        EnforcementAction fromDefaults = defaults.get(outcome);
        if (fromDefaults != null) {
            return fromDefaults;
        }
        return codeDefault(outcome, present);
    }

    private static EnforcementAction codeDefault(ArtifactOutcome outcome, boolean present) {
        return switch (outcome) {
            case FAILED -> EnforcementAction.FAIL;
            case SATISFIED -> EnforcementAction.IGNORE;
            case NOT_CONFIGURED -> present ? EnforcementAction.FAIL : EnforcementAction.IGNORE;
            case UNSATISFIED, NO_CLAIM, INDETERMINATE -> EnforcementAction.FAIL;
        };
    }
}
