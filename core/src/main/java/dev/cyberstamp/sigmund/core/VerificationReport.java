package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * What a verification run found, grouped for reporting, and which of it blocks the build.
 *
 * <p>
 * This lives in core rather than in an integration so that every insertion point says the
 * same thing about the same evidence. A goal and a resolver-level extension that
 * disagreed about which artifacts block, or described the same outcome differently, would
 * undermine the claim that they verify alike.
 *
 * <p>
 * Presentation is left to the caller: this decides what to say and what it means, not how to
 * render it. A build tool logs at its own severities, a CLI prints, an attestation serializes.
 */
public final class VerificationReport {

    private final Map<ArtifactOutcome, List<ArtifactResult>> byOutcome;
    private final Map<ArtifactOutcome, Integer> counts;
    private final TrustPolicy policy;

    private VerificationReport(Map<ArtifactOutcome, List<ArtifactResult>> byOutcome,
            Map<ArtifactOutcome, Integer> counts, TrustPolicy policy) {
        this.byOutcome = byOutcome;
        this.counts = counts;
        this.policy = policy;
    }

    /**
     * Collects the results of a run.
     *
     * @param results one result per artifact assessed
     * @param policy the policy the run applied, which decides what blocks
     * @return the report
     */
    public static VerificationReport of(List<ArtifactResult> results, TrustPolicy policy) {
        Map<ArtifactOutcome, List<ArtifactResult>> grouped = new EnumMap<>(ArtifactOutcome.class);
        for (ArtifactResult result : results) {
            grouped.computeIfAbsent(result.outcome(), outcome -> new ArrayList<>()).add(result);
        }

        // Wrapped rather than copied with Map.copyOf: that returns an unordered map, and a
        // report whose sections appear in a different order each run is harder to read and to
        // diff. An EnumMap orders by the outcome vocabulary itself.
        Map<ArtifactOutcome, List<ArtifactResult>> byOutcome = new EnumMap<>(ArtifactOutcome.class);
        Map<ArtifactOutcome, Integer> counts = new EnumMap<>(ArtifactOutcome.class);
        grouped.forEach((outcome, group) -> {
            byOutcome.put(outcome, List.copyOf(group));
            counts.put(outcome, group.size());
        });
        return new VerificationReport(Collections.unmodifiableMap(byOutcome),
                Collections.unmodifiableMap(counts), policy);
    }

    /**
     * Returns the results grouped by outcome, in the outcome vocabulary's own order, so that
     * two runs of the same build produce reports that read and diff the same way.
     *
     * @return an unmodifiable view, omitting outcomes nothing reached
     */
    public Map<ArtifactOutcome, List<ArtifactResult>> byOutcome() {
        return byOutcome;
    }

    /**
     * Returns how many artifacts reached each outcome.
     *
     * <p>
     * Only outcomes that occurred appear. Coverage counts (§2.1) are built from these, and a
     * zero entry for an outcome nothing reached would misrepresent what the run examined.
     *
     * @return counts by outcome
     */
    public Map<ArtifactOutcome, Integer> counts() {
        return counts;
    }

    /**
     * Returns the artifacts whose outcome the policy does not tolerate.
     *
     * <p>
     * {@link ArtifactOutcome#FAILED} always blocks: a signature that does not verify is an
     * attack signal, not a coverage question, and no setting overrides it — including for an
     * artifact the policy allows to carry no signature at all. Missing evidence blocks unless
     * the policy tolerates it for that artifact, and an artifact no rule covers never blocks,
     * because policy is silent about it rather than permissive.
     *
     * @return the blocking results, in the order they were assessed
     */
    public List<ArtifactResult> blocking() {
        List<ArtifactResult> blocking = new ArrayList<>();
        byOutcome.forEach((outcome, results) -> {
            for (ArtifactResult result : results) {
                if (blocks(outcome, result)) {
                    blocking.add(result);
                }
            }
        });
        return List.copyOf(blocking);
    }

    private boolean blocks(ArtifactOutcome outcome, ArtifactResult result) {
        return switch (outcome) {
            case FAILED -> true;
            case UNSATISFIED, INDETERMINATE -> policy.onUntrusted() == UntrustedPolicy.FAIL;
            case NO_CLAIM -> policy.onUntrusted() == UntrustedPolicy.FAIL
                    && !policy.isUnsignedAllowed(result.subject().coords());
            case SATISFIED, NOT_CONFIGURED -> false;
        };
    }

    /**
     * Describes one result: why it could not be decided, where that applies, and who attested.
     *
     * @param result the result to describe
     * @return the description, empty when there is nothing to add to the outcome itself
     */
    public static String describe(ArtifactResult result) {
        StringBuilder description = new StringBuilder();
        if (result.reason() != null) {
            description.append(" [").append(result.reason()).append(']');
        }
        String attesters = result.claims().stream()
                .map(ClaimResult::attesterDisplayName)
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.joining(", "));
        if (!attesters.isEmpty()) {
            description.append(" - ").append(attesters);
        }
        return description.toString();
    }
}
