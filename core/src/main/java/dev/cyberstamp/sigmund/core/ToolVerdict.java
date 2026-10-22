package dev.cyberstamp.sigmund.core;

/**
 * What a command-line verification tool established about one signature, read from its
 * output before it is turned into a {@link VerifyResult}.
 *
 * <p>
 * Tools report through exit codes and text written for people, and an exit code alone
 * conflates a signature that does not match its bytes with a key the tool will not use. Each
 * runner reads its tool's output into one of these so that only the former becomes
 * {@link ClaimOutcome#FAILED}.
 *
 * @param outcome the claim outcome
 * @param reason why it could not be decided, {@code null} unless indeterminate
 */
record ToolVerdict(ClaimOutcome outcome, IndeterminateReason reason) {

    static ToolVerdict verified() {
        return new ToolVerdict(ClaimOutcome.VERIFIED, null);
    }

    static ToolVerdict failed() {
        return new ToolVerdict(ClaimOutcome.FAILED, null);
    }

    static ToolVerdict indeterminate(IndeterminateReason reason) {
        return new ToolVerdict(ClaimOutcome.INDETERMINATE, reason);
    }
}
