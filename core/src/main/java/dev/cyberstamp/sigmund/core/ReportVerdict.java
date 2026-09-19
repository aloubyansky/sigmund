package dev.cyberstamp.sigmund.core;

/**
 * Aggregate verdict for all signatures in a report.
 *
 * @see SignatureVerificationReport#verdict()
 */
public enum ReportVerdict {

    /** Every claim in the report is {@link ClaimOutcome#VERIFIED}. */
    ALL_PASS,

    /** At least one claim verified and none failed; the rest were indeterminate. */
    PASS_WITH_SKIPS,

    /** At least one claim verified, but at least one also failed. */
    PASS_WITH_FAILURES,

    /** No claim verified: all failed, all were indeterminate, or there were none. */
    NONE_PASSED
}
