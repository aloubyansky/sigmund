package dev.cyberstamp.sigmund.core;

/**
 * Specifies how policy violations are handled: fail, warn, or ignore.
 * <p>
 * Used in policy rules to determine whether a verification failure should:
 * <ul>
 * <li>{@link #FAIL} — block the operation, return a negative verification result</li>
 * <li>{@link #WARN} — log a warning but allow the operation to continue</li>
 * <li>{@link #IGNORE} — silently skip the check</li>
 * </ul>
 *
 * @see #blocks()
 * @see #parse(String)
 */
public enum EnforcementAction {
    /**
     * Policy violation blocks verification; the operation fails.
     */
    FAIL,

    /**
     * Policy violation is logged as a warning; the operation continues.
     */
    WARN,

    /**
     * Policy violation is ignored.
     */
    IGNORE;

    /**
     * Parses a string into an {@code EnforcementAction}, case-insensitively.
     * <p>
     * Accepts "fail", "warn", or "ignore" (with leading/trailing whitespace trimmed).
     *
     * @param value the string to parse
     * @return the matching {@code EnforcementAction}
     * @throws PolicyConfigException if the value is not recognized
     * @throws NullPointerException if value is null
     */
    public static EnforcementAction parse(String value) {
        String normalized = value.trim().toLowerCase();
        return switch (normalized) {
            case "fail" -> FAIL;
            case "warn" -> WARN;
            case "ignore" -> IGNORE;
            default -> throw new PolicyConfigException(
                    "Unknown enforcement action: " + normalized + ". Valid values: fail, warn, ignore");
        };
    }

    /**
     * Returns {@code true} if this action blocks verification (is {@link #FAIL}).
     * <p>
     * Used by verification logic to determine whether a failed check should
     * prevent the operation from proceeding.
     *
     * @return {@code true} if this is {@link #FAIL}; {@code false} otherwise
     */
    public boolean blocks() {
        return this == FAIL;
    }
}
