package dev.cyberstamp.sigmund.core;

/**
 * Result of querying a single source for a signer identity.
 *
 * <p>
 * Each instance represents one source's answer to the question "do you have
 * information about this signer?" — for example, a specific HKP keyserver
 * or the local GnuPG pubring.
 *
 * @param sourceType broad category of the source ({@code "local"}, {@code "hkp"},
 *        {@code "wkd"}, {@code "rekor"}, {@code "fulcio"})
 * @param sourceLabel human-readable label identifying the specific source
 *        (e.g. {@code "hkps://keys.openpgp.org"}, {@code "GnuPG pubring"},
 *        {@code "ephemeral cache"})
 * @param found {@code true} if the source contained a key matching the query
 * @param info key metadata extracted from the source, or {@code null} if
 *        the key was not found
 * @see SignerInspection
 * @see SignerInspectionReport
 */
public record SignerSourceResult(
        String sourceType,
        String sourceLabel,
        boolean found,
        SignerInspectionResult info) {
}
