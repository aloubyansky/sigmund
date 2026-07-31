package dev.cyberstamp.sigmund.core;

import java.util.LinkedHashSet;
import java.util.List;

/**
 * Aggregated result of inspecting a signer identity across all queried sources.
 *
 * <p>
 * Collects per-source {@link SignerSourceResult}s and provides convenience methods
 * for summarizing them — which sources found the key, which returned User IDs,
 * and which did not.
 *
 * @param query the credential that was inspected
 * @param results per-source results in the order they were queried; defensive-copied
 * @see Sigmund#inspectSigner(Credential, String)
 * @see SignerInspectionReportFormatter
 */
public record SignerInspectionReport(
        Credential query,
        List<SignerSourceResult> results) {

    public SignerInspectionReport {
        results = results != null ? List.copyOf(results) : List.of();
    }

    /**
     * Returns all User IDs discovered across every source, deduplicated and in
     * encounter order.
     *
     * @return deduplicated User IDs; empty if no source returned any
     */
    public List<String> allUserIds() {
        var seen = new LinkedHashSet<String>();
        for (SignerSourceResult r : results) {
            if (r.found() && r.info() != null) {
                seen.addAll(r.info().userIds());
            }
        }
        return List.copyOf(seen);
    }

    /**
     * Returns sources that found the key but returned no User IDs.
     *
     * <p>
     * This typically indicates that a keyserver (e.g. {@code keys.openpgp.org})
     * strips UIDs unless the email owner has verified them.
     *
     * @return sources with a found key but empty User ID list
     */
    public List<SignerSourceResult> sourcesWithNoUids() {
        return results.stream()
                .filter(r -> r.found() && r.info() != null && r.info().userIds().isEmpty())
                .toList();
    }

    /**
     * Returns sources that did not contain the queried key.
     *
     * @return sources where the key was not found
     */
    public List<SignerSourceResult> sourcesWhereNotFound() {
        return results.stream()
                .filter(r -> !r.found())
                .toList();
    }

    /**
     * Returns sources that found a key matching the query.
     *
     * @return sources where the key was found
     */
    public List<SignerSourceResult> sourcesWithKey() {
        return results.stream()
                .filter(SignerSourceResult::found)
                .toList();
    }
}
