package dev.cyberstamp.sigmund.core;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

/**
 * Formats a {@link SignerInspectionReport} as human-readable text output.
 *
 * <p>
 * Results are grouped into local sources (GnuPG pubring, cert-d store,
 * ephemeral cache) and remote sources (HKP keyservers), each with per-source
 * detail sections showing key metadata.
 *
 * <p>
 * Output is delivered through a {@link java.util.function.Consumer} callback,
 * allowing callers to route output to Maven's logger, {@code System.out},
 * or any other sink.
 *
 * @see SignerInspectionReport
 */
public final class SignerInspectionReportFormatter {

    private static final String SOURCE_LOCAL = "local";
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC);

    private SignerInspectionReportFormatter() {
    }

    /**
     * Formats the given report and emits lines to the provided callbacks.
     *
     * <p>
     * Output structure:
     * <ol>
     * <li>Header with the queried credential</li>
     * <li>Local sources section (if any local results exist)</li>
     * <li>Remote sources section (if any remote results exist)</li>
     * </ol>
     *
     * @param report the inspection report to format
     * @param info callback for output lines
     */
    public static void format(SignerInspectionReport report,
            Consumer<String> info) {
        info.accept("Credential type: " + report.query().type());
        info.accept("");

        boolean hasLocal = false;
        boolean hasRemote = false;
        for (SignerSourceResult r : report.results()) {
            if (SOURCE_LOCAL.equals(r.sourceType())) {
                hasLocal = true;
            } else {
                hasRemote = true;
            }
            if (hasLocal && hasRemote) {
                break;
            }
        }

        if (hasLocal) {
            info.accept("--- Local sources ---");
            info.accept("");
            for (SignerSourceResult r : report.results()) {
                if (!SOURCE_LOCAL.equals(r.sourceType()))
                    continue;
                formatSourceResult(r, info);
            }
        }

        if (hasRemote) {
            info.accept("--- Remote sources ---");
            info.accept("");
            for (SignerSourceResult r : report.results()) {
                if (SOURCE_LOCAL.equals(r.sourceType()))
                    continue;
                formatSourceResult(r, info);
            }
        }

    }

    private static void formatSourceResult(SignerSourceResult r,
            Consumer<String> info) {
        info.accept("  " + r.sourceLabel());
        if (!r.found()) {
            info.accept("    Not found");
        } else {
            SignerInspectionResult detail = r.info();
            info.accept("    Found");
            info.accept("    Fingerprint: " + detail.fingerprint());
            info.accept("    Version:     " + detail.version());
            info.accept("    Algorithm:   " + detail.algorithm());
            if (detail.creationDate() != null) {
                info.accept("    Created:     " + DATE_FMT.format(detail.creationDate()));
            }
            if (detail.expirationDate() != null) {
                info.accept("    Expires:     " + DATE_FMT.format(detail.expirationDate()));
            } else {
                info.accept("    Expires:     (none)");
            }
            if (detail.userIds().isEmpty()) {
                info.accept("    User IDs:    (none)");
            } else {
                info.accept("    User IDs:");
                for (String uid : detail.userIds()) {
                    info.accept("      " + uid);
                }
            }
            if (!detail.subkeys().isEmpty()) {
                info.accept("    Subkeys:");
                for (SubkeyInfo sk : detail.subkeys()) {
                    var sortedCaps = sk.capabilities().stream().sorted().toList();
                    info.accept("      " + sk.fingerprint() + " "
                            + sk.algorithm() + " " + sortedCaps);
                }
            }
        }
        info.accept("");
    }

}
