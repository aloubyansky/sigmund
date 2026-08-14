package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SignerInspectionReportTest {

    private static final String FP = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";

    private static SignerInspectionResult keyWithUids(List<String> uids) {
        return new SignerInspectionResult(FP, 4, "EdDSA", 256,
                Instant.now(), null, uids, List.of());
    }

    @Test
    void allUserIdsDeduplicatesAcrossSources() {
        var r1 = new SignerSourceResult("hkp", "server1", true,
                keyWithUids(List.of("Alice <a@b.com>")));
        var r2 = new SignerSourceResult("hkp", "server2", true,
                keyWithUids(List.of("Alice <a@b.com>", "Bob <b@b.com>")));
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of(r1, r2));

        assertThat(Set.copyOf(report.allUserIds())).isEqualTo(Set.of("Alice <a@b.com>", "Bob <b@b.com>"));
    }

    @Test
    void sourcesWithNoUidsFindsStrippedKeys() {
        var withUids = new SignerSourceResult("hkp", "server1", true,
                keyWithUids(List.of("Alice <a@b.com>")));
        var noUids = new SignerSourceResult("hkp", "server2", true,
                keyWithUids(List.of()));
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of(withUids, noUids));

        assertThat(report.sourcesWithNoUids()).hasSize(1);
        assertThat(report.sourcesWithNoUids().get(0).sourceLabel()).isEqualTo("server2");
    }

    @Test
    void sourcesWhereNotFoundFiltersCorrectly() {
        var found = new SignerSourceResult("hkp", "server1", true,
                keyWithUids(List.of()));
        var notFound = new SignerSourceResult("hkp", "server2", false, null);
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of(found, notFound));

        assertThat(report.sourcesWhereNotFound()).hasSize(1);
        assertThat(report.sourcesWithKey()).hasSize(1);
    }

    @Test
    void emptyReportReturnsEmptyCollections() {
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of());
        assertThat(report.allUserIds()).isEmpty();
        assertThat(report.sourcesWithNoUids()).isEmpty();
        assertThat(report.sourcesWhereNotFound()).isEmpty();
        assertThat(report.sourcesWithKey()).isEmpty();
    }
}
