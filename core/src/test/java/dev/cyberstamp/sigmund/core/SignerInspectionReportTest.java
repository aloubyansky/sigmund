package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

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

        assertEquals(Set.of("Alice <a@b.com>", "Bob <b@b.com>"),
                Set.copyOf(report.allUserIds()));
    }

    @Test
    void sourcesWithNoUidsFindsStrippedKeys() {
        var withUids = new SignerSourceResult("hkp", "server1", true,
                keyWithUids(List.of("Alice <a@b.com>")));
        var noUids = new SignerSourceResult("hkp", "server2", true,
                keyWithUids(List.of()));
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of(withUids, noUids));

        assertEquals(1, report.sourcesWithNoUids().size());
        assertEquals("server2", report.sourcesWithNoUids().get(0).sourceLabel());
    }

    @Test
    void sourcesWhereNotFoundFiltersCorrectly() {
        var found = new SignerSourceResult("hkp", "server1", true,
                keyWithUids(List.of()));
        var notFound = new SignerSourceResult("hkp", "server2", false, null);
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of(found, notFound));

        assertEquals(1, report.sourcesWhereNotFound().size());
        assertEquals(1, report.sourcesWithKey().size());
    }

    @Test
    void emptyReportReturnsEmptyCollections() {
        var report = new SignerInspectionReport(
                new FingerprintCredential("openpgp4", FP), List.of());
        assertTrue(report.allUserIds().isEmpty());
        assertTrue(report.sourcesWithNoUids().isEmpty());
        assertTrue(report.sourcesWhereNotFound().isEmpty());
        assertTrue(report.sourcesWithKey().isEmpty());
    }
}
