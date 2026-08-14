package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignatureVerificationReportTest {

    @Nested
    class OutcomeTests {

        @Test
        void allPass() {
            var report = reportWith(passResult(), passResult());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.ALL_PASS);
            assertThat(report.isPass()).isTrue();
            assertThat(report.isLenientPass()).isTrue();
        }

        @Test
        void passWithSkipped() {
            var report = reportWith(passResult(), skippedResult());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.PASS_WITH_SKIPS);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isTrue();
        }

        @Test
        void passWithNoKey() {
            var report = reportWith(passResult(), noKeyResult());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.PASS_WITH_SKIPS);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isTrue();
        }

        @Test
        void passWithFailures() {
            var report = reportWith(passResult(), failResult());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.PASS_WITH_FAILURES);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isFalse();
        }

        @Test
        void allFail() {
            var report = reportWith(failResult(), failResult());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.NONE_PASSED);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isFalse();
        }

        @Test
        void allSkipped() {
            var report = reportWith(skippedResult());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.NONE_PASSED);
        }

        @Test
        void emptyReport() {
            var report = new SignatureVerificationReport(List.of());
            assertThat(report.verdict()).isEqualTo(ReportVerdict.NONE_PASSED);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isFalse();
        }

        @Test
        void emptyFileReport() {
            var report = new SignatureVerificationReport(
                    List.of(new FileSignatureReport(Path.of("test.asc"), "openpgp", List.of())));
            assertThat(report.verdict()).isEqualTo(ReportVerdict.NONE_PASSED);
        }
    }

    @Nested
    class MultiFileTests {

        @Test
        void aggregatesAcrossFiles() {
            var file1 = new FileSignatureReport(Path.of("a.asc"), "openpgp", List.of(passResult()));
            var file2 = new FileSignatureReport(Path.of("b.asc"), "openpgp", List.of(failResult()));
            var report = new SignatureVerificationReport(List.of(file1, file2));
            assertThat(report.verdict()).isEqualTo(ReportVerdict.PASS_WITH_FAILURES);
        }

        @Test
        void filesListIsUnmodifiable() {
            var report = reportWith(passResult());
            assertThatThrownBy(() -> report.files().add(null))
                    .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Nested
    class FormatTests {

        @Test
        void formatContainsResultsAndOutcome() {
            var report = reportWith(passResult());
            String formatted = report.format();
            assertThat(formatted).contains("Signature Verification Report:");
            assertThat(formatted).contains("[1]");
            assertThat(formatted).contains("PASS");
            assertThat(formatted).contains("Overall: ALL_PASS");
        }

        @Test
        void formatIncludesAlgorithm() {
            var result = new OpenPgpVerifyResult(Verdict.PASS,
                    "Alice", "RSA", 4, "ABCD1234", "FULL_FP");
            var report = reportWith(result);
            String formatted = report.format();
            assertThat(formatted).contains("(RSA)");
        }

        @Test
        void formatIncludesKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS,
                    null, null, 4, "ABCD1234", "FULL_FP");
            var report = reportWith(result);
            String formatted = report.format();
            assertThat(formatted).contains("[key: ABCD1234]");
        }

        @Test
        void formatIncludesSignerName() {
            var result = new OpenPgpVerifyResult(Verdict.PASS,
                    "Alice <alice@example.com>", "RSA", 4, null, null);
            var report = reportWith(result);
            String formatted = report.format();
            assertThat(formatted).contains("[signer: Alice <alice@example.com>]");
        }
    }

    // --- Helpers ---

    private static SignatureVerificationReport reportWith(VerifyResult... results) {
        return new SignatureVerificationReport(
                List.of(new FileSignatureReport(Path.of("test.asc"), "openpgp", List.of(results))));
    }

    private static OpenPgpVerifyResult passResult() {
        return new OpenPgpVerifyResult(Verdict.PASS, null, "RSA", 4, null, null);
    }

    private static OpenPgpVerifyResult failResult() {
        return new OpenPgpVerifyResult(Verdict.FAIL, null, null, 4, null, null);
    }

    private static OpenPgpVerifyResult skippedResult() {
        return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null);
    }

    private static OpenPgpVerifyResult noKeyResult() {
        return new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, null, null);
    }
}
