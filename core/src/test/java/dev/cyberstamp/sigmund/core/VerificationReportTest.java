package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerificationReportTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final SignerIdentity ALICE = new SignerIdentity("alice", "Alice",
            List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP)));

    private static ArtifactResult result(String name, ArtifactOutcome outcome,
            IndeterminateReason reason, ClaimResult... claims) {
        ArtifactCoords coords = new ArtifactCoords("org.example", name, "", "jar", "1.0");
        ArtifactSubject subject = new ArtifactSubject(coords, DigestSet.sha256(FP.toLowerCase()));
        return new ArtifactResult(subject, outcome, reason, List.of(claims), Instant.EPOCH);
    }

    private static ClaimResult claim(String attester) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null, List.of(), attester,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(),
                new EvidenceRef(Path.of("lib.jar.asc"), DigestSet.sha256(FP.toLowerCase()),
                        Evidence.SOURCE_SIDECAR),
                null, ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static TrustPolicy policy(UntrustedPolicy onUntrusted, List<String> unsigned) {
        return new DefaultTrustPolicy(Map.of("org.example", List.of(ALICE)), unsigned,
                ListedEvidencePolicy.ALL, UnlistedEvidencePolicy.IGNORE, onUntrusted);
    }

    @Nested
    class Grouping {

        @Test
        void groupsByOutcomeAndCounts() {
            VerificationReport report = VerificationReport.of(List.of(
                    result("a", ArtifactOutcome.SATISFIED, null),
                    result("b", ArtifactOutcome.SATISFIED, null),
                    result("c", ArtifactOutcome.NO_CLAIM, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThat(report.counts()).containsEntry(ArtifactOutcome.SATISFIED, 2)
                    .containsEntry(ArtifactOutcome.NO_CLAIM, 1);
            assertThat(report.byOutcome().get(ArtifactOutcome.SATISFIED)).hasSize(2);
        }

        @Test
        void groupsAreOrderedByTheOutcomeVocabulary() {
            VerificationReport report = VerificationReport.of(List.of(
                    result("a", ArtifactOutcome.NO_CLAIM, null),
                    result("b", ArtifactOutcome.FAILED, null),
                    result("c", ArtifactOutcome.SATISFIED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            // reports read the same way every run: the order is the enum's, not the order
            // artifacts happened to be resolved in
            assertThat(report.byOutcome().keySet()).containsExactly(
                    ArtifactOutcome.SATISFIED, ArtifactOutcome.FAILED, ArtifactOutcome.NO_CLAIM);
        }

        @Test
        void theGroupingCannotBeModifiedByCallers() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.SATISFIED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThatThrownBy(() -> report.byOutcome().clear())
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(
                    () -> report.byOutcome().get(ArtifactOutcome.SATISFIED).clear())
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        void countsOnlyWhatWasSeen() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.SATISFIED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThat(report.counts()).doesNotContainKey(ArtifactOutcome.FAILED);
        }
    }

    @Nested
    class Describing {

        @Test
        void namesTheAttestersOfTheClaimsFound() {
            String line = VerificationReport.describe(
                    result("a", ArtifactOutcome.SATISFIED, null, claim("Alice")));

            assertThat(line).contains("Alice");
        }

        @Test
        void statesTheReasonWhenOneApplies() {
            String line = VerificationReport.describe(result("a", ArtifactOutcome.INDETERMINATE,
                    IndeterminateReason.KEY_UNAVAILABLE));

            assertThat(line).contains("KEY_UNAVAILABLE");
        }
    }

    @Nested
    class TheFailureDecision {

        @Test
        void aFailedSignatureAlwaysBlocks() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.FAILED, null)),
                    policy(UntrustedPolicy.WARN, List.of()));

            assertThat(report.blocking()).hasSize(1);
        }

        @Test
        void anUnsatisfiedArtifactBlocksWhenPolicySaysSo() {
            List<ArtifactResult> results = List.of(result("a", ArtifactOutcome.UNSATISFIED, null));

            assertThat(VerificationReport.of(results, policy(UntrustedPolicy.FAIL, List.of()))
                    .blocking()).hasSize(1);
            assertThat(VerificationReport.of(results, policy(UntrustedPolicy.WARN, List.of()))
                    .blocking()).isEmpty();
        }

        @Test
        void missingEvidenceBlocksUnlessPolicyToleratesIt() {
            List<ArtifactResult> results = List.of(result("a", ArtifactOutcome.NO_CLAIM, null));

            assertThat(VerificationReport.of(results, policy(UntrustedPolicy.FAIL, List.of()))
                    .blocking()).hasSize(1);
            assertThat(VerificationReport
                    .of(results, policy(UntrustedPolicy.FAIL, List.of("org.example:a")))
                    .blocking()).isEmpty();
        }

        @Test
        void anArtifactNoRuleCoversDoesNotBlock() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.NOT_CONFIGURED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThat(report.blocking()).isEmpty();
        }

        @Test
        void aToleratedArtifactStillBlocksOnABrokenSignature() {
            // the point of verifying rather than skipping: policy tolerates missing evidence,
            // not evidence that fails
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.FAILED, null)),
                    policy(UntrustedPolicy.FAIL, List.of("org.example:a")));

            assertThat(report.blocking()).hasSize(1);
        }
    }
}
