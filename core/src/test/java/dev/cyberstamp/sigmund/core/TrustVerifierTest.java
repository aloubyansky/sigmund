package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TrustVerifierTest {

    private static final SignerIdentity ALICE = new SignerIdentity("alice", "Alice",
            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

    @Nested
    class VerdictAssignment {

        @Test
        void trustedWhenEvidenceMatchesExpectedSigner() {
            var policy = policyFor(ALICE, ListedEvidencePolicy.ANY);
            var provider = passingProvider("openpgp",
                    new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.TRUSTED);
            assertThat(result.matchedEvidence().size()).isEqualTo(1);
        }

        @Test
        void untrustedWhenEvidenceDoesNotMatch() {
            var policy = policyFor(ALICE, ListedEvidencePolicy.ANY);
            var provider = passingProvider("openpgp",
                    new FingerprintCredential("openpgp4", "DIFFERENT18F83AFD"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.UNTRUSTED);
        }

        @Test
        void unsignedWhenNoEvidence() {
            var policy = policyFor(ALICE, ListedEvidencePolicy.ANY);
            var verifier = new TrustVerifier(policy, List.of());

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of());

            assertThat(result.verdict()).isEqualTo(TrustVerdict.UNSIGNED);
        }

        @Test
        void notConfiguredWhenArtifactNotInPolicy() {
            var policy = emptyPolicy();
            var verifier = new TrustVerifier(policy, List.of());

            var result = verifier.assess(
                    artifact("com.unknown", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of());

            assertThat(result.verdict()).isEqualTo(TrustVerdict.NOT_CONFIGURED);
        }

        @Test
        void verificationFailedWhenEvidenceFails() {
            var policy = policyFor(ALICE, ListedEvidencePolicy.ANY);
            var provider = failingProvider();
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.VERIFICATION_FAILED);
        }
    }

    @Nested
    class RequireAllEvidenceMatch {

        @Test
        void untrustedWhenUnmatchedEvidenceAndPolicyRequiresAll() {
            var alice = ALICE;
            var policy = policyFor(alice, ListedEvidencePolicy.ALL);
            var provider = multiResultProvider(
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")),
                            "openpgp"),
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp6", "UNKNOWNFINGERPRINT")),
                            "openpgp"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.UNTRUSTED);
        }

        @Test
        void trustedWhenUnmatchedEvidenceButPolicyDoesNotRequireAll() {
            var policy = policyFor(ALICE, ListedEvidencePolicy.ANY);
            var provider = multiResultProvider(
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")),
                            "openpgp"),
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp6", "UNKNOWNFINGERPRINT")),
                            "openpgp"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.TRUSTED);
            assertThat(result.unmatchedEvidence().size()).isEqualTo(1);
        }
    }

    @Nested
    class EvidencePreservation {

        @Test
        void noKeyEvidenceIncludedInUnmatched() {
            var policy = policyFor(ALICE, ListedEvidencePolicy.ANY);
            var noKeyResult = new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4,
                    null, "DEADBEEFDEADBEEF");
            var provider = multiResultProvider(
                    new EvidenceResult(noKeyResult,
                            List.of(new FingerprintCredential("openpgp4", "DEADBEEFDEADBEEF")),
                            "openpgp"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.UNTRUSTED);
            assertThat(result.unmatchedEvidence().size()).isEqualTo(1);
            assertThat(result.unmatchedEvidence().get(0).verdict()).isEqualTo(Verdict.NO_KEY);
        }

        @Test
        void notConfiguredCarriesEvidence() {
            var provider = passingProvider("openpgp",
                    new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"));
            var verifier = new TrustVerifier(emptyPolicy(), List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertThat(result.verdict()).isEqualTo(TrustVerdict.NOT_CONFIGURED);
            assertThat(result.unmatchedEvidence().isEmpty()).isFalse();
        }
    }

    @Nested
    class BatchAssessment {

        @Test
        void assessAllReturnsOneResultPerRequest() {
            var policy = emptyPolicy();
            var verifier = new TrustVerifier(policy, List.of());

            var results = verifier.assessAll(List.of(
                    new AssessmentRequest(artifact("a", "b", "1"), Path.of("b.jar"), List.of()),
                    new AssessmentRequest(artifact("c", "d", "2"), Path.of("d.jar"), List.of())));

            assertThat(results.size()).isEqualTo(2);
        }
    }

    // --- Helpers ---

    private static ArtifactIdentity artifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            public String namespace() {
                return ns;
            }

            public String name() {
                return name;
            }

            public String version() {
                return version;
            }
        };
    }

    private static TrustPolicy policyFor(SignerIdentity signer, ListedEvidencePolicy listedEvidence) {
        return new TrustPolicy() {
            public List<SignerIdentity> expectedSigners(ArtifactIdentity a) {
                return List.of(signer);
            }

            public boolean isUnsignedAllowed(ArtifactIdentity a) {
                return false;
            }

            public ListedEvidencePolicy listedEvidence() {
                return listedEvidence;
            }

            public UnlistedEvidencePolicy unlistedEvidence() {
                return UnlistedEvidencePolicy.IGNORE;
            }

            public UntrustedPolicy onUntrusted() {
                return UntrustedPolicy.FAIL;
            }
        };
    }

    private static TrustPolicy emptyPolicy() {
        return new TrustPolicy() {
            public List<SignerIdentity> expectedSigners(ArtifactIdentity a) {
                return List.of();
            }

            public boolean isUnsignedAllowed(ArtifactIdentity a) {
                return false;
            }

            public ListedEvidencePolicy listedEvidence() {
                return ListedEvidencePolicy.ANY;
            }

            public UnlistedEvidencePolicy unlistedEvidence() {
                return UnlistedEvidencePolicy.IGNORE;
            }

            public UntrustedPolicy onUntrusted() {
                return UntrustedPolicy.FAIL;
            }
        };
    }

    private static final VerifyResult PGP_PASS = new OpenPgpVerifyResult(
            Verdict.PASS, null, null, 4, null, null);

    private static EvidenceProvider passingProvider(String mechanism, Credential... proven) {
        return new EvidenceProvider() {
            public String name() {
                return mechanism;
            }

            public boolean isAvailable() {
                return true;
            }

            public boolean canHandle(Path f) {
                return true;
            }

            public List<EvidenceResult> verify(Path a, Path e) {
                return List.of(new EvidenceResult(PGP_PASS,
                        List.of(proven), mechanism));
            }
        };
    }

    private static EvidenceProvider failingProvider() {
        return new EvidenceProvider() {
            public String name() {
                return "openpgp";
            }

            public boolean isAvailable() {
                return true;
            }

            public boolean canHandle(Path f) {
                return true;
            }

            public List<EvidenceResult> verify(Path a, Path e) {
                return List.of(new EvidenceResult(new UnverifiedResult(Verdict.FAIL), List.of(), "openpgp"));
            }
        };
    }

    private static EvidenceProvider multiResultProvider(EvidenceResult... results) {
        return new EvidenceProvider() {
            public String name() {
                return "openpgp";
            }

            public boolean isAvailable() {
                return true;
            }

            public boolean canHandle(Path f) {
                return true;
            }

            public List<EvidenceResult> verify(Path a, Path e) {
                return List.of(results);
            }
        };
    }
}
