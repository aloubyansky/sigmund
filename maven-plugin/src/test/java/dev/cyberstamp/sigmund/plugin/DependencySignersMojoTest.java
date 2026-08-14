package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.OpenPgpVerifyResult;
import dev.cyberstamp.sigmund.core.UnverifiedResult;
import dev.cyberstamp.sigmund.core.Verdict;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.cyberstamp.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DependencySignersMojoTest {

    @Test
    void signedArtifactV4WithSigner() {
        VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                "User <user@example.com>", "RSA", 4, "ABCD1234", "ABCD1234");
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", "central", vr, null, null);
        assertThat(signer.coordinates()).isEqualTo("com.example:lib:1.0");
        assertThat(signer.repoId()).isEqualTo("central");
        assertThat(signer.verifyResult()).isInstanceOf(OpenPgpVerifyResult.class);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertThat(opvr.version()).isEqualTo(4);
        assertThat(opvr.preferredKeyId()).isEqualTo("ABCD1234");
        assertThat(opvr.signerDisplayName()).isEqualTo("User <user@example.com>");
    }

    @Test
    void signedArtifactV6Detected() {
        VerifyResult vr = new OpenPgpVerifyResult(Verdict.SKIPPED,
                null, null, 6, null, null);
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", "central", vr, null, null);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertThat(opvr.version()).isEqualTo(6);
        assertThat(opvr.preferredKeyId()).isNull();
        assertThat(signer.verdict()).isEqualTo(Verdict.SKIPPED);
    }

    @Test
    void signedArtifactNoSignature() {
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", null, Verdict.SKIPPED);
        assertThat(signer.repoId()).isNull();
        assertThat(signer.verifyResult()).isInstanceOf(UnverifiedResult.class);
        assertThat(signer.verdict()).isEqualTo(Verdict.SKIPPED);
    }

    // --- ArtifactCoords.toString tests ---

    @Test
    void artifactCoordsSimpleJar() {
        ArtifactCoords coords = createArtifact("com.example", "lib", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:1.0");
    }

    @Test
    void artifactCoordsWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "sources", "jar", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:jar:sources:1.0");
    }

    @Test
    void artifactCoordsNonJarType() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "", "pom", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:pom:1.0");
    }

    @Test
    void artifactCoordsNonJarTypeWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "dist", "zip", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:zip:dist:1.0");
    }

    @Nested
    class GenerateSignerIdTests {

        private final DependencySignersMojo mojo = new DependencySignersMojo();

        @Test
        void normalUidProducesKebabCaseId() {
            assertThat(mojo.generateSignerId("John Smith <john@example.com>", 1))
                    .isEqualTo("john-smith");
        }

        @Test
        void uidWithoutEmailBrackets() {
            assertThat(mojo.generateSignerId("Jane Doe", 1)).isEqualTo("jane-doe");
        }

        @Test
        void emptyNameFallsBackToCounter() {
            assertThat(mojo.generateSignerId(" <user@example.com>", 1)).isEqualTo("signer-1");
        }

        @Test
        void specialCharsOnlyFallsBackToCounter() {
            assertThat(mojo.generateSignerId("... <user@example.com>", 2)).isEqualTo("signer-2");
        }

        @Test
        void nullUidFallsBackToCounter() {
            assertThat(mojo.generateSignerId(null, 3)).isEqualTo("signer-3");
        }

        @Test
        void collisionProducesUniqueSuffix() {
            VerifyResult vr1 = new OpenPgpVerifyResult(Verdict.PASS,
                    "John Smith <john@a.com>", "RSA", 4, "KEY1", "KEY1");
            VerifyResult vr2 = new OpenPgpVerifyResult(Verdict.PASS,
                    "John Smith <john@b.com>", "RSA", 4, "KEY2", "KEY2");

            Map<String, DependencySignersMojo.SignerInfo> existingSigners = new LinkedHashMap<>();
            var info1 = new DependencySignersMojo.SignerInfo(
                    mojo.resolveUniqueSignerId(vr1, 1, existingSigners, Set.of()), vr1);
            existingSigners.put("KEY1", info1);

            String id2 = mojo.resolveUniqueSignerId(vr2, 2, existingSigners, Set.of());
            assertThat(info1.id).isEqualTo("john-smith");
            assertThat(id2).isEqualTo("john-smith-2");
        }

        @Test
        void collisionWithReservedIds() {
            VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                    "Alice <alice@example.com>", "RSA", 4, "KEY1", "KEY1");
            String id = mojo.resolveUniqueSignerId(vr, 1, new LinkedHashMap<>(), Set.of("alice"));
            assertThat(id).isEqualTo("alice-2");
        }
    }

    @Nested
    class SignerInfoTests {

        @Test
        void v4KeyClassifiedAsPgp4() {
            VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                    "User <user@example.com>", "RSA", 4, null, "FP4");
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertThat(info.pgp4Key).isEqualTo("FP4");
            assertThat(info.pgp6Key).isNull();
        }

        @Test
        void v6KeyClassifiedAsPgp6() {
            VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                    "User <user@example.com>", "ML-DSA-87+Ed448", 6, null, "FP6");
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertThat(info.pgp4Key).isNull();
            assertThat(info.pgp6Key).isEqualTo("FP6");
        }

        @Test
        void mergeAccumulatesBothKeys() {
            VerifyResult vr4 = new OpenPgpVerifyResult(Verdict.PASS,
                    "User <user@example.com>", "RSA", 4, null, "FP4");
            VerifyResult vr6 = new OpenPgpVerifyResult(Verdict.PASS,
                    null, "ML-DSA-87+Ed448", 6, null, "FP6");
            var info = new DependencySignersMojo.SignerInfo("test", vr4);
            info.merge(vr6);
            assertThat(info.pgp4Key).isEqualTo("FP4");
            assertThat(info.pgp6Key).isEqualTo("FP6");
            assertThat(info.email).isEqualTo("user@example.com");
        }
    }

    @Nested
    class SignedArtifactEdgeCases {

        @Test
        void unverifiedWithPassThrows() {
            assertThatThrownBy(() -> new SignedArtifact("coords", null, Verdict.PASS))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void unverifiedWithFail() {
            var sa = new SignedArtifact("coords", "repo", Verdict.FAIL);
            assertThat(sa.verdict()).isEqualTo(Verdict.FAIL);
            assertThat(sa.verifyResult()).isInstanceOf(dev.cyberstamp.sigmund.core.UnverifiedResult.class);
        }
    }

    private ArtifactCoords createArtifact(String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, "", "jar", version);
    }
}
