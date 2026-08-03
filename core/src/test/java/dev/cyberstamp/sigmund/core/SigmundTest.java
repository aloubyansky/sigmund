package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigmundTest {

    @TempDir
    Path tempDir;

    @Nested
    class SignerCreation {

        @Test
        void signerReturnsAllSigningTools() throws IOException {
            var signing = mockTool("gpg", true, true, Set.of("openpgp4"));
            var verifyOnly = mockTool("sq", true, false, Set.of("openpgp6"));
            var sigmund = Sigmund.builder().addTool(signing).addTool(verifyOnly).build();

            Signer signer = sigmund.signer();
            Path artifact = createTempFile("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(1, output.files().size());
            assertEquals("gpg", output.files().get(0).toolName());
        }

        @Test
        void signerExcludesUnconfiguredTools() throws IOException {
            var bc = mockTool("bc", true, true, Set.of("openpgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("openpgp4"));
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of("bc"),
                            Map.of(), null),
                    null, null);
            var sigmund = Sigmund.builder().config(config)
                    .addTool(bc).addTool(gpg).build();

            Signer signer = sigmund.signer();
            Path artifact = createTempFile("configured-only.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(1, output.files().size());
            assertEquals("bc", output.files().get(0).toolName());
        }

        @Test
        void signerThrowsWhenConfiguredToolCannotSign() {
            var bc = mockTool("bc", true, false, Set.of("openpgp4"));
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of("bc"),
                            Map.of(), null),
                    null, null);
            var sigmund = Sigmund.builder().config(config)
                    .addTool(bc).build();

            var ex = assertThrows(SigmundException.class, sigmund::signer);
            assertTrue(ex.getMessage().contains("bc"));
            assertTrue(ex.getMessage().contains("not signing-capable"));
        }

        @Test
        void signerWithDefaultProfile() {
            var v4Tool = mockTool("gpg", true, true, Set.of("openpgp4"));
            var v6Tool = mockTool("sq", true, true, Set.of("openpgp6"));
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of(),
                            Map.of("v6-only", List.of("openpgp6")), "v6-only"),
                    null, null);
            var sigmund = Sigmund.builder().config(config)
                    .addTool(v4Tool).addTool(v6Tool).build();

            Signer signer = sigmund.signer();
            Path artifact = createTempFile("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(1, output.files().size());
            assertEquals("sq", output.files().get(0).toolName());
        }

        @Test
        void signerWithNamedProfile() {
            var v4Tool = mockTool("gpg", true, true, Set.of("openpgp4"));
            var v6Tool = mockTool("sq", true, true, Set.of("openpgp6"));
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of(),
                            Map.of("v6-only", List.of("openpgp6"),
                                    "classical", List.of("openpgp4")),
                            null),
                    null, null);
            var sigmund = Sigmund.builder().config(config)
                    .addTool(v4Tool).addTool(v6Tool).build();

            Signer v6Signer = sigmund.signer("v6-only");
            Path artifact = createTempFile("test.jar");
            SigningOutput output = v6Signer.sign(artifact, tempDir);

            assertEquals(1, output.files().size());
            assertEquals("sq", output.files().get(0).toolName());

            Signer classicalSigner = sigmund.signer("classical");
            SigningOutput classicalOutput = classicalSigner.sign(artifact, tempDir);

            assertEquals(1, classicalOutput.files().size());
            assertEquals("gpg", classicalOutput.files().get(0).toolName());
        }

        @Test
        void signerWithUnknownProfileThrows() {
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of(),
                            Map.of("v6-only", List.of("openpgp6")), null),
                    null, null);
            var sigmund = Sigmund.builder().config(config)
                    .addTool(mockTool("gpg", true, true, Set.of("openpgp4"))).build();

            var ex = assertThrows(SigmundException.class, () -> sigmund.signer("nonexistent"));
            assertTrue(ex.getMessage().contains("nonexistent"));
        }

        @Test
        void signerWithNoSigningConfigThrows() {
            var sigmund = Sigmund.builder()
                    .addTool(mockTool("gpg", true, true, Set.of("openpgp4"))).build();

            assertThrows(SigmundException.class, () -> sigmund.signer("any-profile"));
        }
    }

    @Nested
    class DirectVerification {

        @Test
        void verifyRoutesToCorrectFormatAndTool() throws IOException {
            Path artifact = createTempFile("test.jar");
            Path sigFile = createTempFile("test.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var tool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.PASS, "Alice", "RSA", 4, "KEY", "FP"));
            var sigmund = Sigmund.builder().addTool(tool).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(ReportVerdict.ALL_PASS, report.verdict());
            assertEquals(1, report.files().size());
            assertEquals("openpgp", report.files().get(0).format());
        }

        @Test
        void verifyFallsThroughOnSkipped() throws IOException {
            Path artifact = createTempFile("fallthrough.jar");
            Path sigFile = createTempFile("fallthrough.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var skippingTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null));
            var passingTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.PASS, "Alice", "RSA", 4, "KEY", "FP"));
            var sigmund = Sigmund.builder().addTool(skippingTool).addTool(passingTool).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(ReportVerdict.ALL_PASS, report.verdict());
            assertEquals(1, report.files().size());
            assertEquals(1, report.files().get(0).results().size());
            assertEquals(Verdict.PASS, report.files().get(0).results().get(0).verdict());
        }

        @Test
        void verifyFallsThroughOnNoKey() throws IOException {
            Path artifact = createTempFile("nokey.jar");
            Path sigFile = createTempFile("nokey.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var noKeyTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(Verdict.NO_KEY, null, "RSA", 4, "KEY", "FP"));
            var passingTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.PASS, "Alice", "RSA", 4, "KEY", "FP"));
            var sigmund = Sigmund.builder().addTool(noKeyTool).addTool(passingTool).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(ReportVerdict.ALL_PASS, report.verdict());
            assertEquals(Verdict.PASS, report.files().get(0).results().get(0).verdict());
            assertEquals("Alice", report.files().get(0).results().get(0).signerDisplayName());
        }

        @Test
        void verifyFallsThroughOnFail() throws IOException {
            Path artifact = createTempFile("fail.jar");
            Path sigFile = createTempFile("fail.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var failTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(Verdict.FAIL, null, "RSA", 4, "KEY", "FP"));
            var passingTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.PASS, "Alice", "RSA", 4, "KEY", "FP"));
            var sigmund = Sigmund.builder().addTool(failTool).addTool(passingTool).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(ReportVerdict.ALL_PASS, report.verdict());
            assertEquals(Verdict.PASS, report.files().get(0).results().get(0).verdict());
        }

        @Test
        void verifyKeepsBestNonPassResult() throws IOException {
            Path artifact = createTempFile("best.jar");
            Path sigFile = createTempFile("best.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var noKeyTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, "KEY", "FP"));
            var failTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.FAIL, null, "RSA", 4, "KEY", "FP"));
            var sigmund = Sigmund.builder().addTool(noKeyTool).addTool(failTool).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(Verdict.FAIL, report.files().get(0).results().get(0).verdict());
        }

        @Test
        void verifyAllToolsReturnNoKey() throws IOException {
            Path artifact = createTempFile("allnokey.jar");
            Path sigFile = createTempFile("allnokey.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var tool1 = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, "KEY", "FP"));
            var tool2 = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, "KEY", "FP"));
            var sigmund = Sigmund.builder().addTool(tool1).addTool(tool2).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(1, report.files().get(0).results().size());
            assertEquals(Verdict.NO_KEY, report.files().get(0).results().get(0).verdict());
        }

        @Test
        void verifyAllToolsSkipReturnsEmpty() throws IOException {
            Path artifact = createTempFile("allskip.jar");
            Path sigFile = createTempFile("allskip.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var tool1 = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null));
            var tool2 = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null));
            var sigmund = Sigmund.builder().addTool(tool1).addTool(tool2).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(ReportVerdict.NONE_PASSED, report.verdict());
            assertTrue(report.files().get(0).results().isEmpty());
        }

        @Test
        void verifyWithUnknownFormatReturnsEmptyResults() throws IOException {
            Path artifact = createTempFile("test.jar");
            Path sigFile = createTempFile("test.jar.unknown", "not a signature");

            var format = mockFormat("openpgp", ".asc", false, List.of());
            var tool = mockVerifyingTool("gpg", format, false, null);
            var sigmund = Sigmund.builder().addTool(tool).build();

            SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

            assertEquals(ReportVerdict.NONE_PASSED, report.verdict());
        }

        @Test
        void verifyAllAggregatesMultipleFiles() throws IOException {
            Path artifact = createTempFile("test.jar");
            Path sig1 = createTempFile("test.jar.asc", "sig1");
            Path sig2 = createTempFile("test2.jar.asc", "sig2");

            var unit = new OpenPgpVerificationUnit("armored", 4, "FP", 1);
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var tool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(Verdict.PASS, null, "RSA", 4, null, null));
            var sigmund = Sigmund.builder().addTool(tool).build();

            SignatureVerificationReport report = sigmund.verifyAll(artifact, List.of(sig1, sig2));

            assertEquals(2, report.files().size());
            assertEquals(ReportVerdict.ALL_PASS, report.verdict());
        }
    }

    @Nested
    class SignatureExtensions {

        @Test
        void signatureFileExtensionsReturnsRegisteredFormats() {
            var tool = mockTool("gpg", true, false, Set.of("openpgp4"));
            var sigmund = Sigmund.builder().addTool(tool).build();

            Set<String> extensions = sigmund.signatureFileExtensions();

            assertNotNull(extensions);
            assertTrue(extensions.contains(".asc"));
        }

        @Test
        void signatureFileExtensionsFromMultipleFormats() {
            var openpgpFormat = mockFormat("openpgp", ".asc", true, List.of());
            var sigstoreFormat = mockFormat("sigstore", ".sigstore.json", false, List.of());
            var pgpTool = mockToolWithFormat("gpg", openpgpFormat, true, false, Set.of("openpgp4"));
            var sigstoreTool = mockToolWithFormat("sigstore", sigstoreFormat, true, false, Set.of("oidc"));
            var sigmund = Sigmund.builder().addTool(pgpTool).addTool(sigstoreTool).build();

            Set<String> extensions = sigmund.signatureFileExtensions();

            assertEquals(2, extensions.size());
            assertTrue(extensions.contains(".asc"));
            assertTrue(extensions.contains(".sigstore.json"));
        }

        @Test
        void signatureFileExtensionsIsImmutable() {
            var tool = mockTool("gpg", true, false, Set.of("openpgp4"));
            var sigmund = Sigmund.builder().addTool(tool).build();

            assertThrows(UnsupportedOperationException.class,
                    () -> sigmund.signatureFileExtensions().add(".sig"));
        }
    }

    @Nested
    class ToolAccess {

        @Test
        void toolByName() {
            var gpg = mockTool("gpg", true, false, Set.of("openpgp4"));
            var sq = mockTool("sq", true, false, Set.of("openpgp6"));
            var sigmund = Sigmund.builder().addTool(gpg).addTool(sq).build();

            assertNotNull(sigmund.tool("gpg"));
            assertEquals("gpg", sigmund.tool("gpg").name());
            assertNull(sigmund.tool("sigstore"));
        }

        @Test
        void findToolByCapability() {
            var tool = new MockKeyGeneratorTool("sq");
            var sigmund = Sigmund.builder().addTool(tool)
                    .discoveryConfig(noAutoDiscovery()).build();

            assertNotNull(sigmund.findTool(KeyGenerator.class));
            assertNull(sigmund.findTool(KeyImporter.class));
        }

        @Test
        void findToolByCapabilityAndName() {
            var sq = new MockKeyGeneratorTool("sq");
            var other = new MockKeyGeneratorTool("other");
            var sigmund = Sigmund.builder().addTool(sq).addTool(other).build();

            assertNotNull(sigmund.findTool(KeyGenerator.class, "sq"));
            assertNull(sigmund.findTool(KeyGenerator.class, "nonexistent"));
        }

        @Test
        void toolsListIsUnmodifiable() {
            var sigmund = Sigmund.builder()
                    .addTool(mockTool("gpg", true, false, Set.of())).build();

            assertThrows(UnsupportedOperationException.class, () -> sigmund.tools().add(null));
        }
    }

    @Nested
    class VerifierCreation {

        @Test
        void verifierAssessTrusted() throws IOException {
            var unit = new OpenPgpVerificationUnit("armored", 4, null, 1);
            var result = new OpenPgpVerifyResult(
                    Verdict.PASS, "Alice <alice@example.com>", "RSA",
                    4, "4AEE18F83AFDEB23", "4AEE18F83AFDEB23");
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var tool = mockVerifyingTool("gpg", format, true, result);
            var sigmund = Sigmund.builder().addTool(tool).build();

            var policy = new DefaultTrustPolicy(
                    Map.of("org.example:*", List.of(new SignerIdentity("alice", "Alice",
                            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"))))),
                    List.of(), ListedEvidencePolicy.ANY, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);
            TrustVerifier verifier = sigmund.verifier(policy);

            Path artifact = createTempFile("test.jar");
            Path sigFile = createTempFile("test.jar.asc", "signature");
            ArtifactIdentity artifactId = testArtifact("org.example", "lib", "1.0");

            TrustResult trustResult = verifier.assess(artifactId, artifact, List.of(sigFile));
            assertEquals(TrustVerdict.TRUSTED, trustResult.verdict());
            assertEquals(1, trustResult.matchedEvidence().size());
        }

        @Test
        void verifierAssessUntrusted() throws IOException {
            var unit = new OpenPgpVerificationUnit("armored", 4, null, 1);
            var result = new OpenPgpVerifyResult(
                    Verdict.PASS, "Bob <bob@example.com>", "RSA",
                    4, "DIFFERENT18F83AFD", "DIFFERENT18F83AFD");
            var format = mockFormat("openpgp", ".asc", true, List.of(unit));
            var tool = mockVerifyingTool("gpg", format, true, result);
            var sigmund = Sigmund.builder().addTool(tool).build();

            var policy = new DefaultTrustPolicy(
                    Map.of("org.example:*", List.of(new SignerIdentity("alice", "Alice",
                            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"))))),
                    List.of(), ListedEvidencePolicy.ANY, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);
            TrustVerifier verifier = sigmund.verifier(policy);

            Path artifact = createTempFile("test2.jar");
            Path sigFile = createTempFile("test2.jar.asc", "signature");
            ArtifactIdentity artifactId = testArtifact("org.example", "lib", "1.0");

            TrustResult trustResult = verifier.assess(artifactId, artifact, List.of(sigFile));
            assertEquals(TrustVerdict.UNTRUSTED, trustResult.verdict());
        }

        @Test
        void verifierAssessNotConfigured() throws IOException {
            var sigmund = Sigmund.builder()
                    .addTool(mockTool("gpg", true, false, Set.of("openpgp4")))
                    .build();
            TrustVerifier verifier = sigmund.verifier(DefaultTrustPolicy.EMPTY);

            Path artifact = createTempFile("test3.jar");
            ArtifactIdentity artifactId = testArtifact("org.example", "lib", "1.0");

            TrustResult trustResult = verifier.assess(artifactId, artifact, List.of());
            assertEquals(TrustVerdict.NOT_CONFIGURED, trustResult.verdict());
        }
    }

    @Nested
    class BuilderBehavior {

        @Test
        void rejectsUnavailableExplicitTool() {
            var available = mockTool("gpg", true, false, Set.of("openpgp4"));
            var unavailable = mockTool("sq", false, false, Set.of("openpgp6"));
            var ex = assertThrows(SigmundException.class,
                    () -> Sigmund.builder().addTool(available).addTool(unavailable).build());
            assertTrue(ex.getMessage().contains("sq"));
            assertTrue(ex.getMessage().contains("not available"));
        }

        @Test
        void unknownToolInPriorityDoesNotPreventBuild() {
            var tool = mockTool("gpg", true, false, Set.of("openpgp4"));
            var discoveryConfig = new DiscoveryConfig(false, false, List.of(),
                    List.of("nonexistent", "gpg"));
            var sigmund = Sigmund.builder().addTool(tool).discoveryConfig(discoveryConfig).build();
            assertEquals(1, sigmund.tools().size());
            assertEquals("gpg", sigmund.tools().get(0).name());
        }

        @Test
        void addToolReplacesExistingByName() {
            var tool1 = mockTool("gpg", true, false, Set.of("openpgp4"));
            var tool2 = mockTool("gpg", true, true, Set.of("openpgp4"));
            var sigmund = Sigmund.builder().addTool(tool1).addTool(tool2)
                    .discoveryConfig(noAutoDiscovery()).build();

            assertEquals(1, sigmund.tools().size());
            assertTrue(sigmund.tools().get(0).canSign());
        }
    }

    @Nested
    class BuiltinFactoryDiscovery {

        @Test
        void defaultBuildDiscoversBuiltinTools() {
            // Build with default config. The builder should discover the three
            // built-in factories (bc, gpg, sq) and register at least the tools
            // that are available on this system. BC (pure Java) is always available.
            var sigmund = Sigmund.builder().build();

            assertNotNull(sigmund.tool("bc"),
                    "bc tool should always be available (pure Java)");
        }
    }

    @Nested
    class ExclusiveSignerEnforcement {

        @Test
        void exclusiveSignerRemovesOtherSigningTools() {
            var bc = mockTool("bc", true, true, Set.of("openpgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("openpgp4"));
            var builder = Sigmund.builder().discoveryConfig(noAutoDiscovery());
            builder.addTool(bc);
            builder.addTool(gpg);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            var sigmund = builder.build();
            var signers = sigmund.tools().stream()
                    .filter(SignatureTool::canSign).toList();
            assertEquals(1, signers.size());
            assertEquals("bc", signers.get(0).name());
        }

        @Test
        void exclusiveSignerKeepsVerifyOnlyTools() {
            var bc = mockTool("bc", true, true, Set.of("openpgp4"));
            var gpgVerifyOnly = mockTool("gpg", true, false, Set.of("openpgp4"));
            var builder = Sigmund.builder().discoveryConfig(noAutoDiscovery());
            builder.addTool(bc);
            builder.addTool(gpgVerifyOnly);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            var sigmund = builder.build();
            assertEquals(2, sigmund.tools().size());
            assertNotNull(sigmund.tool("gpg"));
            assertFalse(sigmund.tool("gpg").canSign());
        }

        @Test
        void noOpWhenSigningToolsExplicitlyConfigured() {
            var bc = mockTool("bc", true, true, Set.of("openpgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("openpgp4"));
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of("gpg"),
                            Map.of(), null),
                    null, null);
            var builder = Sigmund.builder().config(config).discoveryConfig(noAutoDiscovery());
            builder.addTool(bc);
            builder.addTool(gpg);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            var sigmund = builder.build();
            var signers = sigmund.tools().stream()
                    .filter(SignatureTool::canSign).toList();
            assertEquals(2, signers.size());
        }

        @Test
        void clearsSigningConfigAfterEnforcement() throws IOException {
            var bc = mockTool("bc", true, true, Set.of("openpgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("openpgp4"));
            var config = new SigmundConfig(1, null, null, null,
                    new SigningConfig(null, List.of(), Map.of(), null),
                    null, null);
            var builder = Sigmund.builder().config(config).discoveryConfig(noAutoDiscovery());
            builder.addTool(bc);
            builder.addTool(gpg);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            var sigmund = builder.build();
            Signer signer = sigmund.signer();
            Path artifact = createTempFile("exclusive.jar");
            SigningOutput output = signer.sign(artifact, tempDir);
            assertEquals(1, output.files().size());
            assertEquals("bc", output.files().get(0).toolName());
        }

        @Test
        void multipleExclusiveSignersThrows() {
            var builder = Sigmund.builder().discoveryConfig(noAutoDiscovery());
            builder.addTool(mockTool("bc", true, true, Set.of("openpgp4")));
            builder.addTool(mockTool("sq", true, true, Set.of("openpgp6")));

            var factories = List.<SignatureToolFactory> of(
                    exclusiveFactory("bc"), exclusiveFactory("sq"));
            var ex = assertThrows(SigmundException.class,
                    () -> builder.enforceExclusiveSigners(factories));
            assertTrue(ex.getMessage().contains("Multiple"));
        }

        private SignatureToolFactory exclusiveFactory(String name) {
            var tool = mockTool(name, true, true, Set.of("openpgp4"));
            return new SignatureToolFactory() {
                @Override
                public String toolName() {
                    return name;
                }

                @Override
                public Set<String> supportedCredentialTypes() {
                    return Set.of("openpgp4");
                }

                @Override
                public SignatureTool createSigning(Credential credential,
                        Map<String, String> settings) {
                    return tool;
                }

                @Override
                public SignatureTool createVerifyOnly(Map<String, String> settings) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public boolean isDefaultExclusiveSigner() {
                    return true;
                }
            };
        }
    }

    @Nested
    class AutoCloseableBehavior {

        @Test
        void closeCallsAutoCloseableTools() throws Exception {
            var closeable = new MockCloseableSignatureTool("closeable");
            var regular = mockTool("regular", true, false, Set.of("openpgp4"));
            var sigmund = Sigmund.builder()
                    .addTool(closeable)
                    .addTool(regular)
                    .build();

            sigmund.close();

            assertTrue(closeable.wasClosed());
        }

        @Test
        void closeSuppressesExceptionsFromTools() throws Exception {
            var throwingTool = new MockThrowingCloseTool("throwing");
            var normalTool = new MockCloseableSignatureTool("normal");
            var sigmund = Sigmund.builder()
                    .addTool(throwingTool)
                    .addTool(normalTool)
                    .build();

            // Should not throw
            sigmund.close();

            assertTrue(normalTool.wasClosed());
        }
    }

    @Nested
    class BuilderCleanupOnFailure {

        @Test
        void closesToolsWhenBuildFails() {
            var closeable = new MockCloseableSignatureTool("closeable");
            var builder = Sigmund.builder().discoveryConfig(noAutoDiscovery());
            builder.addTool(closeable);

            // Add a tool that will cause build() to fail. We can achieve this
            // by adding a second tool with the same format but making the builder
            // fail after tools are added. The simplest way: configure a signing
            // toolchain referencing a non-existent tool, then call signer() on
            // the result. But we need build() itself to fail.
            // Instead, add a tool whose signatureFormat().parse() is broken in a
            // way that triggers the catch in build(). Actually the simplest way
            // is to add a tool with a null signatureFormat which will cause NPE.
            var badTool = new SignatureTool() {
                @Override
                public String name() {
                    return "bad";
                }

                @Override
                public boolean isAvailable() {
                    return true;
                }

                @Override
                public boolean canSign() {
                    return false;
                }

                @Override
                public SignatureFormat signatureFormat() {
                    return null; // causes NPE in build()
                }

                @Override
                public Set<String> supportedCredentialTypes() {
                    return Set.of();
                }

                @Override
                public boolean canVerify(VerificationUnit u) {
                    return false;
                }

                @Override
                public SignResult sign(Path a, Path o) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public VerifyResult verify(Path a, VerificationUnit u) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public List<Credential> extractCredentials(VerifyResult r) {
                    return List.of();
                }
            };
            builder.addTool(badTool);

            assertThrows(RuntimeException.class, builder::build);
            assertTrue(closeable.wasClosed(),
                    "AutoCloseable tool should be closed when build() fails");
        }
    }

    @Nested
    class SignerInspectionOrchestration {

        @Test
        void inspectSignerUsesCapableTool() {
            var tool = mockInspectionTool("bc", true);
            var sigmund = Sigmund.builder().addTool(tool).build();

            var report = sigmund.inspectSigner(
                    new FingerprintCredential("openpgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"),
                    null);

            assertNotNull(report);
            assertFalse(report.results().isEmpty());
            assertTrue(report.results().stream().anyMatch(SignerSourceResult::found));
        }

        @Test
        void inspectSignerFiltersToolByName() {
            var bc = mockInspectionTool("bc", true);
            var gpg = mockInspectionTool("gpg", false);
            var sigmund = Sigmund.builder().addTool(bc).addTool(gpg).build();

            var report = sigmund.inspectSigner(
                    new FingerprintCredential("openpgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"),
                    "gpg");

            assertNotNull(report);
            assertTrue(report.results().stream().noneMatch(SignerSourceResult::found));
        }

        @Test
        void inspectSignerReturnsEmptyWhenNoCapableTool() {
            var tool = mockTool("bc", true, false, Set.of("openpgp4"));
            var sigmund = Sigmund.builder().addTool(tool).build();

            var report = sigmund.inspectSigner(
                    new FingerprintCredential("openpgp4", "AABB"), null);

            assertNotNull(report);
            assertTrue(report.results().isEmpty());
        }

        @Test
        void inspectSignerCollectsFromAllCapableTools() {
            var bc = mockInspectionTool("bc", true);
            var sq = mockInspectionTool("sq", true);
            var sigmund = Sigmund.builder().addTool(bc).addTool(sq).build();

            var report = sigmund.inspectSigner(
                    new FingerprintCredential("openpgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"),
                    null);

            assertEquals(2, report.results().size());
        }
    }

    // --- Helpers ---

    private static DiscoveryConfig noAutoDiscovery() {
        return new DiscoveryConfig(false, false, List.of(), List.of("_none_"));
    }

    private Path createTempFile(String name) {
        return createTempFile(name, "content");
    }

    private Path createTempFile(String name, String content) {
        try {
            Path file = tempDir.resolve(name);
            Files.writeString(file, content);
            return file;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static SignatureTool mockTool(String name, boolean available, boolean canSign,
            Set<String> credentialTypes) {
        var format = mockFormat("openpgp", ".asc", true, List.of());
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return available;
            }

            @Override
            public boolean canSign() {
                return canSign;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return credentialTypes;
            }

            @Override
            public boolean canVerify(VerificationUnit u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                try {
                    Files.writeString(o, "signature");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return new SignResult("RSA");
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
                return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null);
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockToolWithFormat(String name, SignatureFormat format,
            boolean available, boolean canSign, Set<String> credentialTypes) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return available;
            }

            @Override
            public boolean canSign() {
                return canSign;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return credentialTypes;
            }

            @Override
            public boolean canVerify(VerificationUnit u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
                return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null);
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockVerifyingTool(String name, SignatureFormat format,
            boolean canVerify, VerifyResult result) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return false;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("openpgp4");
            }

            @Override
            public boolean canVerify(VerificationUnit u) {
                return canVerify;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
                return result;
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                if (r instanceof OpenPgpVerifyResult opvr && opvr.fingerprint() != null) {
                    return List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, opvr.fingerprint()));
                }
                return List.of();
            }
        };
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean canHandle,
            List<VerificationUnit> units) {
        return new SignatureFormat() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public String fileExtension() {
                return ext;
            }

            @Override
            public boolean canHandleByContent(Path f) {
                return canHandle;
            }

            @Override
            public List<VerificationUnit> parse(Path f) {
                return units;
            }
        };
    }

    private static SignatureTool mockInspectionTool(String name, boolean found) {
        return new MockInspectionTool(name, found);
    }

    private static class MockInspectionTool implements SignatureTool, SignerInspection {
        private final String name;
        private final boolean found;

        MockInspectionTool(String name, boolean found) {
            this.name = name;
            this.found = found;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("openpgp4");
        }

        @Override
        public boolean canVerify(VerificationUnit u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, VerificationUnit u) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }

        @Override
        public boolean canInspect(Credential credential) {
            return credential instanceof FingerprintCredential;
        }

        @Override
        public List<SignerSourceResult> inspect(Credential credential) {
            if (!found) {
                return List.of(new SignerSourceResult("local", "mock", false, null));
            }
            var info = new SignerInspectionResult(
                    "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD",
                    4, "EdDSA", 256,
                    Instant.now(), null,
                    List.of("Mock User <mock@test.com>"), List.of());
            return List.of(new SignerSourceResult("local", "mock", true, info));
        }
    }

    private static class MockKeyGeneratorTool implements SignatureTool, KeyGenerator {
        private final String toolName;

        MockKeyGeneratorTool(String name) {
            this.toolName = name;
        }

        @Override
        public String name() {
            return toolName;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("openpgp6");
        }

        @Override
        public boolean canVerify(VerificationUnit u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, VerificationUnit u) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }

        @Override
        public String generateKey(String userId, String cipherSuite) {
            return "fingerprint";
        }
    }

    private static ArtifactIdentity testArtifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return ns;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String version() {
                return version;
            }
        };
    }

    /**
     * Mock tool that implements AutoCloseable to test close() behavior.
     */
    private static class MockCloseableSignatureTool implements SignatureTool, AutoCloseable {
        private final String toolName;
        private boolean closed;

        MockCloseableSignatureTool(String name) {
            this.toolName = name;
        }

        boolean wasClosed() {
            return closed;
        }

        @Override
        public void close() {
            this.closed = true;
        }

        @Override
        public String name() {
            return toolName;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("openpgp4");
        }

        @Override
        public boolean canVerify(VerificationUnit u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, VerificationUnit u) {
            return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null);
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }
    }

    /**
     * Mock tool that throws an exception when closed.
     */
    private static class MockThrowingCloseTool implements SignatureTool, AutoCloseable {
        private final String toolName;

        MockThrowingCloseTool(String name) {
            this.toolName = name;
        }

        @Override
        public void close() throws Exception {
            throw new Exception("Tool close failed");
        }

        @Override
        public String name() {
            return toolName;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("openpgp4");
        }

        @Override
        public boolean canVerify(VerificationUnit u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, VerificationUnit u) {
            return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null);
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }
    }
}
