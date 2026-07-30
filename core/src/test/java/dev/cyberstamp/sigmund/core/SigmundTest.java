package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null,
                            Map.of("bc", new ToolConfig(null, Map.of())),
                            Map.of(), null),
                    ToolsConfig.DEFAULT);
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null,
                            Map.of("bc", new ToolConfig(null, Map.of())),
                            Map.of(), null),
                    ToolsConfig.DEFAULT);
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null, Map.of(),
                            Map.of("v6-only", List.of("openpgp6")), "v6-only"),
                    ToolsConfig.DEFAULT);
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null, Map.of(),
                            Map.of("v6-only", List.of("openpgp6"),
                                    "classical", List.of("openpgp4")),
                            null),
                    ToolsConfig.DEFAULT);
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null, Map.of(),
                            Map.of("v6-only", List.of("openpgp6")), null),
                    ToolsConfig.DEFAULT);
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
                    .toolsConfig(noAutoInit()).build();

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
                    List.of(), false, UntrustedPolicy.FAIL);
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
                    List.of(), false, UntrustedPolicy.FAIL);
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
            var config = new ToolsConfig(false, false, List.of(), Map.of(),
                    List.of("nonexistent", "gpg"));
            var sigmund = Sigmund.builder().addTool(tool).toolsConfig(config).build();
            assertEquals(1, sigmund.tools().size());
            assertEquals("gpg", sigmund.tools().get(0).name());
        }

        @Test
        void addToolReplacesExistingByName() {
            var tool1 = mockTool("gpg", true, false, Set.of("openpgp4"));
            var tool2 = mockTool("gpg", true, true, Set.of("openpgp4"));
            var sigmund = Sigmund.builder().addTool(tool1).addTool(tool2)
                    .toolsConfig(noAutoInit()).build();

            assertEquals(1, sigmund.tools().size());
            assertTrue(sigmund.tools().get(0).canSign());
        }
    }

    @Nested
    class ExclusiveSignerEnforcement {

        @Test
        void exclusiveSignerRemovesOtherSigningTools() {
            var bc = mockTool("bc", true, true, Set.of("openpgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("openpgp4"));
            var builder = Sigmund.builder().toolsConfig(noAutoInit());
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
            var builder = Sigmund.builder().toolsConfig(noAutoInit());
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null,
                            Map.of("gpg", new ToolConfig(null, Map.of())),
                            Map.of(), null),
                    ToolsConfig.DEFAULT);
            var builder = Sigmund.builder().config(config).toolsConfig(noAutoInit());
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
            var config = new SigmundConfig(1, Map.of(), Map.of(), null,
                    new SigningConfig(null, Map.of(), Map.of(), null),
                    ToolsConfig.DEFAULT);
            var builder = Sigmund.builder().config(config).toolsConfig(noAutoInit());
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
            var builder = Sigmund.builder().toolsConfig(noAutoInit());
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
                public SignatureTool create(Credential credential,
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

    // --- Helpers ---

    private static ToolsConfig noAutoInit() {
        return new ToolsConfig(false, false, List.of(), Map.of(), List.of("_none_"));
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
            public boolean canHandle(Path f) {
                return canHandle;
            }

            @Override
            public List<VerificationUnit> parse(Path f) {
                return units;
            }
        };
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
}
