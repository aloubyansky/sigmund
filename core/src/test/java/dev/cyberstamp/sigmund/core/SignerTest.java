package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SignerTest {

    @TempDir
    Path tempDir;

    @Nested
    class SingleTool {

        @Test
        void producesOneSignatureFile() throws IOException {
            var format = mockFormat("openpgp", ".asc", false);
            var tool = mockSigningTool("gpg", format, "RSA");
            var signer = new Signer(List.of(tool), null);

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertThat(output.files().size()).isEqualTo(1);
            SignedFile sf = output.files().get(0);
            assertThat(sf.toolName()).isEqualTo("gpg");
            assertThat(sf.format()).isEqualTo("openpgp");
            assertThat(sf.algorithm()).isEqualTo("RSA");
            assertThat(sf.path().getFileName().toString().endsWith(".asc")).isTrue();
            assertThat(Files.exists(sf.path())).isTrue();
        }
    }

    @Nested
    class MultipleSameFormat {

        @Test
        void combinesWhenFormatSupportsCombining() throws IOException {
            var format = mockFormat("openpgp", ".asc", true);
            var gpg = mockSigningTool("gpg", format, "RSA");
            var sq = mockSigningTool("sq", format, "ML-DSA-87+Ed448");
            var signer = new Signer(List.of(gpg, sq), null);

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertThat(output.files().size()).isEqualTo(1);
            SignedFile sf = output.files().get(0);
            assertThat(sf.toolName()).isEqualTo("gpg+sq");
            assertThat(sf.algorithm()).isEqualTo("RSA+ML-DSA-87+Ed448");
            assertThat(sf.format()).isEqualTo("openpgp");
        }

        @Test
        void doesNotCombineWhenFormatDoesNotSupportCombining() throws IOException {
            var format = mockFormat("sigstore", ".sigstore.json", false);
            var tool1 = mockSigningTool("sigstore1", format, "ECDSA");
            var tool2 = mockSigningTool("sigstore2", format, "ECDSA");
            var signer = new Signer(List.of(tool1, tool2), null);

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertThat(output.files().size()).isEqualTo(2);
        }
    }

    @Nested
    class MultipleDifferentFormats {

        @Test
        void producesSeparateFilesPerFormat() throws IOException {
            var openpgpFormat = mockFormat("openpgp", ".asc", true);
            var sigstoreFormat = mockFormat("sigstore", ".sigstore.json", false);
            var gpg = mockSigningTool("gpg", openpgpFormat, "RSA");
            var sigstore = mockSigningTool("sigstore", sigstoreFormat, "ECDSA");
            var signer = new Signer(List.of(gpg, sigstore), null);

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertThat(output.files().size()).isEqualTo(2);
            var formats = output.files().stream().map(SignedFile::format).sorted().toList();
            assertThat(formats).isEqualTo(List.of("openpgp", "sigstore"));
        }
    }

    @Nested
    class Validation {

        @Test
        void rejectsEmptyToolList() {
            assertThatThrownBy(() -> new Signer(List.of(), null))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("No signing tools available");
        }
    }

    @Nested
    class SigningInfoAggregation {

        @Test
        void aggregatesInfoFromAllTools() {
            var format = mockFormat("openpgp", ".asc", true);
            var gpg = mockSigningTool("gpg", format, "RSA",
                    new SigningInfo("gpg", "AAAA", "RSA", "alice@example.com", Set.of("pgp4")));
            var sq = mockSigningTool("sq", format, "ML-DSA-87+Ed448",
                    new SigningInfo("sq", "BBBB", "ML-DSA-87+Ed448", "alice@example.com", Set.of("pgp6")));
            var signer = new Signer(List.of(gpg, sq), null);

            List<SigningInfo> infos = signer.signingInfo();

            assertThat(infos.size()).isEqualTo(2);
            assertThat(infos.get(0).toolName()).isEqualTo("gpg");
            assertThat(infos.get(0).fingerprint()).isEqualTo("AAAA");
            assertThat(infos.get(1).toolName()).isEqualTo("sq");
            assertThat(infos.get(1).fingerprint()).isEqualTo("BBBB");
        }

        @Test
        void returnsEmptyWhenToolsProvideNoInfo() {
            var format = mockFormat("openpgp", ".asc", false);
            var tool = mockSigningTool("gpg", format, "RSA");
            var signer = new Signer(List.of(tool), null);

            assertThat(signer.signingInfo().isEmpty()).isTrue();
        }
    }

    @Nested
    class FailureCleanup {

        @Test
        void cleansTempFilesWhenToolThrows() throws IOException {
            var format = mockFormat("openpgp", ".asc", false);
            var goodTool = mockSigningTool("gpg", format, "RSA");
            var failingTool = failingSigningTool("sq", format);
            var signer = new Signer(List.of(goodTool, failingTool), null);

            Path artifact = createArtifact("test.jar");

            assertThatThrownBy(() -> signer.sign(artifact, tempDir)).isInstanceOf(RuntimeException.class);

            long tempFiles = Files.list(tempDir).filter(p -> p.toString().contains("sig-")).count();
            assertThat(tempFiles).as("temp files should be cleaned up after failure").isEqualTo(0);
        }

        @Test
        void cleansTempFilesWhenCombineThrows() throws IOException {
            var format = mockFormat("openpgp", ".asc", true, true);
            var tool1 = mockSigningTool("gpg", format, "RSA");
            var tool2 = mockSigningTool("sq", format, "PQC");
            var signer = new Signer(List.of(tool1, tool2), null);

            Path artifact = createArtifact("test.jar");

            assertThatThrownBy(() -> signer.sign(artifact, tempDir)).isInstanceOf(RuntimeException.class);

            long tempFiles = Files.list(tempDir).filter(p -> p.toString().contains("sig-")).count();
            assertThat(tempFiles).as("temp files should be cleaned up after combine failure").isEqualTo(0);
        }
    }

    @Nested
    class AssertedSigner {

        private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
        private static final String OTHER_FP = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";

        private final SignatureFormat format = claimFormat();
        private final SignerBindingCheck check = new SignerBindingCheck(
                new SignerIdentity("alice", List.of(KeyCredential.openPgp(FP))),
                Map.of(), false, List.of());

        @Test
        void aPassingCheckWritesTheSignature() throws IOException {
            var signer = new Signer(List.of(provingTool("gpg", format, FP)), check);

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertThat(output.files()).hasSize(1);
            assertThat(tempDir.resolve("test.jar.asc")).hasContent("sig-gpg");
        }

        @Test
        void aFailedCheckWritesNothing() throws IOException {
            var signer = new Signer(List.of(provingTool("gpg", format, FP),
                    provingTool("sq", format, OTHER_FP)), check);

            Path artifact = createArtifact("test.jar");

            assertThatThrownBy(() -> signer.sign(artifact, tempDir))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("Signature by sq")
                    .hasMessageContaining("signer 'alice'");
            assertThat(tempDir.resolve("test.jar.asc")).doesNotExist();
            assertThat(tempFiles()).isEmpty();
        }

        @Test
        void aFailedCheckLeavesAnEarlierSignatureAlone() throws IOException {
            Path earlier = Files.writeString(tempDir.resolve("test.jar.asc"), "old");
            var signer = new Signer(List.of(provingTool("gpg", format, OTHER_FP)), check);

            Path artifact = createArtifact("test.jar");

            assertThatThrownBy(() -> signer.sign(artifact, tempDir))
                    .isInstanceOf(SigmundException.class);
            assertThat(earlier).hasContent("old");
            assertThat(tempFiles()).isEmpty();
        }

        @Test
        void withoutACheckSigningIsUnchanged() throws IOException {
            var signer = new Signer(List.of(provingTool("gpg", format, OTHER_FP)), null);

            Path artifact = createArtifact("test.jar");
            signer.sign(artifact, tempDir);

            assertThat(tempDir.resolve("test.jar.asc")).hasContent("sig-gpg");
        }

        private List<Path> tempFiles() throws IOException {
            try (Stream<Path> files = Files.list(tempDir)) {
                return files.filter(p -> p.getFileName().toString().startsWith("sig-")).toList();
            }
        }
    }

    // --- Helpers ---

    /**
     * A combinable OpenPGP-like format whose every file holds one claim.
     */
    private static SignatureFormat claimFormat() {
        SignatureFormat combining = mockFormat("openpgp", ".asc", true);
        return new SignatureFormat() {
            @Override
            public String name() {
                return combining.name();
            }

            @Override
            public String fileExtension() {
                return combining.fileExtension();
            }

            @Override
            public boolean canHandleByContent(Evidence e) {
                return true;
            }

            @Override
            public List<Claim> parse(Evidence e) {
                return List.of(new OpenPgpClaim("block", 4, null, 22, Instant.EPOCH));
            }

            @Override
            public boolean supportsCombining() {
                return true;
            }

            @Override
            public void combine(List<Path> sigs, Path output) {
                combining.combine(sigs, output);
            }
        };
    }

    /**
     * A signing tool whose signatures verify as made by the given key.
     */
    private static SignatureTool provingTool(String name, SignatureFormat format,
            String fingerprint) {
        SignatureTool signing = mockSigningTool(name, format, "EdDSA");
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
                return true;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of(Credential.TYPE_PGP4);
            }

            @Override
            public boolean canVerify(Claim u) {
                return true;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                return signing.sign(a, o);
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                return OpenPgpVerifyResult.verified(null, "EdDSA", 4, null, fingerprint);
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of(KeyCredential.openPgp(fingerprint));
            }
        };
    }

    private Path createArtifact(String name) throws IOException {
        Path file = tempDir.resolve(name);
        Files.writeString(file, "artifact content");
        return file;
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean combinable) {
        return mockFormat(name, ext, combinable, false);
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean combinable,
            boolean failCombine) {
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
            public boolean canHandleByContent(Evidence e) {
                return true;
            }

            @Override
            public List<Claim> parse(Evidence e) {
                return List.of();
            }

            @Override
            public boolean supportsCombining() {
                return combinable;
            }

            @Override
            public void combine(List<Path> sigs, Path output) {
                if (failCombine) {
                    throw new RuntimeException("combine failed");
                }
                try {
                    var sb = new StringBuilder();
                    for (Path s : sigs) {
                        sb.append(Files.readString(s));
                    }
                    Files.writeString(output, sb.toString());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    private static SignatureTool failingSigningTool(String name, SignatureFormat format) {
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
                return true;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("pgp4");
            }

            @Override
            public boolean canVerify(Claim u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new RuntimeException("signing failed");
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockSigningTool(String name, SignatureFormat format, String algorithm) {
        return mockSigningTool(name, format, algorithm, null);
    }

    private static SignatureTool mockSigningTool(String name, SignatureFormat format,
            String algorithm, SigningInfo info) {
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
                return true;
            }

            @Override
            public List<SigningInfo> signingInfo() {
                return info != null ? List.of(info) : List.of();
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("pgp4");
            }

            @Override
            public boolean canVerify(Claim u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                try {
                    Files.writeString(o, "sig-" + name);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return new SignResult(algorithm);
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }
}
