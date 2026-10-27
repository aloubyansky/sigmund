package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ToolFactoryTest {

    private static final String PINNED = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234";

    private static SignerIdentity signerPinning(String fingerprint) {
        return new SignerIdentity("alice", List.of(KeyCredential.openPgp(fingerprint)));
    }

    @Nested
    class GpgFactory {

        private final GpgToolFactory factory = new GpgToolFactory();

        @Test
        void toolName() {
            assertThat(factory.toolName()).isEqualTo("gpg");
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(factory.supportedCredentialTypes()).isEqualTo(Set.of(Credential.TYPE_PGP4));
        }

        @Test
        void createVerifyOnlyDefaultExecutable() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertThat(tool.name()).isEqualTo("gpg");
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void createVerifyOnlyCustomExecutable() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("executable", "/usr/local/bin/gpg2"));
            assertThat(tool.name()).isEqualTo("gpg");
        }

        @Test
        void createWithKeyNameSetting() {
            SignatureTool tool = factory.createSigning(Map.of("key-name", "user@example.com"), null);
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createNoKeyNameNoCredential() {
            SignatureTool tool = factory.createSigning(Map.of(), null);
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void aSigningKeyComesOnlyFromSettings() {
            var tool = (GpgRunner) factory.createSigning(Map.of(), signerPinning(PINNED));

            assertThat(tool.keyName()).isNull();
        }
    }

    @Nested
    class SqFactory {

        @TempDir
        Path tempDir;

        private final SqToolFactory factory = new SqToolFactory();

        @Test
        void toolName() {
            assertThat(factory.toolName()).isEqualTo("sq");
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(factory.supportedCredentialTypes())
                    .isEqualTo(Set.of(Credential.TYPE_PGP4, Credential.TYPE_PGP6));
        }

        @Test
        void createVerifyOnlyDefaultHome() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("home", tempDir.toString()));
            assertThat(tool.name()).isEqualTo("sq");
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void createVerifyOnlyCustomHome() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("home", "/tmp/sq-home"));
            assertThat(tool.name()).isEqualTo("sq");
        }

        @Test
        void createWithFingerprintSetting() {
            SignatureTool tool = factory.createSigning(Map.of(
                    "home", tempDir.toString(),
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"), null);
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createNoFingerprintNoCredential() {
            SignatureTool tool = factory.createSigning(Map.of("home", tempDir.toString()), null);
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void aSigningKeyComesOnlyFromSettings() {
            SignatureTool tool = factory.createSigning(Map.of("home", tempDir.toString()), signerPinning(PINNED));

            assertThat(tool.signingInfo()).noneMatch(info -> PINNED.equals(info.fingerprint()));
        }

        @Test
        void createCustomExecutable() {
            SignatureTool tool = factory.createSigning(Map.of("executable", "/opt/bin/sq"), null);
            assertThat(tool.name()).isEqualTo("sq");
        }
    }

    @Nested
    class BcFactory {

        private final BcToolFactory factory = new BcToolFactory();

        @Test
        void toolName() {
            assertThat(factory.toolName()).isEqualTo("bc");
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(factory.supportedCredentialTypes())
                    .isEqualTo(Set.of(Credential.TYPE_PGP4, Credential.TYPE_PGP6));
        }

        @Test
        void createVerifyOnlyDefaultPaths() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertThat(tool.name()).isEqualTo("bc");
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void createVerifyOnlyCustomPaths() {
            SignatureTool tool = factory.createVerifyOnly(Map.of(
                    "gnupg-home", "/tmp/gnupg",
                    "cert-d-home", "/tmp/cert-d",
                    "bc-private-home", "/tmp/bc-private"));
            assertThat(tool.name()).isEqualTo("bc");
        }

        @Test
        void createWithFingerprintSetting() {
            SignatureTool tool = factory.createSigning(Map.of(
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"), null);
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void aSigningKeyComesOnlyFromSettings() {
            SignatureTool tool = factory.createSigning(Map.of(), signerPinning(PINNED));

            assertThat(tool.signingInfo()).noneMatch(info -> PINNED.equals(info.fingerprint()));
        }

        @Test
        void createNoFingerprintNoCredential() {
            SignatureTool tool = factory.createSigning(Map.of(), null);
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void keygenUsesTheConfiguredCipherSuiteWhenNoneIsGiven(@TempDir Path dir) {
            var tool = (KeyGenerator) factory.createSigning(storesIn(dir, "cipher-suite", "bogus"), null);

            assertThatThrownBy(() -> tool.generateKey("Alice <alice@example.com>", null))
                    .isInstanceOf(ToolExecutionException.class)
                    .hasMessageContaining("Unsupported cipher suite: bogus");
        }

        @Test
        void keygenFallsBackToEd25519WithoutAConfiguredCipherSuite(@TempDir Path dir) {
            var tool = (KeyGenerator) factory.createSigning(storesIn(dir), null);

            assertThat(tool.generateKey("Alice <alice@example.com>", null)).hasSize(64);
        }

        private Map<String, String> storesIn(Path dir, String... extra) {
            Map<String, String> settings = new HashMap<>(Map.of(
                    "gnupg-home", dir.resolve("gnupg").toString(),
                    "cert-d-home", dir.resolve("cert-d").toString(),
                    "bc-private-home", dir.resolve("bc-private").toString()));
            for (int i = 0; i < extra.length; i += 2) {
                settings.put(extra[i], extra[i + 1]);
            }
            return settings;
        }

        @Test
        void createWithTskFile() {
            SignatureTool tool = factory.createSigning(Map.of(
                    "signing-fingerprint", "ABCD1234",
                    "tsk-file", "/tmp/key.tsk"), null);
            assertThat(tool.canSign()).isTrue();
        }
    }

    @Nested
    class BuilderIntegration {

        @Test
        void addToolUnknownNameThrows() {
            var builder = Sigmund.builder();
            assertThatThrownBy(() -> builder.addTool("nonexistent", Map.of()))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("unknown tool 'nonexistent'");
        }

        @Test
        void addSigningToolUnknownNameThrows() {
            var builder = Sigmund.builder();
            assertThatThrownBy(() -> builder.addSigningTool("nonexistent", Map.of()))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("unknown tool 'nonexistent'");
        }
    }
}
