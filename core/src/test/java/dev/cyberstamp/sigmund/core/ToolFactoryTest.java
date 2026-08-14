package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ToolFactoryTest {

    @Nested
    class GpgFactory {

        private final GpgToolFactory factory = new GpgToolFactory();

        @Test
        void toolName() {
            assertThat(factory.toolName()).isEqualTo("gpg");
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(factory.supportedCredentialTypes()).isEqualTo(Set.of(Credential.TYPE_OPENPGP_V4));
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
            SignatureTool tool = factory.createSigning(null, Map.of("key-name", "user@example.com"));
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createWithCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V4, "ABCD1234ABCD1234");
            SignatureTool tool = factory.createSigning(cred, Map.of());
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createNoKeyNameNoCredential() {
            SignatureTool tool = factory.createSigning(null, Map.of());
            assertThat(tool.canSign()).isTrue();
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
                    .isEqualTo(Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6));
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
            SignatureTool tool = factory.createSigning(null, Map.of(
                    "home", tempDir.toString(),
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createWithCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V6,
                    "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
            SignatureTool tool = factory.createSigning(cred, Map.of("home", tempDir.toString()));
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createNoFingerprintNoCredential() {
            SignatureTool tool = factory.createSigning(null, Map.of("home", tempDir.toString()));
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void createCustomExecutable() {
            SignatureTool tool = factory.createSigning(null, Map.of("executable", "/opt/bin/sq"));
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
                    .isEqualTo(Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6));
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
            SignatureTool tool = factory.createSigning(null, Map.of(
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createWithCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V6,
                    "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
            SignatureTool tool = factory.createSigning(cred, Map.of());
            assertThat(tool.canSign()).isTrue();
        }

        @Test
        void createNoFingerprintNoCredential() {
            SignatureTool tool = factory.createSigning(null, Map.of());
            assertThat(tool.canSign()).isFalse();
        }

        @Test
        void createWithTskFile() {
            SignatureTool tool = factory.createSigning(null, Map.of(
                    "signing-fingerprint", "ABCD1234",
                    "tsk-file", "/tmp/key.tsk"));
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
                    .hasMessageContaining("Unknown tool");
        }

        @Test
        void addSigningToolUnknownNameThrows() {
            var builder = Sigmund.builder();
            assertThatThrownBy(() -> builder.addSigningTool("nonexistent", Map.of()))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("Unknown tool");
        }
    }
}
