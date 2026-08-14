package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.SignatureToolFactory;
import dev.cyberstamp.sigmund.core.SigstoreCredential;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigstoreToolFactoryTest {

    private final SigstoreToolFactory factory = new SigstoreToolFactory();

    @Nested
    class Properties {
        @Test
        void toolName() {
            assertThat(factory.toolName()).isEqualTo("sigstore");
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(factory.supportedCredentialTypes().contains("sigstore")).isTrue();
            assertThat(factory.supportedCredentialTypes().size()).isEqualTo(1);
        }
    }

    @Nested
    class ServiceLoaderDiscovery {
        @Test
        void isDiscoverable() {
            boolean found = ServiceLoader.load(SignatureToolFactory.class)
                    .stream()
                    .anyMatch(p -> p.get() instanceof SigstoreToolFactory);
            assertThat(found)
                    .as("SigstoreToolFactory should be discoverable via ServiceLoader")
                    .isTrue();
        }
    }

    @Nested
    class CreateVerifyOnly {
        @Test
        void failsWithInvalidTrustedRoot(@TempDir Path tempDir) {
            Path badRoot = tempDir.resolve("bad-root.json");
            assertThatThrownBy(() -> factory.createVerifyOnly(
                    Map.of("trusted-root", badRoot.toString())))
                    .isInstanceOf(ToolExecutionException.class);
        }

        @Test
        void failsWithMalformedTrustedRoot(@TempDir Path tempDir) throws IOException {
            Path badRoot = tempDir.resolve("bad-root.json");
            Files.writeString(badRoot, "not valid json");
            assertThatThrownBy(() -> factory.createVerifyOnly(
                    Map.of("trusted-root", badRoot.toString())))
                    .isInstanceOf(ToolExecutionException.class);
        }
    }

    @Nested
    class CreateSigning {
        @Test
        void acceptsNullCredential() throws Exception {
            try (var tool = (SigstoreTool) factory.createSigning(
                    null, Map.of("staging", "true"))) {
                assertThat(tool.canSign()).isTrue();
                assertThat(tool.name()).isEqualTo("sigstore");
                assertThat(tool.signingInfo().get(0).userId() == null).isTrue();
            }
        }

        @Test
        void acceptsSigstoreCredential() throws Exception {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://accounts.google.com")
                    .subject("alice@example.com")
                    .build();
            try (var tool = (SigstoreTool) factory.createSigning(
                    sc, Map.of("staging", "true"))) {
                assertThat(tool.canSign()).isTrue();
                assertThat(tool.signingInfo().get(0).userId())
                        .isEqualTo("alice@example.com");
            }
        }
    }
}
