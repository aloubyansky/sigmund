package dev.cyberstamp.sigmund.sigstore;

import static org.junit.jupiter.api.Assertions.*;

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
            assertEquals("sigstore", factory.toolName());
        }

        @Test
        void supportedCredentialTypes() {
            assertTrue(factory.supportedCredentialTypes().contains("sigstore"));
            assertEquals(1, factory.supportedCredentialTypes().size());
        }
    }

    @Nested
    class ServiceLoaderDiscovery {
        @Test
        void isDiscoverable() {
            boolean found = ServiceLoader.load(SignatureToolFactory.class)
                    .stream()
                    .anyMatch(p -> p.get() instanceof SigstoreToolFactory);
            assertTrue(found,
                    "SigstoreToolFactory should be discoverable via ServiceLoader");
        }
    }

    @Nested
    class CreateVerifyOnly {
        @Test
        void failsWithInvalidTrustedRoot(@TempDir Path tempDir) {
            Path badRoot = tempDir.resolve("bad-root.json");
            assertThrows(ToolExecutionException.class,
                    () -> factory.createVerifyOnly(
                            Map.of("trusted-root", badRoot.toString())));
        }

        @Test
        void failsWithMalformedTrustedRoot(@TempDir Path tempDir) throws IOException {
            Path badRoot = tempDir.resolve("bad-root.json");
            Files.writeString(badRoot, "not valid json");
            assertThrows(ToolExecutionException.class,
                    () -> factory.createVerifyOnly(
                            Map.of("trusted-root", badRoot.toString())));
        }
    }

    @Nested
    class CreateSigning {
        @Test
        void acceptsNullCredential() throws Exception {
            try (var tool = (SigstoreTool) factory.createSigning(
                    null, Map.of("staging", "true"))) {
                assertTrue(tool.canSign());
                assertEquals("sigstore", tool.name());
                assertTrue(tool.signingInfo().get(0).userId() == null);
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
                assertTrue(tool.canSign());
                assertEquals("alice@example.com",
                        tool.signingInfo().get(0).userId());
            }
        }
    }
}
