package dev.cyberstamp.sigmund.sigstore;

import static org.junit.jupiter.api.Assertions.*;

import dev.cyberstamp.sigmund.core.SigstoreVerificationUnit;
import dev.cyberstamp.sigmund.core.VerificationUnit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigstoreSignatureFormatTest {

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    @TempDir
    Path tempDir;

    @Nested
    class Properties {
        @Test
        void name() {
            assertEquals("sigstore", format.name());
        }

        @Test
        void fileExtension() {
            assertEquals(".sigstore.json", format.fileExtension());
        }

        @Test
        void doesNotSupportCombining() {
            assertFalse(format.supportsCombining());
        }
    }

    @Nested
    class CanHandle {
        @Test
        void matchesByExtension() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, "{}");
            assertTrue(format.canHandle(file));
        }

        @Test
        void matchesByContent() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sig");
            Files.writeString(file,
                    "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}");
            assertTrue(format.canHandleByContent(file));
        }

        @Test
        void matchesOlderBundleVersion() throws IOException {
            Path file = tempDir.resolve("artifact.sig");
            Files.writeString(file,
                    "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.1+json\"}");
            assertTrue(format.canHandleByContent(file));
        }

        @Test
        void rejectsNonJsonFile() throws IOException {
            Path file = tempDir.resolve("artifact.jar.asc");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----");
            assertFalse(format.canHandleByContent(file));
        }

        @Test
        void rejectsJsonWithoutMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"key\":\"value\"}");
            assertFalse(format.canHandleByContent(file));
        }

        @Test
        void rejectsJsonWithWrongMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"mediaType\":\"application/json\"}");
            assertFalse(format.canHandleByContent(file));
        }

        @Test
        void rejectsEmptyFile() throws IOException {
            Path file = tempDir.resolve("empty.json");
            Files.writeString(file, "");
            assertFalse(format.canHandleByContent(file));
        }

        @Test
        void handlesMissingFile() {
            Path file = tempDir.resolve("nonexistent.json");
            assertFalse(format.canHandleByContent(file));
        }
    }

    @Nested
    class Parse {
        @Test
        void returnsSingleUnit() throws IOException {
            String bundle = "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                    + "\"content\":\"test\"}";
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, bundle);

            List<VerificationUnit> units = format.parse(file);

            assertEquals(1, units.size());
            assertInstanceOf(SigstoreVerificationUnit.class, units.get(0));
            assertEquals(bundle,
                    ((SigstoreVerificationUnit) units.get(0)).jsonBundle());
        }

        @Test
        void preservesExactJsonContent() throws IOException {
            String bundle = "  { \"mediaType\" : \"test\" , \"extra\" : true }  ";
            Path file = tempDir.resolve("bundle.sigstore.json");
            Files.writeString(file, bundle);

            List<VerificationUnit> units = format.parse(file);

            assertEquals(bundle,
                    ((SigstoreVerificationUnit) units.get(0)).jsonBundle());
        }
    }
}
