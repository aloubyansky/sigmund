package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;

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
            assertThat(format.name()).isEqualTo("sigstore");
        }

        @Test
        void fileExtension() {
            assertThat(format.fileExtension()).isEqualTo(".sigstore.json");
        }

        @Test
        void doesNotSupportCombining() {
            assertThat(format.supportsCombining()).isFalse();
        }
    }

    @Nested
    class CanHandle {
        @Test
        void matchesByExtension() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, "{}");
            assertThat(format.canHandle(file)).isTrue();
        }

        @Test
        void matchesByContent() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sig");
            Files.writeString(file,
                    "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}");
            assertThat(format.canHandleByContent(file)).isTrue();
        }

        @Test
        void matchesOlderBundleVersion() throws IOException {
            Path file = tempDir.resolve("artifact.sig");
            Files.writeString(file,
                    "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.1+json\"}");
            assertThat(format.canHandleByContent(file)).isTrue();
        }

        @Test
        void rejectsNonJsonFile() throws IOException {
            Path file = tempDir.resolve("artifact.jar.asc");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----");
            assertThat(format.canHandleByContent(file)).isFalse();
        }

        @Test
        void rejectsJsonWithoutMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"key\":\"value\"}");
            assertThat(format.canHandleByContent(file)).isFalse();
        }

        @Test
        void rejectsJsonWithWrongMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"mediaType\":\"application/json\"}");
            assertThat(format.canHandleByContent(file)).isFalse();
        }

        @Test
        void rejectsEmptyFile() throws IOException {
            Path file = tempDir.resolve("empty.json");
            Files.writeString(file, "");
            assertThat(format.canHandleByContent(file)).isFalse();
        }

        @Test
        void handlesMissingFile() {
            Path file = tempDir.resolve("nonexistent.json");
            assertThat(format.canHandleByContent(file)).isFalse();
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

            assertThat(units.size()).isEqualTo(1);
            assertThat(units.get(0)).isInstanceOf(SigstoreVerificationUnit.class);
            assertThat(((SigstoreVerificationUnit) units.get(0)).jsonBundle())
                    .isEqualTo(bundle);
        }

        @Test
        void preservesExactJsonContent() throws IOException {
            String bundle = "  { \"mediaType\" : \"test\" , \"extra\" : true }  ";
            Path file = tempDir.resolve("bundle.sigstore.json");
            Files.writeString(file, bundle);

            List<VerificationUnit> units = format.parse(file);

            assertThat(((SigstoreVerificationUnit) units.get(0)).jsonBundle())
                    .isEqualTo(bundle);
        }
    }
}
