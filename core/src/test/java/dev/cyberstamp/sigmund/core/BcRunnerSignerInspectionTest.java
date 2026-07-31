package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcRunnerSignerInspectionTest {

    @TempDir
    Path tempDir;

    private BcRunner createRunner(boolean resolveSigners, List<String> keyservers) {
        Path certD = tempDir.resolve("cert-d");
        try {
            Files.createDirectories(certD);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        BcKeyStore store = new BcKeyStore(null, certD,
                tempDir.resolve("bc-private"));
        return new BcRunner(store, null, null, null, null,
                resolveSigners, false, keyservers);
    }

    @Test
    void canInspectFingerprintCredential() {
        BcRunner runner = createRunner(false, List.of());
        assertTrue(runner.canInspect(
                new FingerprintCredential("openpgp4", "AABB")));
    }

    @Test
    void canInspectEmailCredential() {
        BcRunner runner = createRunner(false, List.of());
        assertTrue(runner.canInspect(new EmailCredential("a@b.com")));
    }

    @Test
    void cannotInspectOidcCredential() {
        BcRunner runner = createRunner(false, List.of());
        assertFalse(runner.canInspect(
                new OidcCredential("https://issuer", "subject")));
    }

    @Test
    void inspectLocalStoreNotFoundReturnsPerSourceResults() {
        BcRunner runner = createRunner(false, List.of());
        var results = runner.inspect(
                new FingerprintCredential("openpgp4",
                        "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"));
        assertFalse(results.isEmpty());
        assertTrue(results.stream().allMatch(r -> !r.found()));
        assertTrue(results.stream().anyMatch(r -> "cert-d store".equals(r.sourceLabel())));
    }
}
