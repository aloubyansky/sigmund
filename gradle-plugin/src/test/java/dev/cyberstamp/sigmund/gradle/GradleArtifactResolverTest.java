package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GradleArtifactResolverTest {

    @Test
    void findCompanionSignaturesFindsAsc(@TempDir Path tempDir) throws IOException {
        Path artifact = Files.createFile(tempDir.resolve("lib-1.0.jar"));
        Path asc = Files.createFile(tempDir.resolve("lib-1.0.jar.asc"));

        List<Path> sigs = GradleArtifactResolver.findCompanionSignatures(
                artifact, Set.of(".asc", ".sigstore.json"));
        assertThat(sigs).containsExactly(asc);
    }

    @Test
    void findCompanionSignaturesReturnsEmptyWhenNone(@TempDir Path tempDir) throws IOException {
        Path artifact = Files.createFile(tempDir.resolve("lib-1.0.jar"));

        List<Path> sigs = GradleArtifactResolver.findCompanionSignatures(
                artifact, Set.of(".asc"));
        assertThat(sigs).isEmpty();
    }

    @Test
    void findCompanionSignaturesFindsMultiple(@TempDir Path tempDir) throws IOException {
        Path artifact = Files.createFile(tempDir.resolve("lib-1.0.jar"));
        Path asc = Files.createFile(tempDir.resolve("lib-1.0.jar.asc"));
        Path sigstore = Files.createFile(tempDir.resolve("lib-1.0.jar.sigstore.json"));

        List<Path> sigs = GradleArtifactResolver.findCompanionSignatures(
                artifact, Set.of(".asc", ".sigstore.json"));
        assertThat(sigs).containsExactlyInAnyOrder(asc, sigstore);
    }
}
