package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyMojoTest {

    @Nested
    class PomVerificationTests {

        private ArtifactCoords jarArtifact(String groupId, String artifactId, String version) {
            return new ArtifactCoords(groupId, artifactId, "", "jar", version);
        }

        @Test
        void addPomArtifactsCreatesPomForEachJar() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib-a", "1.0"));
            artifacts.add(jarArtifact("com.example", "lib-b", "2.0"));

            mojo.addPomArtifacts(artifacts);

            assertThat(artifacts.size()).isEqualTo(4);
            ArtifactCoords pomA = artifacts.get(2);
            assertThat(pomA.namespace()).isEqualTo("com.example");
            assertThat(pomA.name()).isEqualTo("lib-a");
            assertThat(pomA.extension()).isEqualTo("pom");
            assertThat(pomA.version()).isEqualTo("1.0");

            ArtifactCoords pomB = artifacts.get(3);
            assertThat(pomB.name()).isEqualTo("lib-b");
            assertThat(pomB.extension()).isEqualTo("pom");
        }

        @Test
        void addPomArtifactsDeduplicatesSameGav() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib", "1.0"));
            artifacts.add(new ArtifactCoords("com.example", "lib", "sources", "jar", "1.0"));

            mojo.addPomArtifacts(artifacts);

            assertThat(artifacts.size()).isEqualTo(3);
            assertThat(artifacts.get(2).extension()).isEqualTo("pom");
        }

        @Test
        void addPomArtifactsSkipsExistingPomArtifacts() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(new ArtifactCoords(
                    "com.example", "parent", "", "pom", "1.0"));

            mojo.addPomArtifacts(artifacts);

            assertThat(artifacts.size()).isEqualTo(1);
        }
    }
}
