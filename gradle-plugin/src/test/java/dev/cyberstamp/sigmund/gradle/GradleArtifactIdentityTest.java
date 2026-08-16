package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class GradleArtifactIdentityTest {

    @Test
    void fromCoordsThreeParts() {
        var id = GradleArtifactIdentity.fromCoords("com.example:lib:1.0");
        assertThat(id.namespace()).isEqualTo("com.example");
        assertThat(id.name()).isEqualTo("lib");
        assertThat(id.version()).isEqualTo("1.0");
    }

    @Test
    void fromCoordsTwoParts() {
        var id = GradleArtifactIdentity.fromCoords("com.example:lib");
        assertThat(id.namespace()).isEqualTo("com.example");
        assertThat(id.name()).isEqualTo("lib");
        assertThat(id.version()).isEmpty();
    }

    @Test
    void toStringFormat() {
        var id = new GradleArtifactIdentity("com.example", "lib", "2.0");
        assertThat(id.toString()).isEqualTo("com.example:lib:2.0");
    }

    @Test
    void toStringOmitsEmptyVersion() {
        var id = new GradleArtifactIdentity("com.example", "lib", "");
        assertThat(id.toString()).isEqualTo("com.example:lib");
    }
}
