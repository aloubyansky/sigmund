package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ArtifactIdentity;

/**
 * Maven-specific implementation of {@link ArtifactIdentity}.
 *
 * @param namespace the groupId
 * @param name the artifactId
 * @param version the version
 */
record MavenArtifactIdentity(String namespace, String name, String version)
        implements
            ArtifactIdentity {

    static MavenArtifactIdentity from(ArtifactCoords coords) {
        return new MavenArtifactIdentity(coords.groupId(), coords.artifactId(), coords.version());
    }

    static MavenArtifactIdentity fromCoords(String coords) {
        String[] parts = coords.split(":");
        return switch (parts.length) {
            case 2 -> new MavenArtifactIdentity(parts[0], parts[1], "");
            case 3 -> new MavenArtifactIdentity(parts[0], parts[1], parts[2]);
            case 4 -> new MavenArtifactIdentity(parts[0], parts[1], parts[3]);
            case 5 -> new MavenArtifactIdentity(parts[0], parts[1], parts[4]);
            default -> new MavenArtifactIdentity(parts[0], parts.length > 1 ? parts[1] : "", "");
        };
    }
}
