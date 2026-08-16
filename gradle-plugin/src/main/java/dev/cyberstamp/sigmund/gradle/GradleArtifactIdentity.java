package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.ArtifactIdentity;

record GradleArtifactIdentity(String namespace, String name, String version)
        implements ArtifactIdentity {

    static GradleArtifactIdentity fromCoords(String coords) {
        String[] parts = coords.split(":");
        return switch (parts.length) {
            case 2 -> new GradleArtifactIdentity(parts[0], parts[1], "");
            case 3 -> new GradleArtifactIdentity(parts[0], parts[1], parts[2]);
            default -> new GradleArtifactIdentity(
                    parts[0], parts.length > 1 ? parts[1] : "", "");
        };
    }

    @Override
    public String toString() {
        if (version.isEmpty()) {
            return namespace + ":" + name;
        }
        return namespace + ":" + name + ":" + version;
    }
}
