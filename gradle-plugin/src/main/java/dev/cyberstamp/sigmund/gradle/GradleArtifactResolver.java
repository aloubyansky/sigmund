package dev.cyberstamp.sigmund.gradle;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.ResolvedArtifact;
import org.gradle.api.logging.Logger;

/**
 * Resolves artifact files and their companion signature files from Gradle's dependency
 * resolution infrastructure.
 * <p>
 * This class provides functionality to locate signature files (such as .asc or .sigstore.json)
 * that accompany main artifact files in the Gradle cache. It is used by verification and
 * inspection tasks to gather evidence files for signature verification.
 */
class GradleArtifactResolver {

    private final Logger logger;
    private final Set<String> signatureExtensions;

    /**
     * Constructs a new GradleArtifactResolver.
     *
     * @param logger the Gradle logger for diagnostic output
     * @param signatureExtensions the set of file extensions to search for (e.g., ".asc", ".sigstore.json")
     */
    GradleArtifactResolver(Logger logger, Set<String> signatureExtensions) {
        this.logger = logger;
        this.signatureExtensions = signatureExtensions;
    }

    /**
     * Represents a resolved artifact along with its discovered signature files.
     *
     * @param groupId the Maven group ID of the artifact
     * @param artifactId the Maven artifact ID
     * @param version the artifact version
     * @param artifactFile the path to the main artifact file
     * @param evidenceFiles the list of discovered signature/evidence files
     */
    record ResolvedArtifactFiles(
            String groupId,
            String artifactId,
            String version,
            Path artifactFile,
            List<Path> evidenceFiles) {

        /**
         * Returns the Maven coordinates string for this artifact.
         *
         * @return the coordinates in the format "groupId:artifactId:version"
         */
        String coordinates() {
            return groupId + ":" + artifactId + ":" + version;
        }
    }

    /**
     * Resolves all artifacts from a Gradle configuration and locates their companion
     * signature files.
     * <p>
     * For each resolved artifact in the configuration, this method searches for companion
     * signature files using the configured signature extensions and returns a list of
     * resolved artifact records containing both the artifact file and any found evidence files.
     *
     * @param configuration the Gradle configuration to resolve
     * @return a list of resolved artifacts with their evidence files
     */
    List<ResolvedArtifactFiles> resolve(Configuration configuration) {
        List<ResolvedArtifactFiles> results = new ArrayList<>();
        Set<ResolvedArtifact> artifacts = configuration.getResolvedConfiguration()
                .getResolvedArtifacts();

        for (ResolvedArtifact artifact : artifacts) {
            Path artifactFile = artifact.getFile().toPath();
            var moduleId = artifact.getModuleVersion().getId();
            String groupId = moduleId.getGroup();
            String artifactId = moduleId.getName();
            String version = moduleId.getVersion();

            List<Path> evidenceFiles = findCompanionSignatures(
                    artifactFile, signatureExtensions);

            results.add(new ResolvedArtifactFiles(
                    groupId, artifactId, version, artifactFile, evidenceFiles));
        }
        return results;
    }

    /**
     * Finds companion signature files for a given artifact file.
     * <p>
     * This method searches for files with names matching the artifact file name plus
     * each of the specified signature extensions. For example, if the artifact is
     * "lib-1.0.jar" and extensions include ".asc", it will look for "lib-1.0.jar.asc".
     *
     * @param artifactFile the main artifact file
     * @param signatureExtensions the collection of signature file extensions to search for
     * @return a list of paths to found signature files (may be empty)
     */
    static List<Path> findCompanionSignatures(Path artifactFile,
            Collection<String> signatureExtensions) {
        List<Path> found = new ArrayList<>();
        for (String ext : signatureExtensions) {
            Path sigFile = artifactFile.resolveSibling(
                    artifactFile.getFileName().toString() + ext);
            if (Files.exists(sigFile)) {
                found.add(sigFile);
            }
        }
        return found;
    }
}
