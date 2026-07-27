package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.SigningInfo;
import dev.cyberstamp.sigmund.core.SigningOutput;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;

/**
 * Signs all project artifacts using the tool chain configured in {@code sigmund.yaml}.
 * <p>
 * Bound to the VERIFY phase. Creates detached {@code .asc} signature files for the
 * main artifact, POM, and all attached artifacts. Signing tools and their priority
 * are determined by the {@code signing.tools} section of {@code sigmund.yaml};
 * Mojo parameters act as overrides.
 *
 * @see Sigmund
 * @see Signer
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SignMojo extends AbstractSigningMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Inject
    private MavenProjectHelper projectHelper;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping signing");
            return;
        }
        Signer signer = createSigner();
        for (SigningInfo info : signer.signingInfo()) {
            getLog().info(info.display());
        }
        List<FileToSign> filesToSign = collectFilesToSign();

        getLog().info("Signing " + filesToSign.size() + " artifact(s)...");

        for (FileToSign fileToSign : filesToSign) {
            signAndAttach(fileToSign, signer);
        }

        getLog().info("Signing completed successfully");
    }

    private List<FileToSign> collectFilesToSign() {
        List<FileToSign> files = new ArrayList<>();

        Artifact mainArtifact = project.getArtifact();
        File mainFile = mainArtifact.getFile();
        if (mainFile != null && mainFile.exists() && !mainFile.getName().endsWith(".asc")) {
            String extension = getExtension(mainFile);
            files.add(new FileToSign(mainFile, extension, null));
            getLog().debug("Added main artifact: " + mainFile.getName());
        }

        File pomFile = project.getFile();
        if (pomFile != null && pomFile.exists()) {
            files.add(new FileToSign(pomFile, "pom", null));
            getLog().debug("Added POM: " + pomFile.getName());
        }

        for (Artifact artifact : project.getAttachedArtifacts()) {
            File file = artifact.getFile();
            if (file != null && file.exists() && !file.getName().endsWith(".asc")) {
                String extension = getExtension(file);
                String classifier = getClassifier(artifact);
                files.add(new FileToSign(file, extension, classifier));
                getLog().debug("Added attached artifact: " + file.getName() +
                        " (classifier=" + classifier + ")");
            }
        }

        return files;
    }

    private void signAndAttach(FileToSign fileToSign, Signer signer)
            throws MojoExecutionException {
        File file = fileToSign.file;
        Path artifactPath = file.toPath();
        Path signaturePath = Path.of(file.getAbsolutePath() + ".asc");

        getLog().info("Signing: " + file.getName());

        try {
            SigningOutput output = signer.sign(artifactPath, artifactPath.getParent());
            if (!output.files().isEmpty()) {
                Path produced = output.files().get(0).path();
                if (!produced.equals(signaturePath)) {
                    Files.move(produced, signaturePath, StandardCopyOption.REPLACE_EXISTING);
                }
            }
            attachSignature(fileToSign, signaturePath.toFile());
        } catch (IOException | SigmundException e) {
            throw new MojoExecutionException("Failed to sign " + file.getName(), e);
        }
    }

    private void attachSignature(FileToSign fileToSign, File signatureFile) {
        String classifier = fileToSign.classifier;
        String extension = fileToSign.extension + ".asc";

        projectHelper.attachArtifact(project, extension, classifier, signatureFile);

        String name = signatureFile.getName();
        if (classifier != null && !classifier.isEmpty()) {
            name += " (classifier=" + classifier + ")";
        }
        getLog().debug("Attached signature: " + name);
    }

    private String getClassifier(Artifact artifact) {
        String classifier = artifact.getClassifier();
        return (classifier != null && !classifier.isEmpty()) ? classifier : null;
    }

    private String getExtension(File file) {
        String name = file.getName();
        int lastDot = name.lastIndexOf('.');
        return (lastDot >= 0) ? name.substring(lastDot + 1) : name;
    }

    private static class FileToSign {
        final File file;
        final String extension;
        final String classifier;

        FileToSign(File file, String extension, String classifier) {
            this.file = file;
            this.extension = extension;
            this.classifier = classifier;
        }
    }
}
