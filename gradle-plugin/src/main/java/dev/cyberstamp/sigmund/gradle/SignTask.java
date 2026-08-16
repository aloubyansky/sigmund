package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.SigningInfo;
import dev.cyberstamp.sigmund.core.SigningOutput;
import dev.cyberstamp.sigmund.core.SignedFile;
import java.nio.file.Path;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;

/**
 * Signs artifacts using the configured Sigmund signing tools.
 * <p>
 * This task takes a set of input files and signs them using the signing
 * configuration defined in sigmund.yaml. The signatures are written to
 * the specified output directory.
 */
public abstract class SignTask extends DefaultTask {

    /**
     * The path to the sigmund.yaml configuration file.
     *
     * @return the configuration file property
     */
    @Internal
    public abstract RegularFileProperty getConfigFile();

    /**
     * The home directory for Sequoia (sq) tool.
     *
     * @return the Sequoia home directory property
     */
    @Internal
    public abstract RegularFileProperty getSqHome();

    /**
     * The home directory for GPG tool.
     *
     * @return the GPG home directory property
     */
    @Internal
    public abstract RegularFileProperty getGpgHome();

    /**
     * The collection of files to sign.
     *
     * @return the input files property
     */
    @InputFiles
    public abstract ConfigurableFileCollection getInputFiles();

    /**
     * The directory where signature files will be written.
     * Defaults to build/sigmund/signatures.
     *
     * @return the output directory property
     */
    @OutputDirectory
    public abstract DirectoryProperty getOutputDirectory();

    /**
     * Constructs a new SignTask with default output directory.
     */
    public SignTask() {
        getOutputDirectory().convention(
                getProject().getLayout().getBuildDirectory().dir("sigmund/signatures"));
    }

    /**
     * Executes the signing task.
     * <p>
     * This method loads the Sigmund configuration, initializes the signing tools,
     * and signs each input file. The generated signature files are written to
     * the output directory.
     *
     * @throws GradleException if signing fails
     */
    @TaskAction
    public void sign() {
        SigmundConfig config = loadConfig();
        try (Sigmund sigmund = SigmundHelper.buildSigningSigmund(
                config, getSqHome(), getGpgHome(), getLogger())) {
            Signer signer = sigmund.signer();
            for (SigningInfo info : signer.signingInfo()) {
                getLogger().lifecycle(info.display());
            }

            Path outputDir = getOutputDirectory().get().getAsFile().toPath();
            var files = getInputFiles().getFiles();
            getLogger().lifecycle("Signing {} artifact(s)...", files.size());

            for (var file : files) {
                Path artifactPath = file.toPath();
                getLogger().lifecycle("Signing: {}", file.getName());
                SigningOutput output = signer.sign(artifactPath, outputDir);
                for (SignedFile sf : output.files()) {
                    getLogger().lifecycle("  Created: {}", sf.path().getFileName());
                }
            }
            getLogger().lifecycle("Signing completed successfully");
        }
    }

    /**
     * Loads the Sigmund configuration from the specified file or default location.
     *
     * @return the loaded SigmundConfig, or null if no config is found
     */
    private SigmundConfig loadConfig() {
        Path configPath = getConfigFile().isPresent()
                ? getConfigFile().get().getAsFile().toPath()
                : null;
        return ConfigLoader.load(configPath);
    }
}
