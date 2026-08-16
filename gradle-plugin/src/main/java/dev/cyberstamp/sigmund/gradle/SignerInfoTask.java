package dev.cyberstamp.sigmund.gradle;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.SigningInfo;
import java.util.List;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;

/**
 * Gradle task for displaying signing identity information.
 * <p>
 * This task retrieves and displays information about the signing identities
 * available for the current project. It shows details from configured signing
 * tools (GPG, Sequoia, Bouncy Castle) about the keys that can be used for signing.
 * <p>
 * Signing identities can be organized into profiles in the Sigmund configuration.
 * If no profile is specified, the default profile is used.
 * <p>
 * Example usage:
 * <pre>
 * sigmundSignerInfo {
 *     profile = "release" // optional: show a specific profile
 * }
 * </pre>
 */
public abstract class SignerInfoTask extends DefaultTask {

    /**
     * Gets the optional configuration file for Sigmund.
     *
     * @return the configuration file property
     */
    @Internal
    public abstract RegularFileProperty getConfigFile();

    /**
     * Gets the optional Sequoia home directory.
     *
     * @return the Sequoia home directory property
     */
    @Internal
    public abstract RegularFileProperty getSqHome();

    /**
     * Gets the optional GPG home directory.
     *
     * @return the GPG home directory property
     */
    @Internal
    public abstract RegularFileProperty getGpgHome();

    /**
     * Gets the optional signing profile name.
     * <p>
     * If not set, the default profile is used.
     *
     * @return the profile name property
     */
    @Input @Optional
    public abstract Property<String> getProfile();

    /**
     * Displays signing identity information.
     * <p>
     * This method:
     * <ol>
     *   <li>Loads the Sigmund configuration</li>
     *   <li>Builds a Sigmund instance with signing tools</li>
     *   <li>Retrieves the signer for the specified or default profile</li>
     *   <li>Displays signing identity information from available tools</li>
     * </ol>
     */
    @TaskAction
    public void info() {
        SigmundConfig config = loadConfig();
        try (Sigmund sigmund = createSigningSigmund(config)) {
            Signer signer = resolveSigner(sigmund);
            displaySigningInfo(signer);
        }
    }

    /**
     * Loads the Sigmund configuration.
     * <p>
     * If a config file is specified, loads from that file.
     * Otherwise, loads the default configuration.
     *
     * @return the loaded Sigmund configuration
     */
    private SigmundConfig loadConfig() {
        if (getConfigFile().isPresent()) {
            return ConfigLoader.load(getConfigFile().get().getAsFile().toPath());
        }
        return ConfigLoader.load(null);
    }

    /**
     * Creates a Sigmund instance configured with signing tools.
     *
     * @param config the Sigmund configuration
     * @return a Sigmund instance with configured signing tools
     */
    private Sigmund createSigningSigmund(SigmundConfig config) {
        return SigmundHelper.buildSigningSigmund(
                config, getSqHome(), getGpgHome(), getLogger());
    }

    /**
     * Resolves the signer for the specified or default profile.
     *
     * @param sigmund the Sigmund instance
     * @return the signer for the requested profile
     */
    private Signer resolveSigner(Sigmund sigmund) {
        return getProfile().isPresent()
                ? sigmund.signer(getProfile().get())
                : sigmund.signer();
    }

    /**
     * Displays signing information for the signer.
     * <p>
     * If no signing identities are available, logs a warning.
     * Otherwise, logs the profile name (if specified) and displays
     * each signing identity.
     *
     * @param signer the signer whose information to display
     */
    private void displaySigningInfo(Signer signer) {
        List<SigningInfo> infos = signer.signingInfo();
        if (infos.isEmpty()) {
            logNoIdentities();
            return;
        }
        logProfile();
        logIdentities(infos);
    }

    /**
     * Logs a warning that no signing identities are available.
     */
    private void logNoIdentities() {
        getLogger().warn("No signing identity information available");
    }

    /**
     * Logs the signing profile name if one was specified.
     */
    private void logProfile() {
        if (getProfile().isPresent()) {
            getLogger().lifecycle("Signing profile: {}", getProfile().get());
        }
    }

    /**
     * Logs each signing identity.
     *
     * @param infos the list of signing identities to log
     */
    private void logIdentities(List<SigningInfo> infos) {
        for (SigningInfo si : infos) {
            getLogger().lifecycle(si.display());
        }
    }
}
