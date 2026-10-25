package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

final class SqToolFactory implements SignatureToolFactory {

    @Override
    public String toolName() {
        return "sq";
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_PGP4, Credential.TYPE_PGP6);
    }

    @Override
    public Set<String> acceptedSettings() {
        return ToolSetting.keysOf(Setting.values());
    }

    @Override
    public SignatureTool createSigning(Credential credential, Map<String, String> settings) {
        String executable = Setting.EXECUTABLE.from(settings, "sq");
        Path home = resolveHome(settings);
        String fingerprint = Setting.SIGNING_FINGERPRINT.from(settings);
        if (fingerprint == null && credential instanceof KeyCredential fp) {
            fingerprint = fp.fingerprint();
        }
        if (fingerprint != null) {
            return new SqRunner(executable, home, fingerprint);
        }
        String defaultSigner = SqRunner.querySignerSelf(executable, SqRunner.envFor(home));
        return new SqRunner(executable, home, null, defaultSigner);
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = Setting.EXECUTABLE.from(settings, "sq");
        Path home = resolveHome(settings);
        return new SqRunner(executable, home, null);
    }

    private static Path resolveHome(Map<String, String> settings) {
        String homeSetting = Setting.HOME.from(settings);
        return homeSetting != null ? Path.of(homeSetting) : null;
    }

    /** The settings {@code tools.sq} accepts, each read only through its constant. */
    private enum Setting implements ToolSetting {
        /** {@code home}. */
        HOME("home"),
        /** {@code executable}. */
        EXECUTABLE("executable"),
        /** {@code signing-fingerprint}. */
        SIGNING_FINGERPRINT("signing-fingerprint");

        private final String key;

        Setting(String key) {
            this.key = key;
        }

        @Override
        public String key() {
            return key;
        }
    }
}
