package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;
import java.util.Set;

final class GpgToolFactory implements SignatureToolFactory {

    private static final String DEFAULT_PASSPHRASE_ENV = "SIGMUND_GPG_PASSPHRASE";

    @Override
    public String toolName() {
        return "gpg";
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_PGP4);
    }

    @Override
    public Set<String> acceptedSettings() {
        return ToolSetting.keysOf(Setting.values());
    }

    @Override
    public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        String executable = Setting.EXECUTABLE.from(settings, "gpg");
        String keyName = Setting.KEY_NAME.from(settings);
        String passphrase = resolvePassphrase(settings);
        return new GpgRunner(executable, keyName, Setting.HOME.from(settings),
                passphrase, false, false, List.of());
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = Setting.EXECUTABLE.from(settings, "gpg");
        boolean resolveSigners = FetchSetting.RESOLVE_SIGNERS.isTrue(settings);
        boolean importToKeyring = FetchSetting.IMPORT_TO_KEYRING.isTrue(settings);
        List<String> keyservers = VerificationConfig.parseKeyserversSetting(FetchSetting.KEYSERVERS.from(settings));
        return new GpgRunner(executable, null, Setting.HOME.from(settings),
                null, false, resolveSigners, importToKeyring, keyservers);
    }

    private static String resolvePassphrase(Map<String, String> settings) {
        String configuredEnv = Setting.PASSPHRASE_ENV.from(settings);
        String envVar = configuredEnv != null ? configuredEnv : DEFAULT_PASSPHRASE_ENV;
        String value = System.getenv(envVar);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        if (configuredEnv != null) {
            throw new SigmundException(
                    "Environment variable " + configuredEnv + " is not set");
        }
        return null;
    }

    /** The settings {@code tools.gpg} accepts, each read only through its constant. */
    private enum Setting implements ToolSetting {
        /** {@code executable}. */
        EXECUTABLE("executable"),
        /** {@code key-name}. */
        KEY_NAME("key-name"),
        /** {@code home}. */
        HOME("home"),
        /** {@code passphrase-env}. */
        PASSPHRASE_ENV("passphrase-env");

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
