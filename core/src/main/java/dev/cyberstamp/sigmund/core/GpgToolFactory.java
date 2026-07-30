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
        return Set.of(Credential.TYPE_OPENPGP_V4);
    }

    @Override
    public SignatureTool create(Credential credential, Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "gpg");
        String keyName = settings.get("key-name");
        if (keyName == null && credential instanceof FingerprintCredential fp) {
            keyName = fp.fingerprint();
        }
        String passphrase = resolvePassphrase(settings);
        return new GpgRunner(executable, keyName, settings.get("home"),
                passphrase, false, false, List.of());
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "gpg");
        boolean resolveSigners = "true".equals(settings.get("resolve-signers"));
        boolean importToKeyring = "true".equals(settings.get("import-to-keyring"));
        List<String> keyservers = ToolsConfig.parseKeyserversSetting(settings.get("keyservers"));
        return new GpgRunner(executable, null, settings.get("home"),
                null, false, resolveSigners, importToKeyring, keyservers);
    }

    private static String resolvePassphrase(Map<String, String> settings) {
        String configuredEnv = settings.get("passphrase-env");
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
}
