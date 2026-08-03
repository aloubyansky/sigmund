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
        return Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6);
    }

    @Override
    public SignatureTool createSigning(Credential credential, Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "sq");
        Path home = resolveHome(settings);
        String fingerprint = settings.get("signing-fingerprint");
        if (fingerprint == null && credential instanceof FingerprintCredential fp) {
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
        String executable = settings.getOrDefault("executable", "sq");
        Path home = resolveHome(settings);
        return new SqRunner(executable, home, null);
    }

    private static Path resolveHome(Map<String, String> settings) {
        String homeSetting = settings.get("home");
        return homeSetting != null ? Path.of(homeSetting) : null;
    }
}
