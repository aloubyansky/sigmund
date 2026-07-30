package dev.cyberstamp.sigmund.core;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Factory for constructing {@link BcRunner} instances from configuration.
 */
final class BcToolFactory implements SignatureToolFactory {

    @Override
    public String toolName() {
        return "bc";
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6);
    }

    private static final String DEFAULT_PASSPHRASE_ENV = "SIGMUND_BC_PASSPHRASE";
    private static final String DEFAULT_SIGNING_KEY_ENV = "SIGMUND_BC_SIGNING_KEY";

    @Override
    public SignatureTool create(Credential credential, Map<String, String> settings) {
        return create(credential, settings, null);
    }

    /**
     * Creates a signing-capable tool with an explicit passphrase provider.
     * <p>
     * The explicit provider bypasses settings-based resolution entirely,
     * preserving the {@code char[]}-based passphrase lifecycle. Called by
     * {@link Sigmund.Builder} when a {@link PassphraseProvider} was set
     * via {@link Sigmund.Builder#bcPassphraseProvider}.
     *
     * <h4>Signing key priority</h4>
     * <ol>
     * <li>{@code SIGMUND_BC_SIGNING_KEY} env var (or custom {@code signing-key-env})</li>
     * <li>{@code tsk-file} setting</li>
     * <li>{@code signing-fingerprint} setting (or credential fingerprint)</li>
     * </ol>
     * <p>
     * The env var takes precedence so that CI environments can override
     * file-based configuration without modifying {@code sigmund.yaml}.
     */
    SignatureTool create(Credential credential, Map<String, String> settings,
            PassphraseProvider explicitProvider) {
        BcKeyStore keyStore = buildKeyStore(settings);
        byte[] tskBytes = resolveSigningKeyBytes(settings);
        Path tskFile = tskBytes == null ? resolveOptionalPath(settings, "tsk-file") : null;
        String fingerprint = null;
        if (tskBytes == null && tskFile == null) {
            fingerprint = settings.get("signing-fingerprint");
            if (fingerprint == null && credential instanceof FingerprintCredential fp) {
                fingerprint = fp.fingerprint();
            }
        }
        PassphraseProvider provider = explicitProvider != null
                ? explicitProvider
                : resolvePassphraseProvider(settings);
        return new BcRunner(keyStore, fingerprint, tskFile, tskBytes, provider,
                false, false, List.of());
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        BcKeyStore keyStore = buildKeyStore(settings);
        boolean resolveSigners = "true".equals(settings.get("resolve-signers"));
        boolean importToKeyring = "true".equals(settings.get("import-to-keyring"));
        List<String> keyservers = ToolsConfig.parseKeyserversSetting(settings.get("keyservers"));
        return new BcRunner(keyStore, null, null, null, null,
                resolveSigners, importToKeyring, keyservers);
    }

    /**
     * Builds a key store from the given settings.
     */
    private static BcKeyStore buildKeyStore(Map<String, String> settings) {
        Path gnupgHome = resolveGnupgHome(settings);
        Path certDHome = resolveCertDHome(settings);
        Path bcPrivateHome = resolveBcPrivateHome(settings, certDHome);
        return new BcKeyStore(gnupgHome, certDHome, bcPrivateHome);
    }

    /**
     * Resolves the GnuPG home directory.
     */
    private static Path resolveGnupgHome(Map<String, String> settings) {
        String home = settings.get("gnupg-home");
        if (home != null) {
            return Path.of(home);
        }
        String userHome = System.getProperty("user.home");
        return userHome != null ? Path.of(userHome, ".gnupg") : null;
    }

    /**
     * Resolves the shared cert-d directory.
     */
    private static Path resolveCertDHome(Map<String, String> settings) {
        String home = settings.get("cert-d-home");
        if (home != null) {
            return Path.of(home);
        }
        String userHome = System.getProperty("user.home");
        if (userHome == null) {
            throw new SigmundException("Cannot determine cert-d home: user.home is not set");
        }
        return Path.of(userHome, ".local", "share", "openpgp-cert-d");
    }

    /**
     * Resolves the BC private key store directory.
     */
    private static Path resolveBcPrivateHome(Map<String, String> settings, Path certDHome) {
        String home = settings.get("bc-private-home");
        if (home != null) {
            return Path.of(home);
        }
        return certDHome.resolve("bc-private");
    }

    /**
     * Resolves an optional file path from settings.
     */
    private static Path resolveOptionalPath(Map<String, String> settings, String key) {
        String value = settings.get(key);
        return value != null ? Path.of(value) : null;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} when the default {@code SIGMUND_BC_SIGNING_KEY} env var
     * is set and non-empty — indicating an ephemeral signing key was injected
     * from the environment, typically a CI secret. When no signing tools are
     * configured in {@code sigmund.yaml}, the builder uses this to make BC the
     * sole signer, preventing other tools (GPG, sq) from co-signing with
     * unintended default keys.
     * <p>
     * A custom env var name configured via {@code signing-key-env} in
     * {@code sigmund.yaml} is not checked here, because that configuration
     * implies BC is already listed as an explicit signing tool — this method
     * is not consulted when signing tools are explicitly configured.
     */
    @Override
    public boolean isDefaultExclusiveSigner() {
        String value = System.getenv(DEFAULT_SIGNING_KEY_ENV);
        return value != null && !value.isEmpty();
    }

    /**
     * Resolves signing key bytes from the environment, using {@link System#getenv}.
     *
     * @see #resolveSigningKeyBytes(Map, Function)
     */
    private static byte[] resolveSigningKeyBytes(Map<String, String> settings) {
        return resolveSigningKeyBytes(settings, System::getenv);
    }

    /**
     * Resolves the raw signing key bytes from an environment variable.
     * <p>
     * Resolution order:
     * <ol>
     * <li>If {@code signing-key-env} is present in settings, use that as the env var name.</li>
     * <li>Otherwise, use the default {@code SIGMUND_BC_SIGNING_KEY}.</li>
     * </ol>
     * <p>
     * If the resolved env var is set and non-empty, its value is returned as UTF-8 bytes.
     * If a custom env var name was configured but the variable is not set (or empty),
     * a {@link SigmundException} is thrown — the user explicitly asked for it. If the
     * default env var is simply absent, {@code null} is returned (no error).
     *
     * @param settings tool-specific settings from the config
     * @param envLookup function mapping env var name to value (or {@code null})
     * @return the key bytes, or {@code null} if the default env var is not set
     * @throws SigmundException if a custom {@code signing-key-env} was configured
     *         but the environment variable is not set or empty
     */
    static byte[] resolveSigningKeyBytes(Map<String, String> settings,
            Function<String, String> envLookup) {
        String configuredEnv = settings.get("signing-key-env");
        String envVar = configuredEnv != null ? configuredEnv : DEFAULT_SIGNING_KEY_ENV;
        String envValue = envLookup.apply(envVar);
        if (envValue != null && !envValue.isEmpty()) {
            return envValue.getBytes(StandardCharsets.UTF_8);
        }
        if (configuredEnv != null) {
            throw new SigmundException("Environment variable " + configuredEnv + " is not set");
        }
        return null;
    }

    /**
     * Resolves a passphrase provider from settings.
     * <p>
     * Priority: {@code passphrase-env} setting (env var name, default
     * {@code SIGMUND_BC_PASSPHRASE}), then interactive console prompt if available.
     */
    private static PassphraseProvider resolvePassphraseProvider(Map<String, String> settings) {
        String configuredEnv = settings.get("passphrase-env");
        String envVar = configuredEnv != null ? configuredEnv : DEFAULT_PASSPHRASE_ENV;
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.isEmpty()) {
            return fp -> envValue.toCharArray();
        }
        if (configuredEnv != null) {
            throw new SigmundException(
                    "Environment variable " + configuredEnv + " is not set");
        }
        Console console = System.console();
        if (console != null) {
            Map<String, char[]> cache = new ConcurrentHashMap<>();
            return fp -> {
                char[] cached = cache.computeIfAbsent(fp,
                        k -> console.readPassword("Passphrase for BC key %s: ", k));
                return Arrays.copyOf(cached, cached.length);
            };
        }
        return null;
    }
}
