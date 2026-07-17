package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper for the GnuPG (gpg) command-line tool.
 * <p>
 * Implements {@link SignatureTool} (signing and verification of detached
 * ASCII-armored signatures), {@link KeyImporter} (importing public keys
 * into the GPG keyring), and {@link SignerIdentityResolver} (resolving
 * signer identities from the keyring).
 * <p>
 * Requires the {@code gpg} executable to be available on the system PATH
 * or at the location specified via the constructor.
 *
 * @see #isAvailable()
 */
public class GpgRunner implements SignatureTool, KeyImporter, SignerIdentityResolver {

    private static final Pattern GPG_KEY_PATTERN = Pattern.compile(
            "using (\\w+) key\\s+([0-9A-Fa-f]{16,40})", Pattern.MULTILINE);

    private static final Pattern GPG_SIGNER_PATTERN = Pattern.compile(
            "Good signature from \"([^\"]+)\"", Pattern.MULTILINE);

    // --with-colons field index 9: user ID in uid: records, fingerprint in fpr: records
    private static final int GPG_COLONS_FIELD_9 = 9;

    /**
     * Checks if the GPG executable is available and functional.
     *
     * @return true if GPG is available and responds to --version, false otherwise
     */
    public static boolean isToolAvailable() {
        try {
            CliTool.Result result = CliTool.run("gpg", "--version");
            return result.exitCode() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts the GPG key ID from gpg --verify stderr output.
     * <p>
     * Parses stderr output looking for lines like:
     * {@code gpg:                using RSA key 4AEE18F83AFDEB23}
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the extracted key ID in uppercase, or null if not found
     */
    static String extractGpgKeyId(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_KEY_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(2).toUpperCase();
        }
        return null;
    }

    /**
     * Extracts the key algorithm (e.g., "RSA", "EDDSA") from gpg --verify stderr output.
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the algorithm name in uppercase, or null if not found
     */
    static String extractAlgorithm(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_KEY_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1).toUpperCase();
        }
        return null;
    }

    /**
     * Extracts the signer's user ID from gpg --verify stderr output.
     * <p>
     * Parses stderr output looking for lines like:
     * {@code gpg: Good signature from "Name <email@example.com>" [ultimate]}
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the signer's user ID (e.g., "Name &lt;email@example.com&gt;"), or null if not found
     */
    static String extractSignerUserId(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_SIGNER_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(Credential.TYPE_OPENPGP_V4);

    /**
     * Result of a GPG signature verification.
     *
     * @param verdict the verification outcome: {@link Verdict#PASS} if the signature is valid,
     *        {@link Verdict#FAIL} if the signature does not match,
     *        {@link Verdict#NO_KEY} if the signing key is not in the keyring
     * @param keyId the signing key ID extracted from GPG output, or null if not found
     * @param algorithm the key algorithm (e.g., "RSA", "EDDSA"), or null if not found
     * @param signerUserId the signer's user ID (e.g., "Name &lt;email&gt;"), or null if the key is not in the keyring
     */
    private record GpgVerifyResult(Verdict verdict, String keyId, String algorithm, String signerUserId) {
    }

    private final String gpgExecutable;
    private final String keyName;
    private final String passphrase;
    private final Map<String, String> env;
    private final OpenPgpSignatureFormat format;
    private volatile String detectedAlgorithm;
    private final boolean resolveSigners;
    private final boolean importToKeyring;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache;

    /**
     * Constructs a GpgRunner using the default "gpg" executable and default key.
     */
    public GpgRunner() {
        this("gpg", null, null);
    }

    /**
     * Constructs a GpgRunner using the default "gpg" executable.
     *
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     */
    public GpgRunner(String keyName) {
        this("gpg", keyName, null);
    }

    /**
     * Constructs a GpgRunner with a custom GPG executable path.
     *
     * @param gpgExecutable the path to the gpg executable (e.g., "gpg" or "/usr/bin/gpg")
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    public GpgRunner(String gpgExecutable, String keyName) {
        this(gpgExecutable, keyName, null);
    }

    /**
     * Constructs a GpgRunner with a custom GPG executable path and home directory.
     *
     * @param gpgExecutable the path to the gpg executable (e.g., "gpg" or "/usr/bin/gpg")
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     * @param home the GPG home directory, or null to use the default
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    public GpgRunner(String gpgExecutable, String keyName, String home) {
        this(gpgExecutable, keyName, home, null, false, false, List.of());
    }

    /**
     * Constructs a GpgRunner with full configuration.
     *
     * @param gpgExecutable the path to the gpg executable
     * @param keyName the key name/ID to use with --local-user, or null
     * @param home the GPG home directory, or null to use the default
     * @param passphrase the GPG passphrase, or null to rely on gpg-agent
     * @param resolveSigners whether to fetch missing keys from keyservers
     * @param importToKeyring whether to persist fetched keys (GPG always persists, so
     *        this must be {@code true} for fetching to work)
     * @param keyservers keyserver URLs to fetch from
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    public GpgRunner(String gpgExecutable, String keyName, String home,
            String passphrase,
            boolean resolveSigners, boolean importToKeyring, List<String> keyservers) {
        if (gpgExecutable == null || gpgExecutable.isEmpty()) {
            throw new IllegalArgumentException("gpgExecutable cannot be null or empty");
        }
        this.gpgExecutable = gpgExecutable;
        this.keyName = keyName;
        this.passphrase = passphrase;
        this.env = home != null ? Map.of("GNUPGHOME", home) : null;
        this.format = new OpenPgpSignatureFormat();
        this.resolveSigners = resolveSigners;
        this.importToKeyring = importToKeyring;
        this.keyservers = keyservers != null ? List.copyOf(keyservers) : List.of();
        this.fetchCache = new KeyFetchCache();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a detached ASCII-armored signature using GPG with options:
     * {@code --batch --yes --armor --detach-sign [--local-user keyName] --output outputSig artifactFile}.
     *
     * @param artifactFile the file to sign
     * @param outputSig the path where the signature file will be written
     * @return a {@link SignResult} with the algorithm used
     * @throws IllegalArgumentException if artifactFile or outputSig is null
     * @throws ToolExecutionException if the GPG command fails
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (outputSig == null) {
            throw new IllegalArgumentException("outputSig cannot be null");
        }

        String[] command = buildSignCommand(artifactFile, outputSig);
        CliTool.Result result = passphrase != null
                ? CliTool.runWithStdin(env, passphrase + "\n", command)
                : CliTool.run(env, command);
        if (result.exitCode() != 0) {
            throw new ToolExecutionException("'" + String.join(" ", command)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }

        if (detectedAlgorithm == null) {
            try {
                String armored = Files.readString(outputSig);
                OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                String name = Algorithms.algorithmName(info.algorithmId());
                detectedAlgorithm = name != null ? name : "unknown";
            } catch (IOException e) {
                detectedAlgorithm = "unknown";
            }
        }
        return new SignResult(detectedAlgorithm);
    }

    /**
     * Verifies a detached signature file for the specified artifact.
     * <p>
     * This method runs {@code gpg --verify <signatureFile> <artifactFile>}
     * and interprets the result.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file to verify
     * @return a {@link GpgVerifyResult} with the verification outcome and extracted key ID
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     */
    private GpgVerifyResult verifyFile(Path artifactFile, Path signatureFile) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        CliTool.Result result = CliTool.run(env,
                gpgExecutable,
                "--verify",
                signatureFile.toString(),
                artifactFile.toString());

        String keyId = extractGpgKeyId(result.stderr());
        String algorithm = extractAlgorithm(result.stderr());
        String signerUserId = extractSignerUserId(result.stderr());

        // Exit code 2 means warnings (e.g. unknown packet versions); treat as
        // valid only if GPG still reports "Good signature"
        Verdict verdict;
        if (result.exitCode() == 0
                || (result.exitCode() == 2 && result.stderr().contains("Good signature"))) {
            verdict = Verdict.PASS;
        } else if (result.stderr().contains("No public key")) {
            verdict = Verdict.NO_KEY;
        } else {
            verdict = Verdict.FAIL;
        }
        return new GpgVerifyResult(verdict, keyId, algorithm, signerUserId);
    }

    /**
     * Receives a public key from a keyserver and imports it into the local keyring.
     *
     * @param keyId the key ID to receive
     * @param keyserver the keyserver URL (e.g., "hkps://keys.openpgp.org")
     * @return true if the key was successfully received, false otherwise
     */
    public boolean receiveKey(String keyId, String keyserver) {
        CliTool.Result result = CliTool.run(env,
                gpgExecutable,
                "--keyserver", keyserver,
                "--recv-keys", keyId);
        return result.exitCode() == 0;
    }

    /**
     * Checks whether a key is already present in the local GPG keyring.
     *
     * @param keyId the key ID or fingerprint to check
     * @return {@code true} if the key is in the keyring
     */
    private boolean hasKey(String keyId) {
        CliTool.Result result = CliTool.run(env,
                gpgExecutable, "--list-keys", keyId);
        return result.exitCode() == 0;
    }

    /**
     * Looks up the user ID (UID) for a key in the local keyring.
     * <p>
     * Parses the {@code --with-colons} output format where the user ID is at field index 9
     * on lines starting with {@code uid:}.
     *
     * @param keyId the key ID to look up
     * @return the user ID string (e.g., "Name &lt;email@example.com&gt;"), or null if not found
     */
    public String listKeyUserId(String keyId) {
        CliTool.Result result = CliTool.run(env,
                gpgExecutable,
                "--list-keys",
                "--with-colons",
                keyId);
        if (result.exitCode() != 0) {
            return null;
        }
        for (String line : result.stdout().split("\\R")) {
            if (line.startsWith("uid:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_FIELD_9 && !fields[GPG_COLONS_FIELD_9].isEmpty()) {
                    return fields[GPG_COLONS_FIELD_9];
                }
            }
        }
        return null;
    }

    @Override
    public String name() {
        return "gpg";
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks availability by running {@code gpg --version}.
     */
    @Override
    public boolean isAvailable() {
        return isToolAvailable();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} if a key name was provided at construction time.
     * A {@code null} key name means GPG's default key is used, which is still
     * considered signing-capable.
     */
    @Override
    public boolean canSign() {
        return true;
    }

    @Override
    public List<SigningInfo> signingInfo() {
        CliTool.Result result = keyName != null
                ? CliTool.run(env, gpgExecutable, "--list-keys", "--with-colons", keyName)
                : CliTool.run(env, gpgExecutable, "--list-secret-keys", "--with-colons");
        if (result.exitCode() != 0) {
            return List.of();
        }
        return List.of(parseColonsSigningInfo(result.stdout()));
    }

    /**
     * Parses GPG {@code --with-colons} output to extract signing identity information.
     * <p>
     * Extracts the algorithm from the first {@code pub:} or {@code sec:} record (field 3),
     * the fingerprint from the first {@code fpr:} record (field 9), and the user ID from
     * the first {@code uid:} record (field 9).
     *
     * @param colonsOutput the raw output from {@code gpg --list-keys --with-colons}
     * @return signing info with whatever fields could be parsed (nulls for missing fields)
     */
    static SigningInfo parseColonsSigningInfo(String colonsOutput) {
        String fingerprint = null;
        String algorithm = null;
        String userId = null;
        for (String line : colonsOutput.split("\\R")) {
            if (algorithm == null && (line.startsWith("pub:") || line.startsWith("sec:"))) {
                String[] fields = line.split(":", -1);
                if (fields.length > 4) {
                    try {
                        algorithm = Algorithms.algorithmName(Integer.parseInt(fields[3]));
                    } catch (NumberFormatException ignored) {
                    }
                }
            } else if (fingerprint == null && line.startsWith("fpr:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_FIELD_9) {
                    fingerprint = fields[GPG_COLONS_FIELD_9];
                }
            } else if (userId == null && line.startsWith("uid:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_FIELD_9
                        && !fields[GPG_COLONS_FIELD_9].isEmpty()) {
                    userId = fields[GPG_COLONS_FIELD_9];
                }
            }
            if (fingerprint != null && algorithm != null && userId != null) {
                break;
            }
        }
        return new SigningInfo("gpg", fingerprint, algorithm, userId,
                Set.copyOf(SUPPORTED_CREDENTIAL_TYPES));
    }

    @Override
    public SignatureFormat signatureFormat() {
        return format;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return SUPPORTED_CREDENTIAL_TYPES;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Accepts {@link OpenPgpVerificationUnit}s with {@code packetVersion <= 4}.
     */
    @Override
    public boolean canVerify(VerificationUnit unit) {
        return unit instanceof OpenPgpVerificationUnit opgu
                && opgu.packetVersion() > 0
                && opgu.packetVersion() <= 4;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Writes the armored block to a temp file, verifies via GPG, and wraps
     * the result into an {@link OpenPgpVerifyResult}.
     */
    @Override
    public VerifyResult verify(Path artifactFile, VerificationUnit unit) {
        if (!(unit instanceof OpenPgpVerificationUnit opgu)) {
            return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, -1, null, null);
        }
        return verifyArmoredBlock(artifactFile, opgu);
    }

    @Override
    public List<Credential> extractCredentials(VerifyResult result) {
        if (result.verdict() != Verdict.PASS) {
            return List.of();
        }
        if (result instanceof OpenPgpVerifyResult opvr && opvr.fingerprint() != null) {
            List<Credential> creds = new ArrayList<>(2);
            creds.add(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, opvr.fingerprint()));
            String email = extractEmail(result.signerDisplayName());
            if (email != null) {
                creds.add(new EmailCredential(email));
            }
            return List.copyOf(creds);
        }
        return List.of();
    }

    public static String extractEmail(String uid) {
        if (uid == null) {
            return null;
        }
        int lt = uid.indexOf('<');
        int gt = uid.indexOf('>', lt + 1);
        if (lt >= 0 && gt > lt + 1) {
            return uid.substring(lt + 1, gt).trim();
        }
        String trimmed = uid.trim();
        if (trimmed.contains("@") && !trimmed.contains(" ")) {
            return trimmed;
        }
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * GPG requires keys in its on-disk keyring — ephemeral imports are not possible.
     * Returns {@code true} only when all three conditions are met:
     * {@code resolveSigners} is enabled, {@code importToKeyring} is {@code true}
     * (GPG always persists), and at least one keyserver is configured.
     */
    @Override
    public boolean canFetchKeys() {
        return resolveSigners && importToKeyring && !keyservers.isEmpty();
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Checks the {@link KeyFetchCache} first to avoid unnecessary work for
     * keys already known to be missing. If the cache allows an attempt, checks
     * the local GPG keyring before hitting keyservers. Then runs
     * {@code gpg --keyserver <server> --recv-keys <keyId>} for each configured
     * keyserver. Connection-level failures (detected from GPG's stderr output)
     * trip the per-keyserver circuit breaker. If the key is not found on any
     * healthy server, it is added to the negative cache.
     */
    @Override
    public boolean fetchKey(String keyId) {
        if (!canFetchKeys()) {
            return false;
        }
        if (!fetchCache.shouldAttemptKey(keyId)) {
            return false;
        }
        if (hasKey(keyId)) {
            return true;
        }
        for (String keyserver : keyservers) {
            if (!fetchCache.shouldAttempt(keyserver, keyId)) {
                continue;
            }
            CliTool.Result result = CliTool.run(env,
                    gpgExecutable,
                    "--keyserver", keyserver,
                    "--recv-keys", keyId);
            if (result.exitCode() == 0) {
                fetchCache.recordSuccess(keyserver, keyId);
                return true;
            }
            if (isConnectionFailure(result)) {
                fetchCache.recordConnectionFailure(keyserver);
            }
        }
        fetchCache.recordKeyNotFound(keyId);
        return false;
    }

    private static boolean isConnectionFailure(CliTool.Result result) {
        String stderr = result.stderr();
        if (stderr == null) {
            return false;
        }
        return stderr.contains("no keyserver available")
                || stderr.contains("keyserver send failed")
                || stderr.contains("keyserver receive failed")
                || stderr.contains("Connection timed out")
                || stderr.contains("Network is unreachable");
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates to {@link #listKeyUserId(String)}.
     */
    @Override
    public String lookupKeyUserId(String keyId) {
        return listKeyUserId(keyId);
    }

    private OpenPgpVerifyResult verifyArmoredBlock(Path artifactFile, OpenPgpVerificationUnit opgu) {
        Path sigFile = null;
        try {
            sigFile = Files.createTempFile("gpg-verify-", ".asc");
            Files.writeString(sigFile, opgu.armoredBlock());
            GpgVerifyResult gpgResult = verifyFile(artifactFile, sigFile);
            return toOpenPgpVerifyResult(gpgResult, opgu);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for GPG verification", e);
        } finally {
            deleteSilently(sigFile);
        }
    }

    private OpenPgpVerifyResult toOpenPgpVerifyResult(GpgVerifyResult gpgResult, OpenPgpVerificationUnit opgu) {
        // Prefer the full fingerprint from the signature packet's issuer fingerprint subpacket.
        // Fall back to GPG's short key ID when the subpacket is absent (older v4 signatures).
        // FingerprintCredential.matches() uses suffix matching, so the short key ID still
        // matches against a full fingerprint in the trust configuration.
        String fingerprint = opgu.issuerFingerprint() != null ? opgu.issuerFingerprint() : gpgResult.keyId();
        return new OpenPgpVerifyResult(
                gpgResult.verdict(),
                gpgResult.signerUserId(),
                gpgResult.algorithm(),
                opgu.packetVersion(),
                gpgResult.keyId(),
                fingerprint);
    }

    private static void deleteSilently(Path file) {
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Builds the GPG sign command. When a passphrase is available,
     * adds {@code --pinentry-mode loopback --passphrase-fd 0} so the passphrase
     * can be piped via stdin.
     */
    private String[] buildSignCommand(Path artifactFile, Path outputSig) {
        List<String> command = new ArrayList<>();
        command.add(gpgExecutable);
        command.add("--batch");
        command.add("--yes");
        command.add("--armor");
        command.add("--detach-sign");

        if (passphrase != null) {
            command.add("--pinentry-mode");
            command.add("loopback");
            command.add("--passphrase-fd");
            command.add("0");
        }

        if (keyName != null && !keyName.isEmpty()) {
            command.add("--local-user");
            command.add(keyName);
        }

        command.add("--output");
        command.add(outputSig.toString());
        command.add(artifactFile.toString());

        return command.toArray(new String[0]);
    }

}
