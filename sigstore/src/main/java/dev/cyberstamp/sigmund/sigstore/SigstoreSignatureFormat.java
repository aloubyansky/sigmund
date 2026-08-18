package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.SignatureFormat;
import dev.cyberstamp.sigmund.core.SigstoreVerificationUnit;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import dev.cyberstamp.sigmund.core.VerificationUnit;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Signature format for Sigstore bundles ({@code .sigstore.json}).
 * <p>
 * Each bundle is a standalone JSON file containing the Fulcio certificate,
 * message signature, and Rekor transparency log entry. Unlike OpenPGP where
 * one {@code .asc} file may contain multiple armored blocks, a Sigstore
 * bundle is always a single verifiable unit.
 *
 * @see SignatureFormat
 * @see SigstoreVerificationUnit
 */
public class SigstoreSignatureFormat implements SignatureFormat {

    /** Format name constant. */
    public static final String FORMAT_SIGSTORE = "sigstore";

    private static final String SIGSTORE_MEDIA_TYPE_PREFIX = "application/vnd.dev.sigstore.bundle";

    /**
     * {@inheritDoc}
     *
     * @return {@code "sigstore"}
     */
    @Override
    public String name() {
        return FORMAT_SIGSTORE;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code ".sigstore.json"}
     */
    @Override
    public String fileExtension() {
        return ".sigstore.json";
    }

    /**
     * Detects Sigstore bundles by checking for the Sigstore media type in the JSON content.
     * <p>
     * Files that do not start with {@code \} are rejected immediately.
     * For files that are JSON, checks for a {@code "mediaType"} field
     * with a value starting with {@code "application/vnd.dev.sigstore.bundle"}.
     * </p>
     *
     * @param signatureFile the file to check
     * @return true if the file appears to be a Sigstore bundle
     */
    @Override
    public boolean canHandleByContent(Path signatureFile) {
        try {
            byte[] buf = new byte[1024];
            int n;
            try (InputStream is = Files.newInputStream(signatureFile)) {
                n = is.read(buf);
            }
            if (n <= 0)
                return false;
            String content = new String(buf, 0, n, StandardCharsets.UTF_8).trim();
            if (!content.startsWith("{")) {
                return false;
            }
            return content.contains("\"mediaType\"")
                    && content.contains(SIGSTORE_MEDIA_TYPE_PREFIX);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Parses a Sigstore bundle file into a single {@link SigstoreVerificationUnit}.
     * <p>
     * The entire file content is wrapped as a JSON string — no sub-parsing
     * is performed at this stage.
     *
     * @param signatureFile the Sigstore bundle file
     * @return a single-element list containing the verification unit
     * @throws ToolExecutionException if the file cannot be read
     */
    @Override
    public List<VerificationUnit> parse(Path signatureFile) {
        try {
            String json = Files.readString(signatureFile);
            return List.of(new SigstoreVerificationUnit(json));
        } catch (IOException e) {
            throw new ToolExecutionException(
                    "Failed to read Sigstore bundle: " + signatureFile, e);
        }
    }
}
