package dev.cyberstamp.sigmund.sigstore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cyberstamp.sigmund.core.Claim;
import dev.cyberstamp.sigmund.core.SignatureFormat;
import dev.cyberstamp.sigmund.core.SigstoreClaim;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Signature format for Sigstore bundles ({@code .sigstore.json}).
 * <p>
 * Each bundle is a standalone JSON file containing the Fulcio certificate,
 * message signature, and Rekor transparency log entry. Unlike OpenPGP where
 * one {@code .asc} file may contain multiple armored blocks, a Sigstore
 * bundle is always a single verifiable claim.
 *
 * @see SignatureFormat
 * @see SigstoreClaim
 */
public class SigstoreSignatureFormat implements SignatureFormat {

    /** Format name, as used in toolchain and credential-type configuration. */
    public static final String FORMAT_SIGSTORE = "sigstore";

    /** Media type every Sigstore bundle declares, whatever its version. */
    private static final String SIGSTORE_MEDIA_TYPE_PREFIX = "application/vnd.dev.sigstore.bundle";

    /** Bytes of a bundle read when sniffing content, enough to reach the media type. */
    private static final int SNIFF_LENGTH = 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
     * Detects Sigstore bundles by looking for the Sigstore media type in the file's opening
     * bytes.
     *
     * <p>
     * A file that does not begin with <code>{</code> is rejected without further reading.
     * Otherwise the first {@value #SNIFF_LENGTH} bytes must carry a {@code "mediaType"} field
     * whose value starts with {@code "application/vnd.dev.sigstore.bundle"}, which every
     * bundle version declares.
     *
     * @param signatureFile the file to check
     * @return {@code true} when the file appears to be a Sigstore bundle
     */
    @Override
    public boolean canHandleByContent(Path signatureFile) {
        try {
            byte[] buf = new byte[SNIFF_LENGTH];
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
     * Parses a Sigstore bundle into a single {@link SigstoreClaim}.
     *
     * <p>
     * A bundle is always one claim: unlike an OpenPGP {@code .asc}, which may carry a classic
     * and a post-quantum block, a bundle holds one certificate and one signature.
     *
     * <p>
     * The bundle text is carried verbatim for the tool to verify; the only field read here is
     * the log entry's integrated time, which becomes the claim's time. Parsing never decides
     * an outcome — a bundle that will not verify, or will not even parse, still yields a claim
     * and the tool reports why.
     *
     * @param signatureFile the Sigstore bundle file
     * @return a single-element list containing the claim
     * @throws ToolExecutionException if the file cannot be read
     */
    @Override
    public List<Claim> parse(Path signatureFile) {
        try {
            String json = Files.readString(signatureFile);
            return List.of(new SigstoreClaim(json, extractIntegratedTime(json)));
        } catch (IOException e) {
            throw new ToolExecutionException(
                    "Failed to read Sigstore bundle: " + signatureFile, e);
        }
    }

    /**
     * Reads the transparency log entry's integrated time from a bundle.
     *
     * <p>
     * This is the instant Rekor recorded and countersigned, which is what makes a Sigstore
     * claim's time independent of the signer (see
     * {@link dev.cyberstamp.sigmund.core.ClaimTimeSource#TRANSPARENCY_LOG}). The field is read
     * straight from the JSON rather than through a full bundle parse, so that a bundle which
     * will not verify still reports when it was logged.
     *
     * <p>
     * Protobuf's JSON mapping renders an {@code int64} as a string, so the value is accepted
     * in either form.
     *
     * <p>
     * The bundle is therefore read twice: once here, and again by {@code SigstoreTool} when it
     * verifies. That is deliberate. Moving this into the tool would not remove a parse —
     * sigstore-java parses the bundle from text either way — and it would lose the claim time
     * for a bundle that does not verify, which is exactly when knowing when it was logged
     * helps. This read is a small tree walk; the tool's is the full bundle.
     *
     * @param json the bundle's JSON text
     * @return the integrated time, or {@code null} when the bundle carries none
     */
    private static Instant extractIntegratedTime(String json) {
        try {
            JsonNode entries = MAPPER.readTree(json)
                    .path("verificationMaterial")
                    .path("tlogEntries");
            if (!entries.isArray() || entries.isEmpty()) {
                return null;
            }
            JsonNode integratedTime = entries.get(0).path("integratedTime");
            if (integratedTime.isMissingNode() || integratedTime.isNull()) {
                return null;
            }
            return Instant.ofEpochSecond(integratedTime.asLong());
        } catch (JsonProcessingException | RuntimeException e) {
            return null;
        }
    }
}
