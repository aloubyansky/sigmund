package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Bridges Layer 2 (signature operations) to Layer 1 (identity verification).
 * <p>
 * Wraps a {@link SignatureFormat} and its associated {@link SignatureTool}s into an
 * {@link EvidenceProvider}. There is one adapter per format, not per tool — the adapter
 * parses the file once and routes each {@link VerificationUnit} to the right tool via
 * {@link SignatureTool#canVerify(VerificationUnit)}.
 *
 * <h3>Verification flow</h3>
 * <ol>
 * <li>{@link SignatureFormat#canHandle(Path)} → detection</li>
 * <li>{@link SignatureFormat#parse(Path)} → {@link VerificationUnit}s</li>
 * <li>For each unit, find a {@link SignatureTool} where {@code canVerify(unit)} is true</li>
 * <li>{@link SignatureTool#verify(Path, VerificationUnit)} → {@link VerifyResult}</li>
 * <li>If {@code NO_KEY}, ask the tool to fetch the key (if it implements {@link KeyImporter})
 * and re-verify; if still {@code NO_KEY}, continue to the next tool</li>
 * <li>{@link SignatureTool#extractCredentials(VerifyResult)} → proven credentials</li>
 * <li>Wrap into {@link EvidenceResult}</li>
 * </ol>
 *
 * <h3>Key fetching</h3>
 * <p>
 * Each tool owns its key fetching configuration (keyservers, persistence mode,
 * circuit breaker). The adapter simply asks the verifying tool to fetch a missing
 * key via {@link KeyImporter#fetchKey(String)}.
 *
 * @see EvidenceProvider
 * @see SignatureFormat
 * @see SignatureTool
 */
public class SignatureEvidenceAdapter implements EvidenceProvider {

    private final SignatureFormat format;
    private final List<SignatureTool> tools;

    /**
     * Creates a new adapter bridging the given format and tools into an evidence provider.
     *
     * @param format the signature format (e.g., {@link OpenPgpSignatureFormat})
     * @param tools the tools that can verify units of this format
     */
    public SignatureEvidenceAdapter(SignatureFormat format, List<SignatureTool> tools) {
        this.format = format;
        this.tools = List.copyOf(tools);
    }

    /**
     * {@inheritDoc}
     *
     * @return the name of the underlying {@link SignatureFormat}
     */
    @Override
    public String name() {
        return format.name();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} if at least one of the registered {@link SignatureTool}s
     * is available on the current system.
     */
    @Override
    public boolean isAvailable() {
        return tools.stream().anyMatch(SignatureTool::isAvailable);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates to the underlying {@link SignatureFormat#canHandle(Path)}.
     */
    @Override
    public boolean canHandle(Path evidenceFile) {
        return format.canHandle(evidenceFile);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Parses the evidence file into verification units, verifies each unit with
     * the appropriate tool, optionally fetches missing keys, and wraps results
     * into {@link EvidenceResult}s.
     */
    @Override
    public List<EvidenceResult> verify(Path artifactFile, Path evidenceFile) {
        List<VerificationUnit> units = parseUnits(evidenceFile);
        List<EvidenceResult> results = new ArrayList<>(units.size());
        for (VerificationUnit unit : units) {
            results.add(verifyUnit(artifactFile, unit));
        }
        return results;
    }

    /**
     * Parses the evidence file into individual verification units using the underlying format.
     *
     * @param evidenceFile path to the signature/evidence file
     * @return the parsed verification units
     */
    private List<VerificationUnit> parseUnits(Path evidenceFile) {
        return format.parse(evidenceFile);
    }

    /**
     * Verifies a single verification unit against the artifact file.
     * <p>
     * Routes the unit to each tool in priority order. If a tool returns
     * {@link Verdict#NO_KEY} and implements {@link KeyImporter}, the adapter
     * asks it to fetch the key and re-verifies. Only {@link Verdict#PASS}
     * stops iteration immediately; {@code NO_KEY} and {@code FAIL} fall
     * through to the next tool, keeping the highest-ranked non-PASS result.
     *
     * @param artifactFile the artifact whose signature is being verified
     * @param unit the verification unit to verify
     * @return the evidence result for this unit
     */
    private EvidenceResult verifyUnit(Path artifactFile, VerificationUnit unit) {
        EvidenceResult best = null;
        for (SignatureTool tool : tools) {
            if (!tool.canVerify(unit)) {
                continue;
            }
            VerifyResult result = tool.verify(artifactFile, unit);
            if (result.verdict() == Verdict.SKIPPED) {
                continue;
            }
            if (result.verdict() == Verdict.NO_KEY) {
                result = fetchKeyAndRetry(artifactFile, unit, tool, result);
            }
            if (result.verdict() == Verdict.PASS) {
                return wrapAsEvidence(tool, result);
            }
            if (best == null || result.verdict().outranks(best.verdict())) {
                best = wrapAsEvidence(tool, result);
            }
        }
        if (best != null) {
            return best;
        }
        return new EvidenceResult(new UnverifiedResult(Verdict.SKIPPED), List.of(), name());
    }

    /**
     * Attempts to fetch a missing key and re-verify with the same tool.
     * <p>
     * If the tool implements {@link KeyImporter}, asks it to fetch the key.
     * The tool handles keyserver iteration, circuit breaking, and persistence
     * internally. If the key is fetched, re-verifies with the same tool.
     *
     * @param artifactFile the artifact being verified
     * @param unit the verification unit whose key is missing
     * @param tool the tool to retry verification with
     * @param originalResult the original {@link Verdict#NO_KEY} result
     * @return the result of re-verification after import, or the original result if fetching failed
     */
    private VerifyResult fetchKeyAndRetry(Path artifactFile, VerificationUnit unit,
            SignatureTool tool, VerifyResult originalResult) {
        String keyId = extractKeyIdFromUnit(unit);
        if (keyId == null) {
            return originalResult;
        }

        if (tool instanceof KeyImporter ki && ki.fetchKey(keyId)) {
            return tool.verify(artifactFile, unit);
        }
        return originalResult;
    }

    /**
     * Extracts the key ID (fingerprint) from a verification unit, if available.
     *
     * @param unit the verification unit
     * @return the issuer fingerprint for OpenPGP units, or {@code null} for unsupported unit types
     */
    private String extractKeyIdFromUnit(VerificationUnit unit) {
        if (unit instanceof OpenPgpVerificationUnit opgu) {
            return opgu.issuerFingerprint();
        }
        return null;
    }

    /**
     * Wraps a verification result into an {@link EvidenceResult} by extracting
     * proven credentials from the tool.
     *
     * @param tool the tool that performed the verification
     * @param result the verification result to wrap
     * @return the evidence result containing the verification outcome and extracted credentials
     */
    private EvidenceResult wrapAsEvidence(SignatureTool tool, VerifyResult result) {
        List<Credential> credentials = tool.extractCredentials(result);
        return new EvidenceResult(result, credentials, name());
    }
}
