package dev.cyberstamp.sigmund.core;

import java.io.Reader;
import java.nio.file.Path;

/**
 * Unified configuration parsed from a single YAML file ({@code sigmund.yaml}).
 * <p>
 * Produces separate typed objects for different consumers while keeping the
 * user's configuration in one place. {@code signers} is a top-level shared
 * registry of known identities — referenced by both the trust policy
 * (via rule clauses) and {@link SigningConfig} (via signer name).
 * <p>
 * The policy is held as a raw {@link TrustPolicySpec}: the parser produces it without resolving
 * signers or validating issuers, so that the signing path can read {@code signing}/{@code signers}/
 * {@code tools} without compiling it. The verification path compiles it with
 * {@link RulePolicy#compile(TrustPolicySpec, SignersConfig)} when the verifier is built.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * SigmundConfig config = SigmundConfig.parse(Path.of("sigmund.yaml"));
 * TrustPolicy policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
 * SigningConfig signing = config.signingConfig();
 * ToolsConfig tools = config.toolsConfig();
 * VerificationConfig verification = config.verificationConfig();
 * }</pre>
 *
 * @param signers shared identity registry
 * @param artifactSets named groups of artifact patterns for reuse in rule match entries
 * @param trustPolicySpec the raw trust policy parsed from the rules/defaults/issuers sections
 * @param signingConfig the signing configuration parsed from the signing section
 * @param toolsConfig the per-tool configuration registry parsed from the top-level tools section
 * @param verificationConfig the verification configuration parsed from the verification section
 * @see SigmundConfigParser
 */
public record SigmundConfig(
        SignersConfig signers,
        ArtifactSetsConfig artifactSets,
        TrustPolicySpec trustPolicySpec,
        SigningConfig signingConfig,
        ToolsConfig toolsConfig,
        VerificationConfig verificationConfig) {

    /**
     * The zero-config configuration, used when no {@code sigmund.yaml} exists: no signers, no
     * policy and default tool, signing and verification settings. Verification under it observes —
     * every artifact is verified and reported, and only {@link ArtifactOutcome#FAILED} blocks.
     */
    public static final SigmundConfig EMPTY = new SigmundConfig(null, null, null, null, null, null);

    /**
     * Creates a config with defensive defaults for null fields.
     */
    public SigmundConfig {
        if (signers == null) {
            signers = SignersConfig.EMPTY;
        }
        if (artifactSets == null) {
            artifactSets = ArtifactSetsConfig.EMPTY;
        }
        if (trustPolicySpec == null) {
            trustPolicySpec = TrustPolicySpec.EMPTY;
        }
        if (signingConfig == null) {
            signingConfig = SigningConfig.DEFAULT;
        }
        if (toolsConfig == null) {
            toolsConfig = ToolsConfig.EMPTY;
        }
        if (verificationConfig == null) {
            verificationConfig = VerificationConfig.DEFAULT;
        }
    }

    /**
     * Parses a {@code sigmund.yaml} configuration file.
     *
     * @param file the path to the YAML file
     * @return the parsed configuration
     * @throws PolicyConfigException if the file cannot be read or contains invalid configuration
     */
    public static SigmundConfig parse(Path file) {
        return SigmundConfigParser.parse(file);
    }

    /**
     * Parses configuration text, for checking a config that has not been written yet.
     *
     * @param source a human-readable name for the text, used in error messages
     * @param reader the YAML text
     * @return the parsed configuration
     * @throws PolicyConfigException if the text contains invalid configuration
     */
    public static SigmundConfig parse(String source, Reader reader) {
        return SigmundConfigParser.parse(source, reader);
    }
}
