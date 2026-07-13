package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.CredentialParser;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignerInspectionReport;
import dev.cyberstamp.sigmund.core.SignerInspectionReportFormatter;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * CLI command that inspects a signer identity across all available sources.
 *
 * <p>
 * Takes a signer identifier (fingerprint, email, or Sigstore identity) as input,
 * queries local stores and HKP keyservers, and prints a per-source report
 * showing key metadata, User IDs, and where the key was found vs. not found.
 *
 * <p>
 * The identifier is auto-detected by default: hex strings are treated as
 * fingerprints, strings containing {@code @} as emails. Explicit
 * {@code --fingerprint} or {@code --email} flags override auto-detection.
 * Sigstore identities require both {@code --sigstore-issuer} and {@code --sigstore-subject}.
 *
 * @see SignerInspectionReportFormatter
 */
@Command(name = "inspect-signer", description = "Inspect a signer identity across available sources", mixinStandardHelpOptions = true)
public class InspectSignerCommand implements Callable<Integer> {

    @Parameters(index = "0", arity = "0..1", description = "Signer identifier (fingerprint or email, auto-detected)")
    String identifier;

    @Option(names = "--fingerprint", description = "Treat identifier as a fingerprint")
    boolean forceFingerprint;

    @Option(names = "--email", description = "Treat identifier as an email")
    boolean forceEmail;

    @Option(names = "--sigstore-issuer", description = "Sigstore certificate OIDC issuer URL")
    String sigstoreIssuer;

    @Option(names = "--sigstore-subject", description = "Sigstore certificate SAN subject")
    String sigstoreSubject;

    @Option(names = { "--keyservers", "--keyserver" }, split = ",", description = "Keyservers to query (comma-separated)")
    List<String> keyservers;

    @Option(names = "--tool", description = "Tool to use (bc, sq, gpg)")
    String tool;

    @Mixin
    SqHomeMixin sqHomeMixin;

    @Mixin
    ConfigMixin configMixin;

    @Override
    public Integer call() {
        try {
            Credential credential = buildCredential();
            try (Sigmund sigmund = buildSigmund()) {
                SignerInspectionReport report = sigmund.inspectSigner(credential, tool);
                SignerInspectionReportFormatter.format(report, System.out::println);
                return 0;
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Inspection failed: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Builds a {@link Credential} from the command-line arguments.
     *
     * <p>
     * Priority: Sigstore (if both issuer and subject are set) → forced email →
     * forced fingerprint → auto-detection via {@link CredentialParser#parse}.
     *
     * @return the parsed credential
     * @throws IllegalArgumentException if no identifier was provided or it cannot be parsed
     */
    Credential buildCredential() {
        if (sigstoreIssuer != null && sigstoreSubject != null) {
            return CredentialParser.fromSigstore(sigstoreIssuer, sigstoreSubject);
        }
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException(
                    "Provide a fingerprint or email as a positional argument, "
                            + "or use --sigstore-issuer and --sigstore-subject");
        }
        if (forceEmail) {
            return CredentialParser.fromEmail(identifier);
        }
        if (forceFingerprint) {
            return CredentialParser.fromFingerprint(identifier);
        }
        return CredentialParser.parse(identifier);
    }

    private Sigmund buildSigmund() {
        SigmundConfig config = loadConfigSafely();

        DiscoveryConfig fileDiscovery = config != null && config.discoveryConfig() != null
                ? config.discoveryConfig()
                : DiscoveryConfig.DEFAULT;
        ToolsConfig fileTools = config != null && config.toolsConfig() != null
                ? config.toolsConfig()
                : ToolsConfig.EMPTY;

        List<String> effectiveServers = keyservers != null
                ? keyservers
                : fileDiscovery.keyservers();
        boolean effectiveResolve = keyservers != null || fileDiscovery.resolveSigners();

        DiscoveryConfig discoveryConfig = new DiscoveryConfig(
                effectiveResolve, fileDiscovery.importToKeyring(),
                effectiveServers, fileDiscovery.toolchain());

        ToolsConfig toolsConfig = mergeSquoiaHome(fileTools);

        return Sigmund.builder()
                .discoveryConfig(discoveryConfig)
                .toolsConfig(toolsConfig)
                .build();
    }

    /**
     * Loads the config, returning {@code null} on failure instead of throwing.
     */
    private SigmundConfig loadConfigSafely() {
        try {
            return configMixin.loadConfig();
        } catch (Exception e) {
            System.err.println("WARNING: Could not load config: " + e.getMessage());
            return null;
        }
    }

    /**
     * Merges Sequoia home override into the tools config if specified.
     */
    private ToolsConfig mergeSquoiaHome(ToolsConfig base) {
        if (sqHomeMixin.resolveSequoiaHome() == null) {
            return base;
        }
        Map<String, ToolConfig> merged = new HashMap<>();
        for (String name : base.toolNames()) {
            merged.put(name, base.get(name));
        }
        merged.put("sq", new ToolConfig(null,
                Map.of("home", sqHomeMixin.resolveSequoiaHome().toString())));
        return new ToolsConfig(merged);
    }
}
