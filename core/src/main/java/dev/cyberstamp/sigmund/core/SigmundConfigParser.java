package dev.cyberstamp.sigmund.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Parses {@code sigmund.yaml} configuration files into {@link SigmundConfig}.
 * <p>
 * Maps YAML signer keys to {@link Credential}s:
 * <ul>
 * <li>{@code openpgp4} / {@code pgp4}, {@code openpgp6} / {@code pgp6} → {@link KeyCredential},
 * full fingerprints only</li>
 * <li>{@code email} → an {@link IdentityCredential} asserting {@code email}, vouched for by
 * one of the top-level {@code issuers}</li>
 * <li>{@code identities} → one {@link IdentityCredential} per entry: an optional
 * {@code issuer}, otherwise the top-level {@code issuers}, and the attributes it must
 * have attested</li>
 * </ul>
 * Identity entries and issuers are checked by {@link IdentityEntryValidator} when the policy is
 * compiled on the verification path, not at parse time, so the signing path never fails on a
 * verification-only semantic error. The parser only normalizes issuer names it recognizes and
 * keeps any other as written.
 */
class SigmundConfigParser {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private SigmundConfigParser() {
    }

    /**
     * Parses a sigmund.yaml file.
     *
     * @param file the path to the YAML file
     * @return the parsed configuration
     * @throws PolicyConfigException if the file cannot be read or is invalid
     */
    static SigmundConfig parse(Path file) {
        try (Reader reader = Files.newBufferedReader(file)) {
            return parse(file.toString(), reader);
        } catch (IOException e) {
            throw new PolicyConfigException("Failed to read config file: " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Parses a sigmund.yaml from a reader.
     *
     * @param source a human-readable description of the source (e.g., file path)
     * @param reader the YAML source
     * @return the parsed configuration
     * @throws PolicyConfigException if the content is invalid
     */
    static SigmundConfig parse(String source, Reader reader) {
        try {
            JsonNode root = YAML.readTree(reader);
            return parseRoot(root);
        } catch (IOException e) {
            throw new PolicyConfigException(
                    "Failed to parse config " + source + ": " + e.getMessage(), e);
        }
    }

    private static SigmundConfig parseRoot(JsonNode root) {
        if (root.has("trust")) {
            throw new PolicyConfigException(
                    "The 'trust' key is no longer supported; use 'rules' instead");
        }
        if (root.has("signature-optional")) {
            throw new PolicyConfigException(
                    "The 'signature-optional' key is no longer supported; use 'rules' with "
                            + "enforcement overrides (e.g., 'on-no-claim: ignore') instead");
        }
        if (root.has("policy")) {
            throw new PolicyConfigException(
                    "The 'policy' key is no longer supported; use 'rules' instead");
        }
        if (root.has("version")) {
            throw new PolicyConfigException(
                    "The 'version' key is no longer supported; remove it");
        }
        if (root.has("artifacts")) {
            throw new PolicyConfigException(
                    "The 'artifacts' key is no longer supported; use 'artifact-sets' instead");
        }

        rejectUnknownTopLevelKeys(root);

        SignersConfig signers = parseSigners(root.get("signers"));
        List<String> issuers = parseIssuers(root.get("issuers"));
        SigningConfig signingConfig = parseSigningConfig(root.get("signing"));
        ToolsConfig toolsConfig = parseToolsRegistry(root.get("tools"));
        VerificationConfig verificationConfig = parseVerificationConfig(root.get("verification"));

        ArtifactSetsConfig artifactSets = parseArtifactGroups(root.get("artifact-sets"));
        TrustPolicySpec trustPolicySpec = parseTrustPolicySpec(root, artifactSets, issuers);

        return new SigmundConfig(signers, artifactSets, trustPolicySpec,
                signingConfig, toolsConfig, verificationConfig);
    }

    private static final List<String> TOP_LEVEL_KEYS = List.of("issuers", "signers",
            "signing", "tools", "verification", "artifact-sets", "rules", "defaults");

    /**
     * Rejects top-level keys the schema does not define.
     * <p>
     * An ignored key would silently drop what the author wrote, and for the policy sections that
     * fails open: a misspelled {@code rules} would leave a file with no policy, which observes
     * rather than enforces.
     */
    private static void rejectUnknownTopLevelKeys(JsonNode root) {
        for (Map.Entry<String, JsonNode> field : root.properties()) {
            String key = field.getKey();
            if (!TOP_LEVEL_KEYS.contains(key)) {
                String suggestion = NearestName.among(key, TOP_LEVEL_KEYS);
                throw new PolicyConfigException("Unknown top-level key '" + key + "'"
                        + (suggestion == null
                                ? "; expected one of " + String.join(", ", TOP_LEVEL_KEYS)
                                : " — did you mean '" + suggestion + "'?"));
            }
        }
    }

    // --- Issuers ---

    private static List<String> parseIssuers(JsonNode node) {
        List<String> issuers = new ArrayList<>();
        for (String name : parseStringList(node)) {
            String canonical = IssuerKind.canonicalName(name);
            if (!issuers.contains(canonical)) {
                issuers.add(canonical);
            }
        }
        return List.copyOf(issuers);
    }

    // --- Signers ---

    private static SignersConfig parseSigners(JsonNode node) {
        if (node == null || node.isNull()) {
            return SignersConfig.EMPTY;
        }
        Map<String, SignerIdentity> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            result.put(entry.getKey(), parseSigner(entry.getKey(), entry.getValue()));
        }
        return new SignersConfig(result);
    }

    private static SignerIdentity parseSigner(String id, JsonNode node) {
        if (node.isTextual()) {
            return parseMinimalSigner(id, node.asText());
        }
        if (!node.isObject()) {
            throw new PolicyConfigException("Signer '" + id + "' must be a string or object");
        }
        return parseObjectSigner(id, node);
    }

    private static SignerIdentity parseMinimalSigner(String id, String email) {
        if (email.isBlank()) {
            throw new PolicyConfigException("Signer '" + id + "' must not be empty");
        }
        return new SignerIdentity(id, List.of(identity(id, null, Map.of(IdentityCredential.EMAIL, email))));
    }

    private static final String MEMBERS = "members";
    private static final String IDENTITIES = "identities";
    private static final String ISSUER = "issuer";
    private static final List<String> CREDENTIAL_KEYS = List.of(
            "pgp4", Credential.TYPE_OPENPGP_V4, "pgp6", Credential.TYPE_OPENPGP_V6,
            IdentityCredential.EMAIL, IDENTITIES);

    /**
     * Parses an object-form signer definition.
     * <p>
     * Supports three forms:
     * <ul>
     * <li><b>Single signer</b> — credentials ({@code pgp4}, {@code pgp6}, {@code email},
     * {@code identities}) at the top level</li>
     * <li><b>Organization with members</b> — a {@code members} array where each element
     * carries its own credentials, all aggregated into one signer identity</li>
     * <li><b>Mixed</b> — top-level credentials and {@code members} combined</li>
     * </ul>
     * At least one credential must be present across the top level and all members. Unknown
     * keys are errors: an ignored key would silently drop a credential the author wrote.
     *
     * @param id the signer identifier from the YAML key
     * @param node the YAML object node for this signer
     * @return the parsed signer identity with all collected credentials
     * @throws PolicyConfigException if no credentials are found, a key is unknown, or the
     *         members node is invalid
     */
    private static SignerIdentity parseObjectSigner(String id, JsonNode node) {
        List<String> known = new ArrayList<>(CREDENTIAL_KEYS);
        known.add(MEMBERS);
        rejectUnknownKeys(id, node, known);
        List<Credential> credentials = new ArrayList<>();

        addCredentialsFromNode(credentials, id, node);
        addMemberCredentials(credentials, id, node);

        if (credentials.isEmpty()) {
            throw new PolicyConfigException("Signer '" + id
                    + "' must have at least one credential (pgp4, pgp6, email or identities)");
        }

        return new SignerIdentity(id, credentials);
    }

    /**
     * Extracts all credentials ({@code pgp4}, {@code pgp6}, {@code email}, {@code identities})
     * from a single YAML node and appends them to the given list.
     *
     * @param credentials the list to append extracted credentials to
     * @param signerId the signer identifier, used for error messages
     * @param node the YAML node containing credential fields
     */
    private static void addCredentialsFromNode(List<Credential> credentials, String signerId,
            JsonNode node) {
        addKeyCredential(credentials, signerId, node, "pgp4", Credential.TYPE_OPENPGP_V4);
        addKeyCredential(credentials, signerId, node, Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V4);
        addKeyCredential(credentials, signerId, node, "pgp6", Credential.TYPE_OPENPGP_V6);
        addKeyCredential(credentials, signerId, node, Credential.TYPE_OPENPGP_V6, Credential.TYPE_OPENPGP_V6);
        addEmailCredential(credentials, signerId, node);
        addIdentities(credentials, signerId, node);
    }

    /**
     * Parses the {@code members} array of a signer definition, extracting credentials
     * from each member element and appending them to the given list.
     * <p>
     * Nested {@code members} inside a member element are rejected to prevent
     * silent misconfiguration.
     *
     * @param credentials the list to append member credentials to
     * @param signerId the signer identifier, used for error messages
     * @param node the signer YAML node that may contain a {@code members} array
     * @throws PolicyConfigException if {@code members} is present but not an array,
     *         or if a member element contains an unknown key or nested {@code members}
     */
    private static void addMemberCredentials(List<Credential> credentials, String signerId, JsonNode node) {
        JsonNode membersNode = node.get(MEMBERS);
        if (membersNode == null || membersNode.isNull()) {
            return;
        }
        if (!membersNode.isArray()) {
            throw new PolicyConfigException(
                    "Signer '" + signerId + "': 'members' must be an array");
        }
        for (JsonNode member : membersNode) {
            if (!member.isObject()) {
                throw new PolicyConfigException(
                        "Signer '" + signerId + "': each member must be an object");
            }
            if (member.has(MEMBERS)) {
                throw new PolicyConfigException(
                        "Signer '" + signerId + "': nested 'members' are not allowed");
            }
            rejectUnknownKeys(signerId, member, CREDENTIAL_KEYS);
            addCredentialsFromNode(credentials, signerId, member);
        }
    }

    private static void addKeyCredential(List<Credential> creds, String signerId,
            JsonNode node, String yamlKey, String keyType) {
        String value = textField(node, yamlKey);
        if (value == null) {
            return;
        }
        try {
            creds.add(new KeyCredential(keyType, value));
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException(
                    "Signer '" + signerId + "': '" + yamlKey + "' " + e.getMessage(), e);
        }
    }

    /**
     * Adds the {@code email} shorthand: an address vouched for by one of the listed issuers.
     */
    private static void addEmailCredential(List<Credential> creds, String signerId,
            JsonNode node) {
        JsonNode email = node.get(IdentityCredential.EMAIL);
        if (email == null || email.isNull()) {
            return;
        }
        if (!email.isTextual()) {
            throw new PolicyConfigException("Signer '" + signerId
                    + "': 'email' must be an address; to name its issuer, use 'identities'");
        }
        creds.add(identity(signerId, null, Map.of(IdentityCredential.EMAIL, email.asText())));
    }

    /**
     * Adds the {@code identities} list: each entry an optional {@code issuer} plus the
     * attributes it must have attested.
     */
    private static void addIdentities(List<Credential> creds, String signerId, JsonNode node) {
        JsonNode identities = node.get(IDENTITIES);
        if (identities == null || identities.isNull()) {
            return;
        }
        if (!identities.isArray()) {
            throw new PolicyConfigException("Signer '" + signerId + "': 'identities' must be a list");
        }
        for (JsonNode entry : identities) {
            if (!entry.isObject()) {
                throw new PolicyConfigException("Signer '" + signerId
                        + "': each identity must be a map of an optional 'issuer' and attributes");
            }
            creds.add(identity(signerId, inlineIssuer(entry), attributesOf(entry)));
        }
    }

    private static Map<String, String> attributesOf(JsonNode entry) {
        Map<String, String> attributes = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> field : entry.properties()) {
            if (!ISSUER.equals(field.getKey())) {
                attributes.put(field.getKey(), field.getValue().asText());
            }
        }
        return attributes;
    }

    private static String inlineIssuer(JsonNode entry) {
        String issuer = textField(entry, ISSUER);
        return issuer == null ? null : IssuerKind.canonicalName(issuer);
    }

    private static IdentityCredential identity(String signerId, String issuer,
            Map<String, String> attributes) {
        try {
            return new IdentityCredential(issuer, attributes);
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException("Signer '" + signerId
                    + "': an identity needs at least one attribute besides its issuer, "
                    + "each with a value", e);
        }
    }

    private static void rejectUnknownKeys(String signerId, JsonNode node, List<String> known) {
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            if (!known.contains(field.getKey())) {
                throw new PolicyConfigException("Signer '" + signerId + "': unknown key '"
                        + field.getKey() + "'; expected " + String.join(", ", known));
            }
        }
    }

    // --- Signing ---

    private static SigningConfig parseSigningConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return SigningConfig.DEFAULT;
        }
        String signer = textField(node, "signer");
        List<String> toolchain = parseStringList(node.get("toolchain"));
        List<String> credentialTypes = parseStringList(node.get("credential-types"));
        Map<String, List<String>> profiles = parseProfiles(node.get("profiles"));
        return new SigningConfig(signer, toolchain, credentialTypes, profiles);
    }

    private static Map<String, List<String>> parseProfiles(JsonNode node) {
        return parseStringListMap(node);
    }

    // --- Top-level Tools Registry ---

    /**
     * Parses the top-level {@code tools} section into a {@link ToolsConfig} registry.
     * <p>
     * Each tool entry maps a tool name to a {@link ToolConfig} containing optional
     * credentials and tool-specific settings.
     *
     * @param node the {@code tools} YAML node, or {@code null}
     * @return the parsed tool registry, or {@link ToolsConfig#EMPTY} if absent
     */
    private static ToolsConfig parseToolsRegistry(JsonNode node) {
        if (node == null || node.isNull()) {
            return ToolsConfig.EMPTY;
        }
        Map<String, ToolConfig> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            result.put(entry.getKey(), parseToolConfig(entry.getValue()));
        }
        return new ToolsConfig(result);
    }

    private static ToolConfig parseToolConfig(JsonNode node) {
        List<String> credentials = null;
        JsonNode credsNode = node.get("credentials");
        if (credsNode != null && credsNode.isArray()) {
            credentials = new ArrayList<>();
            for (JsonNode c : credsNode) {
                credentials.add(c.asText());
            }
        }

        Map<String, String> settings = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            if (!"credentials".equals(entry.getKey()) && entry.getValue().isValueNode()) {
                settings.put(entry.getKey(), entry.getValue().asText());
            }
        }
        return new ToolConfig(credentials, settings);
    }

    // --- Trust Policy (rules / defaults) ---

    /**
     * Parses the {@code rules} and {@code defaults} sections into a raw {@link TrustPolicySpec}.
     * <p>
     * This is structural only: {@code match} entries are resolved against the artifact-set names or
     * parsed as patterns, {@code requires} is normalized into a conjunction of disjunctions by
     * signer id, and the enforcement and extra-claims settings are read. Signer references are not
     * resolved and issuer assertability is not checked — those happen when the policy is compiled on
     * the verification path. The policy is {@code present} when the document declares
     * {@code rules} or {@code defaults}; a file that only configures signing, tools or signers
     * is zero-config for verification, which observes rather than enforces.
     *
     * @param root the document root
     * @param sets the parsed artifact-set registry, for {@code match} expansion
     * @param issuers the canonical default issuers
     * @return the raw trust policy spec
     * @throws PolicyConfigException if a rule, requirement, pattern or enforcement setting is
     *         structurally invalid
     */
    private static TrustPolicySpec parseTrustPolicySpec(JsonNode root, ArtifactSetsConfig sets,
            List<String> issuers) {
        JsonNode defaultsNode = root.get("defaults");
        List<RuleSpec> rules = parseRules(root.get("rules"), sets);
        ClaimSetMode extraClaims = parseExtraClaims(defaultsNode);
        Map<ArtifactOutcome, EnforcementAction> defaults = parseDefaults(defaultsNode);
        boolean declared = root.has("rules") || root.has("defaults");
        return new TrustPolicySpec(rules, extraClaims, defaults, issuers, declared);
    }

    private static List<RuleSpec> parseRules(JsonNode node, ArtifactSetsConfig sets) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            throw new PolicyConfigException("'rules' must be a list of rule objects");
        }
        List<RuleSpec> rules = new ArrayList<>();
        int index = 0;
        for (JsonNode ruleNode : node) {
            rules.add(parseRule(ruleNode, sets, "rules[" + index + "]"));
            index++;
        }
        return rules;
    }

    private static RuleSpec parseRule(JsonNode node, ArtifactSetsConfig sets, String location) {
        if (!node.isObject()) {
            throw new PolicyConfigException(location + " must be a rule object with 'match'");
        }
        List<ArtifactPattern> patterns = parseMatch(node.get("match"), sets, location);
        List<Set<String>> clauseIds = parseRequires(node.get("requires"), location);
        Map<ArtifactOutcome, EnforcementAction> enforcement = parseEnforcementOverrides(node, location);
        return new RuleSpec(patterns, clauseIds, enforcement, location);
    }

    private static List<ArtifactPattern> parseMatch(JsonNode node, ArtifactSetsConfig sets,
            String location) {
        if (node == null || node.isNull()) {
            throw new PolicyConfigException(location + ": a rule must declare 'match'");
        }
        List<String> entries = parseStringList(node);
        if (entries.isEmpty()) {
            throw new PolicyConfigException(
                    location + ": 'match' must list at least one artifact-set name or pattern");
        }
        List<ArtifactPattern> patterns = new ArrayList<>();
        for (String entry : entries) {
            List<String> expanded = sets.get(entry);
            if (expanded != null) {
                for (String pattern : expanded) {
                    patterns.add(ArtifactPattern.parse(pattern));
                }
            } else if (isBareWord(entry)) {
                throw new PolicyConfigException(undefinedSetMessage(entry, sets, location));
            } else {
                patterns.add(ArtifactPattern.parse(entry));
            }
        }
        return patterns;
    }

    /**
     * Indicates whether a {@code match} entry can only be an artifact-set reference.
     * <p>
     * A word with no {@code .}, {@code :} or {@code *} reads equally as a set name and as a
     * one-word group, so a misspelled set would silently become a group pattern matching nothing.
     * Such a word is therefore always a set reference, and a one-word group is written with an
     * artifact wildcard, {@code junit:*}.
     */
    private static boolean isBareWord(String entry) {
        return entry.indexOf('.') < 0 && entry.indexOf(':') < 0 && entry.indexOf('*') < 0;
    }

    private static String undefinedSetMessage(String entry, ArtifactSetsConfig sets,
            String location) {
        String suggestion = NearestName.among(entry, sets.names());
        return location + ": '" + entry + "' is not a defined artifact-set"
                + (suggestion == null ? "" : " — did you mean '" + suggestion + "'?")
                + "; to match a one-word group, write '" + entry + ":*'";
    }

    private static List<Set<String>> parseRequires(JsonNode node, String location) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            throw new PolicyConfigException(location
                    + ": 'requires' must be a list of clauses, not a scalar");
        }
        if (node.isEmpty()) {
            throw new PolicyConfigException(location + ": 'requires' must not be empty; to tolerate"
                    + " an artifact relax enforcement, e.g. 'on-no-claim: ignore'");
        }
        List<Set<String>> clauses = new ArrayList<>();
        for (JsonNode clauseNode : node) {
            clauses.add(parseClause(clauseNode, location));
        }
        return clauses;
    }

    private static Set<String> parseClause(JsonNode node, String location) {
        if (node.isTextual()) {
            return Set.of(signerReference(node, location));
        }
        if (node.isObject()) {
            return parseAnyOfClause(node, location);
        }
        throw new PolicyConfigException(location
                + ": a requirement clause must be a signer id or '{any-of: [...]}'");
    }

    private static Set<String> parseAnyOfClause(JsonNode node, String location) {
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            if (!"any-of".equals(field.getKey())) {
                throw new PolicyConfigException(location + ": unknown key '" + field.getKey()
                        + "' in a requirement clause; expected a signer id or 'any-of'");
            }
        }
        JsonNode anyOf = node.get("any-of");
        if (anyOf == null || !anyOf.isArray() || anyOf.isEmpty()) {
            throw new PolicyConfigException(location
                    + ": 'any-of' must list at least one signer id");
        }
        Set<String> ids = new LinkedHashSet<>();
        for (JsonNode element : anyOf) {
            ids.add(anyOfEntry(element, location));
        }
        return ids;
    }

    /**
     * Reads one {@code any-of} entry. A requirement is a conjunction of disjunctions, so an entry
     * is a signer id and nothing deeper: a mapping or a nested {@code any-of} has no meaning.
     */
    private static String anyOfEntry(JsonNode element, String location) {
        if (element.isObject() && element.has("any-of")) {
            throw new PolicyConfigException(location
                    + ": nested 'any-of' is not supported; list the signers in one 'any-of'");
        }
        if (!element.isValueNode() || element.isNull()) {
            throw new PolicyConfigException(location + ": 'any-of' entries must be signer ids; found "
                    + describe(element));
        }
        return signerReference(element, location);
    }

    private static String signerReference(JsonNode node, String location) {
        String id = node.asText();
        if (id.isBlank()) {
            throw new PolicyConfigException(location
                    + ": a signer reference must not be blank");
        }
        return id;
    }

    private static String describe(JsonNode node) {
        if (node.isObject()) {
            return "a mapping";
        }
        if (node.isArray()) {
            return "a list";
        }
        return node.isNull() ? "an empty value" : "'" + node.asText() + "'";
    }

    private static Map<ArtifactOutcome, EnforcementAction> parseEnforcementOverrides(JsonNode node,
            String location) {
        Map<ArtifactOutcome, EnforcementAction> enforcement = new EnumMap<>(ArtifactOutcome.class);
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            String key = field.getKey();
            if ("match".equals(key) || "requires".equals(key)) {
                continue;
            }
            if (!key.startsWith("on-")) {
                throw new PolicyConfigException(location + ": unknown key '" + key
                        + "'; expected 'match', 'requires' or an 'on-*' enforcement override");
            }
            enforcement.put(outcomeForEnforcementKey(key, location),
                    EnforcementAction.parse(field.getValue().asText()));
        }
        return enforcement;
    }

    private static ClaimSetMode parseExtraClaims(JsonNode defaultsNode) {
        if (defaultsNode == null || defaultsNode.isNull()) {
            return ClaimSetMode.ALL_CLAIMS;
        }
        String value = textField(defaultsNode, "extra-claims");
        if (value == null) {
            return ClaimSetMode.ALL_CLAIMS;
        }
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "reject" -> ClaimSetMode.ALL_CLAIMS;
            case "ignore" -> ClaimSetMode.ANY_CLAIM;
            default -> throw new PolicyConfigException("defaults: 'extra-claims' must be 'reject'"
                    + " or 'ignore', not '" + value + "'");
        };
    }

    private static Map<ArtifactOutcome, EnforcementAction> parseDefaults(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        if (!node.isObject()) {
            throw new PolicyConfigException("'defaults' must be a mapping");
        }
        Map<ArtifactOutcome, EnforcementAction> defaults = new EnumMap<>(ArtifactOutcome.class);
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            String key = field.getKey();
            if ("extra-claims".equals(key)) {
                continue;
            }
            if (!key.startsWith("on-")) {
                throw new PolicyConfigException("defaults: unknown key '" + key
                        + "'; expected 'extra-claims' or an 'on-*' enforcement default");
            }
            defaults.put(outcomeForEnforcementKey(key, "defaults"),
                    EnforcementAction.parse(field.getValue().asText()));
        }
        return defaults;
    }

    private static ArtifactOutcome outcomeForEnforcementKey(String key, String location) {
        return switch (key) {
            case "on-unsatisfied" -> ArtifactOutcome.UNSATISFIED;
            case "on-no-claim" -> ArtifactOutcome.NO_CLAIM;
            case "on-indeterminate" -> ArtifactOutcome.INDETERMINATE;
            case "on-not-configured" -> ArtifactOutcome.NOT_CONFIGURED;
            case "on-failed" -> throw new PolicyConfigException(location
                    + ": FAILED is always 'fail' and cannot be overridden; remove 'on-failed'");
            case "on-satisfied" -> throw new PolicyConfigException(location
                    + ": SATISFIED has no enforcement; remove 'on-satisfied'");
            default -> throw new PolicyConfigException(location + ": unknown enforcement override '"
                    + key + "'");
        };
    }

    // --- Artifact Groups ---

    private static ArtifactSetsConfig parseArtifactGroups(JsonNode node) {
        Map<String, List<String>> groups = parseStringListMap(node);
        return new ArtifactSetsConfig(groups);
    }

    private static Map<String, List<String>> parseStringListMap(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            result.put(entry.getKey(), parseStringList(entry.getValue()));
        }
        return result;
    }

    // --- Verification ---

    /**
     * Parses the {@code verification} section into a {@link VerificationConfig}.
     * <p>
     * Contains operational concerns: key fetching behavior, keyserver URLs,
     * and the verification toolchain priority.
     *
     * @param node the {@code verification} YAML node, or {@code null}
     * @return the parsed verification configuration
     */
    private static VerificationConfig parseVerificationConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return VerificationConfig.DEFAULT;
        }
        boolean resolveSigners = boolOrDefault(node, "resolve-signers", true);
        boolean importToKeyring = boolOrDefault(node, "import-to-keyring", false);
        List<String> keyservers = parseStringList(node.get("keyservers"));
        JsonNode tcNode = node.get("toolchain");
        List<String> toolchain = (tcNode != null && !tcNode.isNull()) ? parseStringList(tcNode) : null;
        return new VerificationConfig(resolveSigners, importToKeyring, keyservers, toolchain);
    }

    // --- Utilities ---

    private static List<String> parseStringList(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (node.isTextual()) {
            String text = node.asText();
            return text.isEmpty() ? List.of() : List.of(text);
        }
        if (!node.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (JsonNode el : node) {
            if (!el.isNull()) {
                result.add(el.asText());
            }
        }
        return Collections.unmodifiableList(result);
    }

    private static String textField(JsonNode node, String field) {
        JsonNode child = node.get(field);
        return child != null && !child.isNull() && child.isValueNode() ? child.asText() : null;
    }

    private static boolean boolOrDefault(JsonNode node, String field, boolean defaultValue) {
        JsonNode child = node.get(field);
        return child != null && !child.isNull() ? child.asBoolean() : defaultValue;
    }

}
