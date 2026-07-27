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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses {@code sigmund.yaml} configuration files into {@link SigmundConfig}.
 * <p>
 * Maps YAML signer keys to {@link Credential} types:
 * <ul>
 * <li>{@code openpgp4} / {@code pgp4} → {@link FingerprintCredential}("openpgp4", ...)</li>
 * <li>{@code openpgp6} / {@code pgp6} → {@link FingerprintCredential}("openpgp6", ...)</li>
 * <li>{@code email} → {@link EmailCredential}</li>
 * <li>{@code oidc} → {@link OidcCredential}(issuer, subject)</li>
 * </ul>
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
            return parse(reader);
        } catch (IOException e) {
            throw new PolicyConfigException("Failed to read config file: " + file, e);
        }
    }

    /**
     * Parses a sigmund.yaml from a reader.
     *
     * @param reader the YAML source
     * @return the parsed configuration
     * @throws PolicyConfigException if the content is invalid
     */
    static SigmundConfig parse(Reader reader) {
        try {
            JsonNode root = YAML.readTree(reader);
            return parseRoot(root);
        } catch (IOException e) {
            throw new PolicyConfigException("Failed to parse config", e);
        }
    }

    private static SigmundConfig parseRoot(JsonNode root) {
        int version = root.has("version") ? root.get("version").asInt(1) : 1;
        Map<String, SignerIdentity> signers = parseSigners(root.get("signers"));
        SigningConfig signingConfig = parseSigningConfig(root.get("signing"));
        ToolsConfig toolsConfig = parseToolsConfig(root.get("discovery"));

        Map<String, List<String>> artifactGroups = parseArtifactGroups(root.get("artifacts"));
        Map<String, List<String>> rawTrust = parseTrustSection(root.get("trust"));
        Map<String, List<String>> expandedTrust = expandArtifactGroups(rawTrust, artifactGroups);
        List<String> rawUnsigned = parseStringList(root.get("unsigned"));
        List<String> expandedUnsigned = expandUnsignedGroups(rawUnsigned, artifactGroups);
        boolean requireAll = boolField(root, "policy", "require-all-evidence-match", true);
        UntrustedPolicy untrustedPolicy = parseUntrustedPolicy(root);

        Map<String, List<SignerIdentity>> trustMappings = DefaultTrustPolicy.resolveTrustMappings(expandedTrust, signers);
        TrustPolicy trustPolicy = new DefaultTrustPolicy(
                trustMappings, expandedUnsigned, requireAll, untrustedPolicy);

        return new SigmundConfig(version, signers, artifactGroups, trustPolicy, signingConfig, toolsConfig);
    }

    // --- Signers ---

    private static Map<String, SignerIdentity> parseSigners(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, SignerIdentity> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseSigner(entry.getKey(), entry.getValue()));
        }
        return result;
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
        return new SignerIdentity(id, id, List.of(new EmailCredential(email)));
    }

    private static SignerIdentity parseObjectSigner(String id, JsonNode node) {
        String displayName = textField(node, "name");
        List<Credential> credentials = new ArrayList<>();

        addFingerprintCredential(credentials, node, Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V4);
        addFingerprintCredential(credentials, node, "pgp4", Credential.TYPE_OPENPGP_V4);
        addFingerprintCredential(credentials, node, Credential.TYPE_OPENPGP_V6, Credential.TYPE_OPENPGP_V6);
        addFingerprintCredential(credentials, node, "pgp6", Credential.TYPE_OPENPGP_V6);
        addEmailCredential(credentials, node);
        addOidcCredential(credentials, node);

        if (credentials.isEmpty()) {
            throw new PolicyConfigException(
                    "Signer '" + id + "' must have at least one credential (pgp4, pgp6, email, or oidc)");
        }

        return new SignerIdentity(id, displayName != null ? displayName : id, credentials);
    }

    private static void addFingerprintCredential(List<Credential> creds, JsonNode node,
            String yamlKey, String credType) {
        String value = textField(node, yamlKey);
        if (value != null) {
            creds.add(new FingerprintCredential(credType, value));
        }
    }

    private static void addEmailCredential(List<Credential> creds, JsonNode node) {
        String email = textField(node, "email");
        if (email != null) {
            creds.add(new EmailCredential(email));
        }
    }

    private static void addOidcCredential(List<Credential> creds, JsonNode node) {
        JsonNode oidcNode = node.get("oidc");
        if (oidcNode == null || oidcNode.isNull()) {
            return;
        }
        if (oidcNode.isObject()) {
            String issuer = textField(oidcNode, "issuer");
            String subject = textField(oidcNode, "subject");
            if (issuer != null && subject != null) {
                creds.add(new OidcCredential(issuer, subject));
            }
        }
    }

    // --- Signing ---

    private static SigningConfig parseSigningConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return SigningConfig.DEFAULT;
        }
        String signer = textField(node, "signer");
        Map<String, ToolConfig> tools = parseToolConfigs(node.get("tools"));
        Map<String, List<String>> profiles = parseProfiles(node.get("profiles"));
        String defaultProfile = textField(node, "default-profile");
        return new SigningConfig(signer, tools, profiles, defaultProfile);
    }

    private static Map<String, ToolConfig> parseToolConfigs(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, ToolConfig> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseToolConfig(entry.getValue()));
        }
        return result;
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
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            if (!"credentials".equals(entry.getKey()) && entry.getValue().isValueNode()) {
                settings.put(entry.getKey(), entry.getValue().asText());
            }
        }
        return new ToolConfig(credentials, settings);
    }

    private static Map<String, List<String>> parseProfiles(JsonNode node) {
        return parseStringListMap(node);
    }

    // --- Trust ---

    private static Map<String, List<String>> parseTrustSection(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseSignerRefs(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    private static List<String> parseSignerRefs(String key, JsonNode node) {
        if (node.isTextual()) {
            return List.of(node.asText());
        }
        if (node.isArray()) {
            List<String> refs = new ArrayList<>();
            for (JsonNode el : node) {
                refs.add(el.asText());
            }
            return Collections.unmodifiableList(refs);
        }
        throw new PolicyConfigException(
                "Trust entry '" + key + "' must be a string or array of strings");
    }

    private static UntrustedPolicy parseUntrustedPolicy(JsonNode root) {
        JsonNode policy = root.get("policy");
        if (policy == null || policy.isNull()) {
            return UntrustedPolicy.FAIL;
        }
        String value = textField(policy, "on-untrusted");
        if (value == null || "fail".equalsIgnoreCase(value)) {
            return UntrustedPolicy.FAIL;
        }
        if ("warn".equalsIgnoreCase(value)) {
            return UntrustedPolicy.WARN;
        }
        throw new PolicyConfigException("Invalid on-untrusted value: '" + value + "' (must be 'fail' or 'warn')");
    }

    // --- Artifact Groups ---

    private static Map<String, List<String>> parseArtifactGroups(JsonNode node) {
        return parseStringListMap(node);
    }

    private static Map<String, List<String>> parseStringListMap(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseStringList(entry.getValue()));
        }
        return result;
    }

    private static Map<String, List<String>> expandArtifactGroups(
            Map<String, List<String>> rawTrust,
            Map<String, List<String>> artifactGroups) {
        if (artifactGroups.isEmpty()) {
            return rawTrust;
        }
        Map<String, List<String>> expanded = new LinkedHashMap<>();
        for (var entry : rawTrust.entrySet()) {
            List<String> patterns = artifactGroups.getOrDefault(entry.getKey(), List.of(entry.getKey()));
            for (String pattern : patterns) {
                expanded.merge(pattern, entry.getValue(), (existing, incoming) -> {
                    var merged = new ArrayList<>(existing);
                    for (String ref : incoming) {
                        if (!merged.contains(ref)) {
                            merged.add(ref);
                        }
                    }
                    return Collections.unmodifiableList(merged);
                });
            }
        }
        return expanded;
    }

    private static List<String> expandUnsignedGroups(
            List<String> rawUnsigned,
            Map<String, List<String>> artifactGroups) {
        if (artifactGroups.isEmpty()) {
            return rawUnsigned;
        }
        List<String> expanded = new ArrayList<>();
        for (String entry : rawUnsigned) {
            expanded.addAll(artifactGroups.getOrDefault(entry, List.of(entry)));
        }
        return expanded;
    }

    // --- Discovery ---

    private static ToolsConfig parseToolsConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return ToolsConfig.DEFAULT;
        }
        boolean resolveSigners = node.has("resolve-signers")
                ? boolOrDefault(node, "resolve-signers", true)
                : boolOrDefault(node, "fetch-signer-info", true);
        boolean importToKeyring = boolOrDefault(node, "import-to-keyring", false);
        List<String> keyservers = parseStringList(node.get("keyservers"));
        Map<String, Map<String, String>> tools = parseDiscoveryTools(node.get("tools"));
        JsonNode tpNode = node.get("tool-priority");
        List<String> toolPriority = (tpNode != null && !tpNode.isNull()) ? parseStringList(tpNode) : null;
        return new ToolsConfig(resolveSigners, importToKeyring, keyservers, tools, toolPriority);
    }

    private static Map<String, Map<String, String>> parseDiscoveryTools(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, Map<String, String>> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            Map<String, String> settings = new LinkedHashMap<>();
            Iterator<Map.Entry<String, JsonNode>> toolFields = entry.getValue().fields();
            while (toolFields.hasNext()) {
                Map.Entry<String, JsonNode> tf = toolFields.next();
                settings.put(tf.getKey(), tf.getValue().asText());
            }
            result.put(entry.getKey(), Map.copyOf(settings));
        }
        return result;
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

    private static boolean boolField(JsonNode root, String section, String field, boolean defaultValue) {
        JsonNode sectionNode = root.get(section);
        if (sectionNode == null || sectionNode.isNull()) {
            return defaultValue;
        }
        return boolOrDefault(sectionNode, field, defaultValue);
    }
}
