package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only registry of named artifact pattern groups, parsed from the
 * {@code artifacts} section of {@code sigmund.yaml}.
 * <p>
 * Provides group expansion for the {@code trust} and {@code unsigned} sections —
 * when a key matches a group name, it is expanded into the group's patterns.
 *
 * @see SigmundConfig
 */
public class ArtifactsConfig {

    /** Empty artifact groups. */
    public static final ArtifactsConfig EMPTY = new ArtifactsConfig(Map.of());

    private final Map<String, List<String>> groups;

    /**
     * Creates an artifact group registry from the given map.
     *
     * @param groups group names mapped to lists of artifact patterns
     */
    public ArtifactsConfig(Map<String, List<String>> groups) {
        this.groups = groups != null ? Map.copyOf(groups) : Map.of();
    }

    /**
     * Returns the patterns for the given group name, or {@code null} if not found.
     *
     * @param groupName the group name
     * @return the list of patterns, or {@code null}
     */
    public List<String> get(String groupName) {
        return groups.get(groupName);
    }

    /**
     * Returns whether this registry is empty.
     *
     * @return {@code true} if no groups are defined
     */
    public boolean isEmpty() {
        return groups.isEmpty();
    }

    /**
     * Expands a trust mappings map, replacing group-name keys with their patterns.
     * <p>
     * When a key matches a group name, each pattern in the group gets the
     * key's signer list. Literal pattern keys are preserved unchanged.
     *
     * @param rawTrust the raw trust mappings from the config
     * @return the expanded mappings with group names replaced by patterns
     */
    public Map<String, List<String>> expandTrustMappings(Map<String, List<String>> rawTrust) {
        if (groups.isEmpty()) {
            return rawTrust;
        }
        Map<String, List<String>> expanded = new LinkedHashMap<>();
        for (var entry : rawTrust.entrySet()) {
            List<String> patterns = groups.getOrDefault(entry.getKey(), List.of(entry.getKey()));
            for (String pattern : patterns) {
                expanded.merge(pattern, entry.getValue(), ArtifactsConfig::mergeUnique);
            }
        }
        return expanded;
    }

    /**
     * Expands a list of entries (e.g., unsigned patterns), replacing group names
     * with their patterns. Non-group entries are preserved as-is.
     *
     * @param entries the raw list of group names or literal patterns
     * @return the expanded list with group names replaced
     */
    public List<String> expandPatterns(List<String> entries) {
        if (groups.isEmpty()) {
            return entries;
        }
        List<String> expanded = new ArrayList<>();
        for (String entry : entries) {
            expanded.addAll(groups.getOrDefault(entry, List.of(entry)));
        }
        return expanded;
    }

    private static List<String> mergeUnique(List<String> existing, List<String> incoming) {
        var merged = new ArrayList<>(existing);
        for (String ref : incoming) {
            if (!merged.contains(ref)) {
                merged.add(ref);
            }
        }
        return Collections.unmodifiableList(merged);
    }
}
