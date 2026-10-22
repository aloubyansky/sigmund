package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Read-only registry of named artifact pattern groups, parsed from the
 * {@code artifact-sets} section of {@code sigmund.yaml}.
 * <p>
 * A rule's {@code match} entry may name a group: the parser looks it up with {@link #get(String)}
 * and expands it into the group's patterns.
 *
 * @see SigmundConfig
 */
public class ArtifactSetsConfig {

    /** Empty artifact groups. */
    public static final ArtifactSetsConfig EMPTY = new ArtifactSetsConfig(Map.of());

    private final Map<String, List<String>> groups;

    /**
     * Creates an artifact group registry from the given map.
     *
     * @param groups group names mapped to lists of artifact patterns
     */
    public ArtifactSetsConfig(Map<String, List<String>> groups) {
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
     * Returns the names of the defined groups.
     *
     * @return the group names
     */
    public Set<String> names() {
        return groups.keySet();
    }

    /**
     * Returns whether this registry is empty.
     *
     * @return {@code true} if no groups are defined
     */
    public boolean isEmpty() {
        return groups.isEmpty();
    }
}
