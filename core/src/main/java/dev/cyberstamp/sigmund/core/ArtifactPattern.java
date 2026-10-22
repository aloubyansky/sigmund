package dev.cyberstamp.sigmund.core;

import java.util.Objects;

/**
 * A parsed policy target: the coordinate pattern a rule matches artifacts against.
 *
 * <p>
 * Patterns are written as {@code group}, {@code group:artifact} or
 * {@code group:artifact:version}, where an omitted component matches anything. A component
 * may be {@code *} to match anything explicitly. A group may end in {@code .*} to match a
 * namespace and everything below it, so {@code org.apache.*} covers {@code org.apache} and
 * {@code org.apache.maven} but not {@code org.apachex}. An artifact or version ending in
 * {@code *} is a plain prefix of everything before the {@code *}, dot included, so
 * {@code 1.*} covers {@code 1.0} and {@code 1.2.3} but not {@code 10.0} or {@code 1}.
 *
 * <p>
 * Patterns stop at the version. Classifier and extension are deliberately not policy
 * dimensions: every file published under one coordinate — jar, pom, sources, javadoc —
 * comes from the same module build and shares its signer, so a rule that accepted a
 * classifier would suggest a distinction the trust model does not make. A pattern carrying
 * more than three components is a configuration error rather than a pattern that silently
 * matches nothing.
 *
 * <p>
 * Parsing happens once, when policy is loaded, so that malformed patterns surface as
 * configuration errors at load time instead of as silent mismatches during a build, and so
 * that matching an artifact costs no string splitting.
 */
public final class ArtifactPattern {

    private static final String ANY = "*";
    private static final String PREFIX_WILDCARD = ".*";

    private final String namespace;
    private final String name;
    private final String version;
    private final String text;

    private ArtifactPattern(String namespace, String name, String version, String text) {
        this.namespace = namespace;
        this.name = name;
        this.version = version;
        this.text = text;
    }

    /**
     * Parses a coordinate pattern.
     *
     * @param pattern the pattern text, one to three colon-separated components
     * @return the parsed pattern
     * @throws PolicyConfigException if the pattern is blank or carries more components than
     *         group, artifact and version
     */
    public static ArtifactPattern parse(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            throw new PolicyConfigException("Artifact pattern must not be blank");
        }
        String text = pattern.trim();
        String[] parts = text.split(":", -1);
        return switch (parts.length) {
            case 1 -> new ArtifactPattern(parts[0], ANY, ANY, text);
            case 2 -> new ArtifactPattern(parts[0], parts[1], ANY, text);
            case 3 -> new ArtifactPattern(parts[0], parts[1], parts[2], text);
            default -> throw new PolicyConfigException(
                    "Artifact pattern '" + text + "' matches on group, artifact and version only;"
                            + " classifier and extension are not policy dimensions");
        };
    }

    /**
     * Builds the pattern covering every file published under an artifact's module.
     *
     * <p>
     * Version, classifier and extension are dropped, so the pattern matches the module's
     * jar, pom, sources and javadoc alike, and every version of them. This is the shape
     * bootstrap generates when it turns observed signers into policy: trust is stated per
     * module, not per released file.
     *
     * @param coords the artifact whose module should be covered
     * @return a pattern matching {@code group:artifact}
     */
    public static ArtifactPattern forModule(ArtifactCoords coords) {
        return new ArtifactPattern(coords.namespace(), coords.name(), ANY,
                coords.namespace() + ":" + coords.name());
    }

    /**
     * Indicates whether this pattern applies to an artifact.
     *
     * <p>
     * Only the group, artifact and version are considered. Classifier and extension are
     * ignored, so a rule written for a module covers every file published under it.
     *
     * @param coords the artifact's coordinate
     * @return {@code true} when the pattern applies
     */
    public boolean matches(ArtifactCoords coords) {
        return coords != null
                && matchesNamespace(coords.namespace())
                && matchesComponent(name, coords.name())
                && matchesComponent(version, coords.version());
    }

    /**
     * Scores how specific this pattern is, so that the most specific rule wins when several
     * apply.
     *
     * <p>
     * The group dominates: it scores ten per namespace segment, with an exact group
     * outranking the prefix wildcard that contains it. Artifact and version add two for an
     * exact match and one for a prefix wildcard, so a named artifact outranks a wildcard
     * within the same group and a versioned rule outranks an unversioned one. A pattern
     * that matches everything scores zero.
     *
     * @return the specificity score, never negative
     */
    public int specificity() {
        return namespaceSpecificity() + componentSpecificity(name) + componentSpecificity(version);
    }

    private boolean matchesNamespace(String value) {
        if (ANY.equals(namespace)) {
            return true;
        }
        if (namespace.endsWith(PREFIX_WILDCARD)) {
            String prefix = namespace.substring(0, namespace.length() - PREFIX_WILDCARD.length());
            return value.equals(prefix) || value.startsWith(prefix + ".");
        }
        return namespace.equals(value);
    }

    private static boolean matchesComponent(String pattern, String value) {
        if (ANY.equals(pattern)) {
            return true;
        }
        if (pattern.endsWith(ANY)) {
            return value.startsWith(componentPrefix(pattern));
        }
        return pattern.equals(value);
    }

    private static String componentPrefix(String pattern) {
        return pattern.substring(0, pattern.length() - 1);
    }

    /**
     * Indicates whether some coordinate is matched by both this pattern and another.
     *
     * <p>
     * A pattern matches a coordinate only when its group, artifact and version each match,
     * so the coordinates it matches are the product of three independent sets, and two
     * patterns share a coordinate exactly when every pair of components shares a value. Each
     * component has only three shapes — anything, an exact value, and a prefix (for the group,
     * a dot-bounded subtree) — so the answer is exact rather than a heuristic.
     *
     * @param other the pattern to compare with
     * @return {@code true} when at least one coordinate matches both patterns
     */
    boolean overlaps(ArtifactPattern other) {
        return commonNamespace(namespace, other.namespace) != null
                && commonComponent(name, other.name) != null
                && commonComponent(version, other.version) != null;
    }

    /**
     * Returns a coordinate both patterns match, as {@code group:artifact:version}, for naming the
     * conflict in configuration errors.
     *
     * <p>
     * Each component is the narrower side's value: the exact value, the longer prefix, or the
     * deeper subtree root. A component left open by both patterns is written {@code *}.
     *
     * @param other the pattern to compare with
     * @return a coordinate both patterns match, or {@code null} when they share none
     */
    String commonCoordinate(ArtifactPattern other) {
        if (!overlaps(other)) {
            return null;
        }
        return commonNamespace(namespace, other.namespace) + ":"
                + commonComponent(name, other.name) + ":"
                + commonComponent(version, other.version);
    }

    private static String commonNamespace(String a, String b) {
        if (ANY.equals(a)) {
            return b.endsWith(PREFIX_WILDCARD) ? subtreeRoot(b) : b;
        }
        if (ANY.equals(b)) {
            return commonNamespace(b, a);
        }
        String rootA = a.endsWith(PREFIX_WILDCARD) ? subtreeRoot(a) : null;
        String rootB = b.endsWith(PREFIX_WILDCARD) ? subtreeRoot(b) : null;
        if (rootA == null && rootB == null) {
            return a.equals(b) ? a : null;
        }
        if (rootA == null) {
            return withinSubtree(a, rootB) ? a : null;
        }
        if (rootB == null) {
            return withinSubtree(b, rootA) ? b : null;
        }
        if (withinSubtree(rootA, rootB)) {
            return rootA;
        }
        return withinSubtree(rootB, rootA) ? rootB : null;
    }

    private static String subtreeRoot(String namespacePattern) {
        return namespacePattern.substring(0, namespacePattern.length() - PREFIX_WILDCARD.length());
    }

    private static boolean withinSubtree(String value, String root) {
        return value.equals(root) || value.startsWith(root + ".");
    }

    private static String commonComponent(String a, String b) {
        if (ANY.equals(a)) {
            return ANY.equals(b) ? ANY : b.endsWith(ANY) ? componentPrefix(b) : b;
        }
        if (ANY.equals(b)) {
            return commonComponent(b, a);
        }
        boolean prefixA = a.endsWith(ANY);
        boolean prefixB = b.endsWith(ANY);
        if (!prefixA && !prefixB) {
            return a.equals(b) ? a : null;
        }
        if (!prefixA) {
            return a.startsWith(componentPrefix(b)) ? a : null;
        }
        if (!prefixB) {
            return b.startsWith(componentPrefix(a)) ? b : null;
        }
        String longer = a.length() >= b.length() ? componentPrefix(a) : componentPrefix(b);
        String shorter = a.length() >= b.length() ? componentPrefix(b) : componentPrefix(a);
        return longer.startsWith(shorter) ? longer : null;
    }

    private int namespaceSpecificity() {
        if (ANY.equals(namespace)) {
            return 0;
        }
        if (namespace.endsWith(PREFIX_WILDCARD)) {
            String prefix = namespace.substring(0, namespace.length() - PREFIX_WILDCARD.length());
            return countSegments(prefix) * 10;
        }
        return (countSegments(namespace) + 1) * 10;
    }

    private static int componentSpecificity(String pattern) {
        if (ANY.equals(pattern)) {
            return 0;
        }
        return pattern.endsWith(ANY) ? 1 : 2;
    }

    private static int countSegments(String value) {
        int count = 1;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }

    /**
     * Returns the pattern as it was written in the policy, so reports and errors quote the
     * user's own text.
     *
     * @return the original pattern text
     */
    @Override
    public String toString() {
        return text;
    }

    /**
     * Compares patterns by what they match, ignoring how they were written.
     *
     * @param o the object to compare with
     * @return {@code true} when both patterns match the same coordinates
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        return o instanceof ArtifactPattern other
                && namespace.equals(other.namespace)
                && name.equals(other.name)
                && version.equals(other.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(namespace, name, version);
    }
}
