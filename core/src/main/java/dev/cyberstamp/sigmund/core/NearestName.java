package dev.cyberstamp.sigmund.core;

import java.util.Collection;

/**
 * Suggests the known name a misspelled configuration name most likely meant, for "did you mean"
 * hints in configuration errors.
 *
 * <p>
 * Closeness is the Levenshtein edit distance. A candidate further than a few edits away is not
 * suggested, since an unrelated name offered as a correction misleads more than no suggestion.
 */
final class NearestName {

    private static final int MAX_SUGGESTION_DISTANCE = 3;

    private NearestName() {
    }

    /**
     * Finds the candidate closest to a name, within the suggestion distance.
     *
     * @param name the name as written
     * @param candidates the names that are defined
     * @return the closest candidate, or {@code null} when none is close enough
     */
    static String among(String name, Collection<String> candidates) {
        String best = null;
        int bestDistance = MAX_SUGGESTION_DISTANCE + 1;
        for (String candidate : candidates) {
            int distance = distance(name, candidate);
            if (distance < bestDistance) {
                best = candidate;
                bestDistance = distance;
            }
        }
        return best;
    }

    private static int distance(String a, String b) {
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int substitution = previous[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1);
                current[j] = Math.min(substitution, Math.min(previous[j], current[j - 1]) + 1);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }
}
