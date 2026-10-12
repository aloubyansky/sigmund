package dev.cyberstamp.sigmund.plugin;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Removes patterns from a rule's {@code match} list in the text of a {@code sigmund.yaml},
 * leaving every other line as written.
 *
 * <p>
 * Updating a config moves a module out of the rule that tolerated it unsigned once it starts
 * being signed; left in place, the identical pattern in the new requirement rule would tie with
 * it. Only the shape bootstrap writes is edited — a top-level {@code rules:} sequence whose rule
 * carries a single-line flow list, {@code match: [a, b]}, with no comment on the line. Anything
 * else is left alone and reported as not editable, because rewriting YAML someone formatted by
 * hand is where a line-based edit goes wrong.
 */
final class RuleListEditor {

    private static final String RULES = "rules:";
    private static final String MATCH = "match:";

    private RuleListEditor() {
    }

    /**
     * Removes patterns from the {@code match} list of one rule, all or nothing.
     *
     * <p>
     * When no pattern would remain the whole rule item is removed, since a rule must match
     * something.
     *
     * @param lines the config file lines, mutated only when every pattern was removed
     * @param ruleIndex the rule's position in the {@code rules} sequence, as in {@code rules[2]}
     * @param patterns the patterns to remove, as written in the list
     * @return {@code true} when every pattern was found and removed; {@code false} when the rule
     *         or its list does not have the editable shape or lacks one of the patterns
     */
    static boolean removeFromMatch(List<String> lines, int ruleIndex, Collection<String> patterns) {
        int[] item = findRuleItem(lines, ruleIndex);
        if (item == null) {
            return false;
        }
        int matchLine = findMatchLine(lines, item[0], item[1]);
        if (matchLine < 0) {
            return false;
        }
        List<String> entries = flowEntries(lines.get(matchLine));
        if (entries == null
                || !entries.stream().map(RuleListEditor::unquote).toList().containsAll(patterns)) {
            return false;
        }
        List<String> remaining = new ArrayList<>(entries);
        remaining.removeIf(entry -> patterns.contains(unquote(entry)));
        if (remaining.isEmpty()) {
            lines.subList(item[0], item[1]).clear();
        } else {
            lines.set(matchLine, rewriteMatch(lines.get(matchLine), remaining));
        }
        return true;
    }

    /**
     * Parses a rule's position from its location, as recorded on a compiled rule.
     *
     * @param location a location such as {@code rules[2]}
     * @return the index, or {@code -1} when the location has another shape
     */
    static int ruleIndex(String location) {
        if (location == null || !location.startsWith("rules[") || !location.endsWith("]")) {
            return -1;
        }
        try {
            return Integer.parseInt(location.substring("rules[".length(), location.length() - 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Finds the line range of one item of the top-level {@code rules} sequence.
     *
     * @return the first line and the line after the last, or {@code null} when not found
     */
    private static int[] findRuleItem(List<String> lines, int ruleIndex) {
        int header = lines.indexOf(RULES);
        if (header < 0 || ruleIndex < 0) {
            return null;
        }
        int itemIndent = -1;
        int seen = -1;
        int start = -1;
        for (int i = header + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (isSectionEnd(line)) {
                return start >= 0 ? new int[] { start, trimTrailingBlank(lines, start, i) } : null;
            }
            String trimmed = line.stripLeading();
            int indent = line.length() - trimmed.length();
            if (!trimmed.startsWith("- ") || (itemIndent >= 0 && indent != itemIndent)) {
                continue;
            }
            itemIndent = indent;
            seen++;
            if (start >= 0) {
                return new int[] { start, trimTrailingBlank(lines, start, i) };
            }
            if (seen == ruleIndex) {
                start = i;
            }
        }
        return start >= 0 ? new int[] { start, trimTrailingBlank(lines, start, lines.size()) } : null;
    }

    private static boolean isSectionEnd(String line) {
        return !line.isEmpty() && !line.startsWith(" ") && !line.startsWith("#")
                && !line.startsWith("-");
    }

    private static int trimTrailingBlank(List<String> lines, int start, int end) {
        while (end > start + 1 && lines.get(end - 1).isBlank()) {
            end--;
        }
        return end;
    }

    private static int findMatchLine(List<String> lines, int start, int end) {
        for (int i = start; i < end; i++) {
            String key = lines.get(i).stripLeading();
            if (key.startsWith("- ")) {
                key = key.substring(2).stripLeading();
            }
            if (key.startsWith(MATCH)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Reads a single-line flow list after {@code match:}, each entry as written, so that a
     * rewritten list keeps the quoting an entry such as {@code "*"} needs.
     *
     * @return the entries, or {@code null} when the value is not a single-line flow list
     */
    private static List<String> flowEntries(String line) {
        String value = line.substring(line.indexOf(MATCH) + MATCH.length()).strip();
        if (!value.startsWith("[") || !value.endsWith("]") || value.contains("#")) {
            return null;
        }
        List<String> entries = new ArrayList<>();
        for (String raw : value.substring(1, value.length() - 1).split(",")) {
            String entry = raw.strip();
            if (!entry.isEmpty()) {
                entries.add(entry);
            }
        }
        return entries;
    }

    private static String unquote(String entry) {
        boolean quoted = entry.length() >= 2
                && (entry.startsWith("\"") && entry.endsWith("\"")
                        || entry.startsWith("'") && entry.endsWith("'"));
        return quoted ? entry.substring(1, entry.length() - 1) : entry;
    }

    private static String rewriteMatch(String line, List<String> entries) {
        String prefix = line.substring(0, line.indexOf(MATCH) + MATCH.length());
        return prefix + " [" + String.join(", ", entries) + "]";
    }
}
