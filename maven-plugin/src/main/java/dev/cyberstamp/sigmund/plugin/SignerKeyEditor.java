package dev.cyberstamp.sigmund.plugin;

import java.util.ArrayList;
import java.util.List;

/**
 * Adds a fingerprint to a signer's {@code pgp4} or {@code pgp6} in the text of a
 * {@code sigmund.yaml}, leaving every other line as written.
 *
 * <p>
 * Pinning a rotated key onto the signer it belongs to is the one change an update makes to a
 * signer. Each key keeps its own comment — the user ID bootstrap saw on it, or what pinned it —
 * so a signer with several keys of a version has them in a block list, one per line. Only the
 * shapes bootstrap and update write are edited: a top-level {@code signers:} mapping whose signer
 * is a mapping of credentials, its fingerprints a single value, a block list of single values, or
 * a single-line flow list with no comment, which gains an entry but cannot carry its note. A
 * signer written as an address, an organization with {@code members}, or any other shape is left
 * alone and reported as not editable, because rewriting YAML someone formatted by hand is where
 * a line-based edit goes wrong.
 */
final class SignerKeyEditor {

    private static final String SIGNERS = "signers:";
    private static final String MEMBERS = "members";
    private static final String PGP4 = "pgp4";
    private static final String ITEM = "- ";
    private static final String COMMENT = "  # ";

    private SignerKeyEditor() {
    }

    /**
     * Adds a fingerprint to one signer, all or nothing.
     *
     * @param lines the config file lines, mutated only when the fingerprint was added
     * @param signerId the signer's id
     * @param keyField {@code pgp4} or {@code pgp6}
     * @param fingerprint the full fingerprint to add
     * @param note the comment written beside the added fingerprint, or {@code null} for none
     * @return {@code true} when the fingerprint was added; {@code false} when the signer is not
     *         defined or does not have the editable shape
     */
    static boolean addFingerprint(List<String> lines, String signerId, String keyField,
            String fingerprint, String note) {
        int[] block = findSigner(lines, signerId);
        if (block == null || !isMappingHeader(lines.get(block[0]), signerId)) {
            return false;
        }
        int childIndent = childIndent(lines, block);
        if (findKey(lines, block, childIndent, MEMBERS) >= 0) {
            return false;
        }
        int keyLine = findKey(lines, block, childIndent, keyField);
        if (keyLine < 0) {
            lines.add(insertionPoint(lines, block, childIndent, keyField),
                    " ".repeat(childIndent) + keyField + ": " + entry(fingerprint, note));
            return true;
        }
        String value = valueOf(lines.get(keyLine), keyField);
        if (value.isEmpty() || value.startsWith("#")) {
            return appendToBlockList(lines, keyLine, block[1], fingerprint, note);
        }
        if (value.startsWith("[")) {
            return appendToFlowList(lines, keyLine, keyField, value, fingerprint);
        }
        return toBlockList(lines, keyLine, keyField, value, fingerprint, note);
    }

    /**
     * Turns a single fingerprint into a block list of it and the new one, its comment staying
     * with it on its own item.
     */
    private static boolean toBlockList(List<String> lines, int keyLine, String keyField, String value,
            String fingerprint, String note) {
        String line = lines.get(keyLine);
        String itemIndent = " ".repeat(indentOf(line) + 2);
        lines.set(keyLine, line.substring(0, line.indexOf(keyField + ":") + keyField.length() + 1));
        lines.add(keyLine + 1, itemIndent + ITEM + value);
        lines.add(keyLine + 2, itemIndent + ITEM + entry(fingerprint, note));
        return true;
    }

    /**
     * Appends to a block list whose items are each a single value, after its last item.
     *
     * @return {@code false} when the list is empty or an item is not a single value
     */
    private static boolean appendToBlockList(List<String> lines, int keyLine, int blockEnd,
            String fingerprint, String note) {
        int keyIndent = indentOf(lines.get(keyLine));
        int itemIndent = -1;
        int last = -1;
        for (int i = keyLine + 1; i < blockEnd; i++) {
            String line = lines.get(i);
            if (isBlankOrComment(line)) {
                continue;
            }
            if (indentOf(line) <= keyIndent) {
                break;
            }
            String item = line.stripLeading();
            if (!item.startsWith(ITEM) || !isSingleValue(item.substring(ITEM.length()))
                    || itemIndent >= 0 && indentOf(line) != itemIndent) {
                return false;
            }
            itemIndent = indentOf(line);
            last = i;
        }
        if (last < 0) {
            return false;
        }
        lines.add(last + 1, " ".repeat(itemIndent) + ITEM + entry(fingerprint, note));
        return true;
    }

    /**
     * Adds an entry to a single-line flow list, which has no place for the note.
     *
     * @return {@code false} when the line carries a comment
     */
    private static boolean appendToFlowList(List<String> lines, int keyLine, String keyField,
            String value, String fingerprint) {
        if (value.contains("#") || !value.endsWith("]")) {
            return false;
        }
        List<String> entries = new ArrayList<>();
        for (String entry : value.substring(1, value.length() - 1).split(",")) {
            if (!entry.isBlank()) {
                entries.add(entry.strip());
            }
        }
        entries.add(quoted(fingerprint));
        String line = lines.get(keyLine);
        String prefix = line.substring(0, line.indexOf(keyField + ":") + keyField.length() + 1);
        lines.set(keyLine, prefix + " [" + String.join(", ", entries) + "]");
        return true;
    }

    /**
     * Whether a list item, ignoring its comment, is a single value rather than a mapping or a
     * nested list.
     */
    private static boolean isSingleValue(String item) {
        int comment = item.indexOf(" #");
        String value = (comment < 0 ? item : item.substring(0, comment)).strip();
        return !value.isEmpty() && !value.startsWith("{") && !value.startsWith("[")
                && !value.startsWith("-") && !value.contains(": ") && !value.endsWith(":");
    }

    private static String valueOf(String line, String keyField) {
        return line.substring(line.indexOf(keyField + ":") + keyField.length() + 1).strip();
    }

    private static String entry(String fingerprint, String note) {
        return quoted(fingerprint) + (note == null ? "" : COMMENT + note);
    }

    /**
     * Finds the line range of one signer in the top-level {@code signers} mapping.
     *
     * @return the signer's line and the line after its last, or {@code null} when not found
     */
    private static int[] findSigner(List<String> lines, String signerId) {
        int header = signersHeader(lines);
        if (header < 0) {
            return null;
        }
        int entryIndent = -1;
        int start = -1;
        for (int i = header + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (isSectionEnd(line)) {
                return start >= 0 ? new int[] { start, trimTrailingBlank(lines, start, i) } : null;
            }
            if (isBlankOrComment(line)) {
                continue;
            }
            int indent = indentOf(line);
            if (entryIndent < 0) {
                entryIndent = indent;
            }
            if (indent > entryIndent) {
                continue;
            }
            if (start >= 0) {
                return new int[] { start, trimTrailingBlank(lines, start, i) };
            }
            if (indent == entryIndent && line.stripLeading().startsWith(signerId + ":")) {
                start = i;
            }
        }
        return start >= 0 ? new int[] { start, trimTrailingBlank(lines, start, lines.size()) } : null;
    }

    /**
     * Finds the top-level {@code signers:} line, which may carry a comment.
     *
     * @return its index, or {@code -1} when there is none
     */
    private static int signersHeader(List<String> lines) {
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.startsWith(SIGNERS)) {
                String rest = line.substring(SIGNERS.length()).strip();
                if (rest.isEmpty() || rest.startsWith("#")) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static boolean isMappingHeader(String line, String signerId) {
        String rest = line.stripLeading().substring(signerId.length() + 1).strip();
        return rest.isEmpty() || rest.startsWith("#");
    }

    private static int childIndent(List<String> lines, int[] block) {
        for (int i = block[0] + 1; i < block[1]; i++) {
            if (!isBlankOrComment(lines.get(i))) {
                return indentOf(lines.get(i));
            }
        }
        return indentOf(lines.get(block[0])) + 2;
    }

    private static int findKey(List<String> lines, int[] block, int childIndent, String key) {
        for (int i = block[0] + 1; i < block[1]; i++) {
            String line = lines.get(i);
            if (indentOf(line) == childIndent && line.stripLeading().startsWith(key + ":")) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Places a new {@code pgp4} line first in the signer and a new {@code pgp6} line after its
     * {@code pgp4}, the order bootstrap writes them in.
     */
    private static int insertionPoint(List<String> lines, int[] block, int childIndent, String keyField) {
        if (!PGP4.equals(keyField)) {
            int pgp4 = findKey(lines, block, childIndent, PGP4);
            if (pgp4 >= 0) {
                return pgp4 + 1;
            }
        }
        return block[0] + 1;
    }

    private static String quoted(String fingerprint) {
        return "\"" + fingerprint + "\"";
    }

    private static boolean isSectionEnd(String line) {
        return !line.isEmpty() && !line.startsWith(" ") && !line.startsWith("#");
    }

    private static boolean isBlankOrComment(String line) {
        return line.isBlank() || line.stripLeading().startsWith("#");
    }

    private static int indentOf(String line) {
        return line.length() - line.stripLeading().length();
    }

    private static int trimTrailingBlank(List<String> lines, int start, int end) {
        while (end > start + 1 && lines.get(end - 1).isBlank()) {
            end--;
        }
        return end;
    }
}
