package dev.cyberstamp.sigmund.core;

/**
 * The JSON Schema for {@code sigmund.yaml}, which YAML editors use for completion, hover
 * documentation and unknown-key errors while the file is written.
 * <p>
 * The schema ships as the classpath resource {@value #RESOURCE} and is published from the
 * repository at the release tag, so a file is edited against the schema of the Sigmund that
 * reads it. It states keys and value shapes only; Sigmund stays authoritative and never consults
 * the schema at runtime — signer references, rule ties and issuer assertability are checked
 * when the file is loaded.
 */
public final class SigmundSchema {

    /** The schema's name on the classpath, at its root. */
    public static final String RESOURCE = "sigmund.schema.json";

    private static final String REPOSITORY = "https://raw.githubusercontent.com/cyberstamp/sigmund/";
    private static final String PATH = "/core/src/main/resources/" + RESOURCE;
    private static final String SNAPSHOT = "-SNAPSHOT";

    private SigmundSchema() {
    }

    /**
     * Returns the URL the schema of this Sigmund version is published at.
     *
     * @return the schema URL
     */
    public static String url() {
        return url(SigmundVersion.VERSION);
    }

    /**
     * Returns the URL the schema of a Sigmund version is published at: the file at that
     * version's release tag, or on {@code main} for a snapshot, which has no tag.
     *
     * @param version a Sigmund version
     * @return the schema URL
     */
    static String url(String version) {
        String ref = version.endsWith(SNAPSHOT) ? "main" : version;
        return REPOSITORY + ref + PATH;
    }

    /**
     * Returns the comment that points YAML language servers — in IntelliJ and VS Code — at the
     * schema, written as the first line of a generated {@code sigmund.yaml}.
     *
     * @return the modeline
     */
    public static String modeline() {
        return "# yaml-language-server: $schema=" + url();
    }
}
