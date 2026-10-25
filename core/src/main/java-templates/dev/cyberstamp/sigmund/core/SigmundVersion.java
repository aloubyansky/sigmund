package dev.cyberstamp.sigmund.core;

/**
 * The version of Sigmund this code was built as, filtered in at build time.
 */
final class SigmundVersion {

    /** The project version, such as {@code 0.0.3} or {@code 0.0.3-SNAPSHOT}. */
    static final String VERSION = "${project.version}";

    private SigmundVersion() {
    }
}
