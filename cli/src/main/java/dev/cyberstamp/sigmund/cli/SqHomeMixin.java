package dev.cyberstamp.sigmund.cli;

import java.nio.file.Path;
import picocli.CommandLine;

/**
 * Picocli mixin for the {@code --sq-home} option and path utilities
 * shared across CLI commands.
 */
public class SqHomeMixin {

    @CommandLine.Option(names = { "--sq-home" }, description = "Sequoia home directory (overrides SEQUOIA_HOME)")
    private String sqHome;

    boolean hasExplicitHome() {
        return sqHome != null && !sqHome.isEmpty();
    }

    Path resolveSequoiaHome() {
        if (sqHome != null && !sqHome.isEmpty()) {
            return expandTilde(sqHome);
        }
        return null;
    }

    Path expandTilde(String path) {
        if (path.startsWith("~/")) {
            String userHome = System.getProperty("user.home");
            return Path.of(userHome, path.substring(2));
        }
        return Path.of(path);
    }
}
