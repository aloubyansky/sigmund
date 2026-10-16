package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Every {@code sigmund.yaml} example in the documentation loads.
 *
 * <p>
 * A documented example that the parser rejects sends a reader straight into an error, and one it
 * silently ignores teaches a setting that does nothing — the parser rejects unknown keys and the
 * removed v1 schema, so a stale example fails here. Each example is parsed; one that defines both
 * {@code signers} and {@code rules} is also compiled into a policy, which checks its signer
 * references and rule ties. YAML that is not a Sigmund configuration — a CI workflow, a fragment
 * with no top-level key — is skipped.
 */
class DocumentationExamplesTest {

    private static final Path REPOSITORY = Path.of("..");
    private static final Pattern YAML_BLOCK = Pattern.compile("(?ms)^```yaml\\n(.*?)^```");
    private static final Pattern TOP_LEVEL_KEY = Pattern.compile("(?m)^([A-Za-z][\\w-]*):");
    private static final Set<String> NOT_SIGMUND_KEYS = Set.of("permissions", "steps", "jobs", "on");

    @TestFactory
    Stream<DynamicTest> everyDocumentedConfigurationLoads() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        for (Path file : documentationFiles()) {
            String text = Files.readString(file);
            Matcher block = YAML_BLOCK.matcher(text);
            while (block.find()) {
                String yaml = block.group(1);
                if (isSigmundConfiguration(yaml)) {
                    String location = REPOSITORY.relativize(file) + ":" + lineOf(text, block.start());
                    tests.add(DynamicTest.dynamicTest(location, () -> load(location, yaml)));
                }
            }
        }
        assertThat(tests).as("documentation examples found").isNotEmpty();
        return tests.stream();
    }

    private static void load(String location, String yaml) {
        SigmundConfig config = SigmundConfigParser.parse(location, new StringReader(yaml));
        if (!config.signers().isEmpty() && !config.trustPolicySpec().rules().isEmpty()) {
            RulePolicy.compile(config.trustPolicySpec(), config.signers());
        }
    }

    private static List<Path> documentationFiles() throws IOException {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> docs = Files.list(REPOSITORY.resolve("docs"))) {
            docs.filter(path -> path.toString().endsWith(".md")).sorted().forEach(files::add);
        }
        files.add(REPOSITORY.resolve("README.md"));
        return files;
    }

    private static boolean isSigmundConfiguration(String yaml) {
        Matcher key = TOP_LEVEL_KEY.matcher(yaml);
        boolean any = false;
        while (key.find()) {
            if (NOT_SIGMUND_KEYS.contains(key.group(1))) {
                return false;
            }
            any = true;
        }
        return any;
    }

    private static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
}
