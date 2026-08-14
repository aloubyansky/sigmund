package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link CliTool}.
 */
class CliToolTest {

    /**
     * Verifies that stdout is captured correctly from a simple echo command.
     */
    @Test
    void runCapturesStdout() {
        CliTool.Result result = CliTool.run("echo", "hello");

        assertThat(result.exitCode()).as("Exit code should be 0").isEqualTo(0);
        assertThat(result.stdout().trim()).as("Stdout should contain 'hello'").isEqualTo("hello");
    }

    /**
     * Verifies that stderr is captured correctly from a command that writes to stderr.
     */
    @Test
    void runCapturesStderr() {
        CliTool.Result result = CliTool.run("sh", "-c", "echo err >&2");

        assertThat(result.exitCode()).as("Exit code should be 0").isEqualTo(0);
        assertThat(result.stderr().trim()).as("Stderr should contain 'err'").isEqualTo("err");
    }

    /**
     * Verifies that run() does not throw an exception for non-zero exit codes.
     */
    @Test
    void runNonZeroExitDoesNotThrow() {
        CliTool.Result result = CliTool.run("sh", "-c", "exit 42");

        assertThat(result.exitCode()).as("Exit code should be 42").isEqualTo(42);
    }

}
