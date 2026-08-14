package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GpgRunnerTest {

    @Test
    void extractGpgKeyIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractGpgKeyId(stderr)).isEqualTo("4AEE18F83AFDEB23");
    }

    @Test
    void extractGpgKeyIdLongForm() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractGpgKeyId(stderr)).isEqualTo("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
    }

    @Test
    void extractGpgKeyIdNotFound() {
        assertThat(GpgRunner.extractGpgKeyId("gpg: some other output\n")).isNull();
    }

    @Test
    void extractGpgKeyIdNullInput() {
        assertThat(GpgRunner.extractGpgKeyId(null)).isNull();
    }

    // --- extractSignerUserId ---

    @Test
    void extractSignerUserIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User Name <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractSignerUserId(stderr)).isEqualTo("User Name <user@example.com>");
    }

    @Test
    void extractSignerUserIdNoGoodSignature() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Can't check signature: No public key
                """;
        assertThat(GpgRunner.extractSignerUserId(stderr)).isNull();
    }

    @Test
    void extractSignerUserIdNullInput() {
        assertThat(GpgRunner.extractSignerUserId(null)).isNull();
    }

    // --- extractAlgorithm ---

    @Test
    void extractAlgorithmRsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractAlgorithm(stderr)).isEqualTo("RSA");
    }

    @Test
    void extractAlgorithmEddsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using EDDSA key ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractAlgorithm(stderr)).isEqualTo("EDDSA");
    }

    @Test
    void extractAlgorithmNullInput() {
        assertThat(GpgRunner.extractAlgorithm(null)).isNull();
    }

    @Test
    void extractAlgorithmNotFound() {
        assertThat(GpgRunner.extractAlgorithm("gpg: some other output\n")).isNull();
    }

    // --- parseColonsSigningInfo ---

    @Test
    void parseColonsPublicKey() {
        String output = """
                pub:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1669154062::HASH::Alice <alice@example.com>::::::::::0:
                sub:u:4096:1:84EFABB1BAFB7050:1669154062::::::e::::::23:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.toolName()).isEqualTo("gpg");
        assertThat(info.fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isEqualTo("Alice <alice@example.com>");
    }

    @Test
    void parseColonsSecretKey() {
        String output = """
                sec:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1669154062::HASH::Bob <bob@example.com>::::::::::0:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isEqualTo("Bob <bob@example.com>");
    }

    @Test
    void parseColonsEddsaKey() {
        String output = """
                pub:u:255:22:AABBCCDD11223344:1700000000:::u:::scESC::::::23::0:
                fpr:::::::::AABBCCDD11223344AABBCCDD11223344AABBCCDD:
                uid:u::::1700000000::HASH::Ed User <ed@example.com>::::::::::0:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.fingerprint()).isEqualTo("AABBCCDD11223344AABBCCDD11223344AABBCCDD");
        assertThat(info.algorithm()).isEqualTo("EdDSA");
        assertThat(info.userId()).isEqualTo("Ed User <ed@example.com>");
    }

    @Test
    void parseColonsEmptyOutput() {
        SigningInfo info = GpgRunner.parseColonsSigningInfo("");
        assertThat(info.toolName()).isEqualTo("gpg");
        assertThat(info.fingerprint()).isNull();
        assertThat(info.algorithm()).isNull();
        assertThat(info.userId()).isNull();
    }

    @Test
    void parseColonsNoUidLine() {
        String output = """
                pub:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isNull();
    }

    // --- canSign ---

    @Test
    void signingCapableRunnerCanSign() {
        var runner = new GpgRunner("gpg", null, null,
                null, true, false, false, List.of());
        assertThat(runner.canSign()).isTrue();
    }

    @Test
    void verifyOnlyRunnerCannotSign() {
        var runner = new GpgRunner("gpg", null, null,
                null, false, false, false, List.of());
        assertThat(runner.canSign()).isFalse();
    }

    @Test
    void defaultConstructorCanSign() {
        var runner = new GpgRunner();
        assertThat(runner.canSign()).isTrue();
    }

    // --- parseDefaultKey ---

    @TempDir
    Path tempDir;

    @Test
    void parseDefaultKeyFound() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key ABCD1234ABCD1234\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyWithComments() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                # This is a comment
                keyserver hkps://keys.openpgp.org

                # default-key OLD_KEY
                default-key 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
                """);
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
    }

    @Test
    void parseDefaultKeyLastWins() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                default-key FIRST_KEY
                default-key SECOND_KEY
                """);
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("SECOND_KEY");
    }

    @Test
    void parseDefaultKeyNotPresent() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                keyserver hkps://keys.openpgp.org
                auto-key-locate local,wkd
                """);
        assertThat(GpgRunner.parseDefaultKey(conf)).isNull();
    }

    @Test
    void parseDefaultKeyFileNotFound() {
        assertThat(GpgRunner.parseDefaultKey(tempDir.resolve("nonexistent.conf"))).isNull();
    }

    @Test
    void parseDefaultKeyNullPath() {
        assertThat(GpgRunner.parseDefaultKey(null)).isNull();
    }

    @Test
    void parseDefaultKeyQuoted() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key \"ABCD1234ABCD1234\"\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyHexPrefix() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key 0xABCD1234ABCD1234\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyExactSubkeyMarker() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key ABCD1234ABCD1234!\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyQuotedHexPrefixAndExclamation() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key \"0xABCD1234ABCD1234!\"\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyTabDelimiter() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key\tABCD1234ABCD1234\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }
}
