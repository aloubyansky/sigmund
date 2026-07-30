package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

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
        assertEquals("4AEE18F83AFDEB23", GpgRunner.extractGpgKeyId(stderr));
    }

    @Test
    void extractGpgKeyIdLongForm() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", GpgRunner.extractGpgKeyId(stderr));
    }

    @Test
    void extractGpgKeyIdNotFound() {
        assertNull(GpgRunner.extractGpgKeyId("gpg: some other output\n"));
    }

    @Test
    void extractGpgKeyIdNullInput() {
        assertNull(GpgRunner.extractGpgKeyId(null));
    }

    // --- extractSignerUserId ---

    @Test
    void extractSignerUserIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User Name <user@example.com>" [ultimate]
                """;
        assertEquals("User Name <user@example.com>", GpgRunner.extractSignerUserId(stderr));
    }

    @Test
    void extractSignerUserIdNoGoodSignature() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Can't check signature: No public key
                """;
        assertNull(GpgRunner.extractSignerUserId(stderr));
    }

    @Test
    void extractSignerUserIdNullInput() {
        assertNull(GpgRunner.extractSignerUserId(null));
    }

    // --- extractAlgorithm ---

    @Test
    void extractAlgorithmRsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("RSA", GpgRunner.extractAlgorithm(stderr));
    }

    @Test
    void extractAlgorithmEddsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using EDDSA key ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("EDDSA", GpgRunner.extractAlgorithm(stderr));
    }

    @Test
    void extractAlgorithmNullInput() {
        assertNull(GpgRunner.extractAlgorithm(null));
    }

    @Test
    void extractAlgorithmNotFound() {
        assertNull(GpgRunner.extractAlgorithm("gpg: some other output\n"));
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
        assertEquals("gpg", info.toolName());
        assertEquals("41A2197725BD63EB00D071D46A7F5DB1C68BDB81", info.fingerprint());
        assertEquals("RSA", info.algorithm());
        assertEquals("Alice <alice@example.com>", info.userId());
    }

    @Test
    void parseColonsSecretKey() {
        String output = """
                sec:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1669154062::HASH::Bob <bob@example.com>::::::::::0:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertEquals("41A2197725BD63EB00D071D46A7F5DB1C68BDB81", info.fingerprint());
        assertEquals("RSA", info.algorithm());
        assertEquals("Bob <bob@example.com>", info.userId());
    }

    @Test
    void parseColonsEddsaKey() {
        String output = """
                pub:u:255:22:AABBCCDD11223344:1700000000:::u:::scESC::::::23::0:
                fpr:::::::::AABBCCDD11223344AABBCCDD11223344AABBCCDD:
                uid:u::::1700000000::HASH::Ed User <ed@example.com>::::::::::0:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertEquals("AABBCCDD11223344AABBCCDD11223344AABBCCDD", info.fingerprint());
        assertEquals("EdDSA", info.algorithm());
        assertEquals("Ed User <ed@example.com>", info.userId());
    }

    @Test
    void parseColonsEmptyOutput() {
        SigningInfo info = GpgRunner.parseColonsSigningInfo("");
        assertEquals("gpg", info.toolName());
        assertNull(info.fingerprint());
        assertNull(info.algorithm());
        assertNull(info.userId());
    }

    @Test
    void parseColonsNoUidLine() {
        String output = """
                pub:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertEquals("41A2197725BD63EB00D071D46A7F5DB1C68BDB81", info.fingerprint());
        assertEquals("RSA", info.algorithm());
        assertNull(info.userId());
    }

    // --- canSign ---

    @Test
    void signingCapableRunnerCanSign() {
        var runner = new GpgRunner("gpg", null, null,
                null, true, false, false, List.of());
        assertTrue(runner.canSign());
    }

    @Test
    void verifyOnlyRunnerCannotSign() {
        var runner = new GpgRunner("gpg", null, null,
                null, false, false, false, List.of());
        assertFalse(runner.canSign());
    }

    @Test
    void defaultConstructorCanSign() {
        var runner = new GpgRunner();
        assertTrue(runner.canSign());
    }

    // --- parseDefaultKey ---

    @TempDir
    Path tempDir;

    @Test
    void parseDefaultKeyFound() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key ABCD1234ABCD1234\n");
        assertEquals("ABCD1234ABCD1234", GpgRunner.parseDefaultKey(conf));
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
        assertEquals("41A2197725BD63EB00D071D46A7F5DB1C68BDB81", GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyLastWins() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                default-key FIRST_KEY
                default-key SECOND_KEY
                """);
        assertEquals("SECOND_KEY", GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyNotPresent() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                keyserver hkps://keys.openpgp.org
                auto-key-locate local,wkd
                """);
        assertNull(GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyFileNotFound() {
        assertNull(GpgRunner.parseDefaultKey(tempDir.resolve("nonexistent.conf")));
    }

    @Test
    void parseDefaultKeyNullPath() {
        assertNull(GpgRunner.parseDefaultKey(null));
    }

    @Test
    void parseDefaultKeyQuoted() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key \"ABCD1234ABCD1234\"\n");
        assertEquals("ABCD1234ABCD1234", GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyHexPrefix() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key 0xABCD1234ABCD1234\n");
        assertEquals("ABCD1234ABCD1234", GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyExactSubkeyMarker() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key ABCD1234ABCD1234!\n");
        assertEquals("ABCD1234ABCD1234", GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyQuotedHexPrefixAndExclamation() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key \"0xABCD1234ABCD1234!\"\n");
        assertEquals("ABCD1234ABCD1234", GpgRunner.parseDefaultKey(conf));
    }

    @Test
    void parseDefaultKeyTabDelimiter() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key\tABCD1234ABCD1234\n");
        assertEquals("ABCD1234ABCD1234", GpgRunner.parseDefaultKey(conf));
    }
}
