package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

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
}
