package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SqRunnerTest {

    @Test
    void parseCertInfoRsaCert() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
                  Public-key algo: RSA
                  Public-key size: 4096 bits
                    Creation time: 2022-11-22 21:54:22 UTC
                        Key flags: certification, signing

                           Subkey: 25C3B7C9C0DF627E052F126F84EFABB1BAFB7050
                  Public-key algo: RSA
                  Public-key size: 4096 bits
                    Creation time: 2022-11-22 21:54:22 UTC
                        Key flags: transport encryption, data-at-rest encryption

                           UserID: Alexey Loubyansky <olubyans@redhat.com>
                """;
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, null);
        assertNotNull(info);
        assertEquals("RSA", info.algorithm());
        assertEquals("Alexey Loubyansky <olubyans@redhat.com>", info.userId());
        assertNull(info.certFile());
    }

    @Test
    void parseCertInfoPqcCertWithSubkeys() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: 3EE8B170C692FEFEFF2033DDD872C037A75FFE8BD8748005D0285222E76EDB53
                  Public-key algo: ML-DSA-65+Ed25519
                    Creation time: 2026-05-04 21:09:50 UTC
                        Key flags: certification

                           Subkey: D62AAB339E45E5EA2FD036872B01D46A517A299115599CCADD4C50A956F8E707
                  Public-key algo: ML-DSA-65+Ed25519
                    Creation time: 2026-05-04 21:09:50 UTC
                        Key flags: signing

                           UserID: Alexey Loubyansky <olubyans@redhat.com>
                """;
        java.nio.file.Path certFile = java.nio.file.Path.of("/some/cert.pgp");
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, certFile);
        assertNotNull(info);
        assertEquals("ML-DSA-65+Ed25519", info.algorithm());
        assertEquals("Alexey Loubyansky <olubyans@redhat.com>", info.userId());
        assertEquals(certFile, info.certFile());
    }

    @Test
    void parseCertInfoNoUserID() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
                  Public-key algo: ML-DSA-87+Ed448
                    Creation time: 2025-01-15 10:00:00 UTC
                """;
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, null);
        assertNotNull(info);
        assertEquals("ML-DSA-87+Ed448", info.algorithm());
        assertNull(info.userId());
    }

    @Test
    void parseCertInfoNullInput() {
        assertNull(SqRunner.parseCertInfo(null, null));
    }

    @Test
    void parseCertInfoEmptyInput() {
        assertNull(SqRunner.parseCertInfo("", null));
    }

    @Test
    void parseCertInfoNoMatchingFields() {
        assertNull(SqRunner.parseCertInfo("some random output\n", null));
    }

    @Nested
    class ParseSignerSelfOutputTests {

        @Test
        void validV6Fingerprint() {
            String output = "sign.signer-self.0 = \"ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890\"\n";
            assertEquals("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
                    SqRunner.parseSignerSelfOutput(output));
        }

        @Test
        void validV4Fingerprint() {
            String output = "sign.signer-self.0 = \"41A2197725BD63EB00D071D46A7F5DB1C68BDB81\"\n";
            assertEquals("41A2197725BD63EB00D071D46A7F5DB1C68BDB81",
                    SqRunner.parseSignerSelfOutput(output));
        }

        @Test
        void lowercaseFingerprintNormalized() {
            String output = "sign.signer-self.0 = \"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\"\n";
            assertEquals("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
                    SqRunner.parseSignerSelfOutput(output));
        }

        @Test
        void placeholderTextRejected() {
            String output = "sign.signer-self.0 = \"fingerprint of your key\"\n";
            assertNull(SqRunner.parseSignerSelfOutput(output));
        }

        @Test
        void emptyValueRejected() {
            String output = "sign.signer-self.0 = \"\"\n";
            assertNull(SqRunner.parseSignerSelfOutput(output));
        }

        @Test
        void nullInput() {
            assertNull(SqRunner.parseSignerSelfOutput(null));
        }

        @Test
        void emptyInput() {
            assertNull(SqRunner.parseSignerSelfOutput(""));
        }

        @Test
        void noEqualsSign() {
            assertNull(SqRunner.parseSignerSelfOutput("some random output"));
        }

        @Test
        void tooShortHexRejected() {
            String output = "sign.signer-self.0 = \"ABCDEF1234\"\n";
            assertNull(SqRunner.parseSignerSelfOutput(output));
        }

        @Test
        void nonHexRejected() {
            String output = "sign.signer-self.0 = \"GHIJKL1234567890ABCDEF1234567890ABCDEF1234\"\n";
            assertNull(SqRunner.parseSignerSelfOutput(output));
        }
    }

    @Nested
    class SignerSelfCanSignTests {

        @TempDir
        Path tempDir;

        @Test
        void canSignWithDefaultSignerFingerprint() {
            String fp = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
            SqRunner sq = new SqRunner("sq", tempDir, null, fp);
            assertTrue(sq.canSign());
        }

        @Test
        void cannotSignWithNullDefaultSigner() {
            SqRunner sq = new SqRunner("sq", tempDir, null, null);
            assertFalse(sq.canSign());
        }

        @Test
        void explicitFingerprintTakesPrecedence() {
            String explicit = "1111111111111111111111111111111111111111111111111111111111111111";
            String defaultFp = "2222222222222222222222222222222222222222222222222222222222222222";
            SqRunner sq = new SqRunner("sq", tempDir, explicit, defaultFp);
            assertTrue(sq.canSign());
            List<SigningInfo> info = sq.signingInfo();
            assertEquals(1, info.size());
            assertEquals(explicit, info.get(0).fingerprint());
        }
    }

    @Nested
    class ParseCertStorePathTests {

        @Test
        void normalOutput() {
            String output = """
                     - home directory
                       - /home/user
                       - This holds the configuration file.

                     - certificate store
                       - /home/user/.local/share/pgp.cert.d
                       - This holds all the certificates.

                     - key store
                       - /home/user/.local/share/sequoia/keystore
                    """;
            assertEquals(Path.of("/home/user/.local/share/pgp.cert.d"),
                    SqRunner.parseCertStorePath(output));
        }

        @Test
        void withSequoiaHome() {
            String output = """
                     - certificate store
                       - /tmp/sq-home/data/pgp.cert.d
                       - This holds all the certificates.
                    """;
            assertEquals(Path.of("/tmp/sq-home/data/pgp.cert.d"),
                    SqRunner.parseCertStorePath(output));
        }

        @Test
        void trailingWhitespace() {
            String output = " - certificate store  \n   - /some/path/pgp.cert.d   \n";
            assertEquals(Path.of("/some/path/pgp.cert.d"),
                    SqRunner.parseCertStorePath(output));
        }

        @Test
        void missingCertificateStoreSection() {
            String output = """
                     - home directory
                       - /home/user

                     - key store
                       - /home/user/.local/share/sequoia/keystore
                    """;
            assertNull(SqRunner.parseCertStorePath(output));
        }

        @Test
        void nullInput() {
            assertNull(SqRunner.parseCertStorePath(null));
        }

        @Test
        void emptyInput() {
            assertNull(SqRunner.parseCertStorePath(""));
        }
    }

    @Nested
    class FindCertFileTests {

        @TempDir
        Path tempDir;

        @Test
        void directPathExistsReturnsIt() throws IOException {
            String fingerprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
            Path certDir = tempDir.resolve("data").resolve("pgp.cert.d").resolve("ab");
            Files.createDirectories(certDir);
            Path certFile = certDir.resolve(
                    "cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
            Files.writeString(certFile, "fake cert data");

            SqRunner sq = new SqRunner(tempDir);
            Path result = sq.findCertFile(fingerprint);
            assertNotNull(result);
            assertEquals(certFile, result);
        }

        @Test
        void directPathMissingReturnsNull() {
            String fingerprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
            SqRunner sq = new SqRunner(tempDir);
            Path result = sq.findCertFile(fingerprint);
            assertNull(result);
        }

        @Test
        void nullFingerprintReturnsNull() {
            SqRunner sq = new SqRunner(tempDir);
            assertNull(sq.findCertFile(null));
        }

        @Test
        void emptyFingerprintReturnsNull() {
            SqRunner sq = new SqRunner(tempDir);
            assertNull(sq.findCertFile(""));
        }
    }
}
