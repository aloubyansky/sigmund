package dev.cyberstamp.sigmund.sigstore;

import static org.junit.jupiter.api.Assertions.*;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.EmailCredential;
import dev.cyberstamp.sigmund.core.OpenPgpVerificationUnit;
import dev.cyberstamp.sigmund.core.SigstoreCredential;
import dev.cyberstamp.sigmund.core.SigstoreVerificationUnit;
import dev.cyberstamp.sigmund.core.SigstoreVerifyResult;
import dev.cyberstamp.sigmund.core.Verdict;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigstoreToolTest {

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    /**
     * Creates a tool with no signer and no verifier — suitable only for testing
     * metadata methods and {@code extractCredentials()}, not {@code sign()} or {@code verify()}.
     */
    private SigstoreTool metadataOnlyTool() {
        return new SigstoreTool(format, null, null, null);
    }

    @Nested
    class Properties {
        @Test
        void name() {
            assertEquals("sigstore", metadataOnlyTool().name());
        }

        @Test
        void isAlwaysAvailable() {
            assertTrue(metadataOnlyTool().isAvailable());
        }

        @Test
        void cannotSignWithoutSigner() {
            assertFalse(metadataOnlyTool().canSign());
        }

        @Test
        void signatureFormat() {
            assertSame(format, metadataOnlyTool().signatureFormat());
        }

        @Test
        void supportedCredentialTypes() {
            assertEquals(Set.of("sigstore"), metadataOnlyTool().supportedCredentialTypes());
        }

        @Test
        void signingInfoEmptyWhenVerifyOnly() {
            assertTrue(metadataOnlyTool().signingInfo().isEmpty());
        }
    }

    @Nested
    class CanVerify {
        @Test
        void acceptsSigstoreUnit() {
            assertTrue(metadataOnlyTool().canVerify(
                    new SigstoreVerificationUnit("{}")));
        }

        @Test
        void rejectsOpenPgpUnit() {
            assertFalse(metadataOnlyTool().canVerify(
                    new OpenPgpVerificationUnit("block", 4, null, 0)));
        }
    }

    @Nested
    class ExtractCredentials {
        @Test
        void emailSubjectProducesBothCredentials() {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://accounts.google.com")
                    .subject("alice@example.com")
                    .build();
            var result = new SigstoreVerifyResult(
                    Verdict.PASS, "alice@example.com", "EC",
                    sc, "12345", GeneralName.rfc822Name);

            List<Credential> credentials = metadataOnlyTool().extractCredentials(result);

            assertEquals(2, credentials.size());
            assertInstanceOf(SigstoreCredential.class, credentials.get(0));
            assertInstanceOf(EmailCredential.class, credentials.get(1));

            SigstoreCredential extracted = (SigstoreCredential) credentials.get(0);
            assertEquals("https://accounts.google.com", extracted.issuer());
            assertEquals("alice@example.com", extracted.subject());

            EmailCredential email = (EmailCredential) credentials.get(1);
            assertEquals("alice@example.com", email.email());
        }

        @Test
        void uriSubjectProducesOnlySigstoreCredential() {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://token.actions.githubusercontent.com")
                    .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0")
                    .sourceRepositoryUri("https://github.com/org/repo")
                    .build();
            var result = new SigstoreVerifyResult(
                    Verdict.PASS,
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0",
                    "EC", sc, "67890",
                    GeneralName.uniformResourceIdentifier);

            List<Credential> credentials = metadataOnlyTool().extractCredentials(result);

            assertEquals(1, credentials.size());
            SigstoreCredential extracted = assertInstanceOf(SigstoreCredential.class, credentials.get(0));
            assertEquals("https://github.com/org/repo", extracted.sourceRepositoryUri());
        }

        @Test
        void failedVerificationProducesNoCredentials() {
            var result = new SigstoreVerifyResult(
                    Verdict.FAIL, null, null, null, null, -1);
            assertTrue(metadataOnlyTool().extractCredentials(result).isEmpty());
        }

        @Test
        void missingIssuerProducesBothCredentials() {
            var sc = new SigstoreCredential.Builder()
                    .subject("alice@example.com")
                    .build();
            var result = new SigstoreVerifyResult(
                    Verdict.PASS, "alice@example.com", "EC",
                    sc, "12345", GeneralName.rfc822Name);

            List<Credential> credentials = metadataOnlyTool().extractCredentials(result);

            assertEquals(2, credentials.size());
            assertInstanceOf(SigstoreCredential.class, credentials.get(0));
            assertInstanceOf(EmailCredential.class, credentials.get(1));
        }

        @Test
        void missingSubjectProducesNoCredentials() {
            var result = new SigstoreVerifyResult(
                    Verdict.PASS, null, "EC",
                    null, "12345", -1);

            assertTrue(metadataOnlyTool().extractCredentials(result).isEmpty());
        }
    }

    @Nested
    class Lifecycle {
        @Test
        void closeIsNoOpForVerifyOnly() {
            assertDoesNotThrow(() -> metadataOnlyTool().close());
        }

        @Test
        void signThrowsWithoutSigner() {
            assertThrows(IllegalStateException.class,
                    () -> metadataOnlyTool().sign(null, null));
        }

        @Test
        void verifyThrowsWithoutVerifier() {
            assertThrows(IllegalStateException.class,
                    () -> metadataOnlyTool().verify(null, new SigstoreVerificationUnit("{}")));
        }
    }
}
