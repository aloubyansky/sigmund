package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcToolFactoryTest {

    @Test
    void toolName() {
        assertEquals("bc", new BcToolFactory().toolName());
    }

    @Test
    void supportedCredentialTypes() {
        assertEquals(Set.of("openpgp4", "openpgp6"),
                new BcToolFactory().supportedCredentialTypes());
    }

    @Test
    void createVerifyOnlyIsAvailable() {
        SignatureTool tool = new BcToolFactory().createVerifyOnly(Map.of());
        assertTrue(tool.isAvailable());
        assertFalse(tool.canSign());
        assertEquals("bc", tool.name());
    }

    @Test
    void createVerifyOnlyWithCustomPaths() {
        SignatureTool tool = new BcToolFactory().createVerifyOnly(Map.of(
                "gnupg-home", "/tmp/gnupg",
                "cert-d-home", "/tmp/cert-d",
                "bc-private-home", "/tmp/bc-private"));
        assertTrue(tool.isAvailable());
    }

    @Test
    void createWithSigningFingerprint() {
        SignatureTool tool = new BcToolFactory().createSigning(null, Map.of(
                "signing-fingerprint", "AABBCCDD"));
        assertTrue(tool.canSign());
    }

    // --- resolveSigningKeyBytes (custom env var path) ---

    @Test
    void resolveSigningKeyBytesFromCustomEnvVar() {
        String keyData = "key-content";
        byte[] result = BcToolFactory.resolveSigningKeyBytes(
                Map.of("signing-key-env", "MY_KEY"),
                name -> "MY_KEY".equals(name) ? keyData : null);
        assertArrayEquals(keyData.getBytes(StandardCharsets.UTF_8), result);
    }

    @Test
    void resolveSigningKeyBytesThrowsWhenCustomEnvVarNotSet() {
        assertThrows(SigmundException.class,
                () -> BcToolFactory.resolveSigningKeyBytes(
                        Map.of("signing-key-env", "MY_KEY"), name -> null));
    }

    @Test
    void resolveSigningKeyBytesThrowsWhenCustomEnvVarEmpty() {
        assertThrows(SigmundException.class,
                () -> BcToolFactory.resolveSigningKeyBytes(
                        Map.of("signing-key-env", "MY_KEY"),
                        name -> "MY_KEY".equals(name) ? "" : null));
    }

    // --- Ephemeral signing key round-trip (the SIGMUND_BC_SIGNING_KEY code path) ---

    @Test
    void ephemeralKeySignAndVerifyRoundTrip(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null);
        String fingerprint = generator.generateKey("CI <ci@example.com>", "ed25519");

        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        byte[] armoredKey = armorSecretKey(ring);

        BcRunner signer = new BcRunner(store, null, null,
                armoredKey, null, false, false, List.of());
        assertTrue(signer.canSign());

        Path artifact = tempDir.resolve("artifact.jar");
        Files.writeString(artifact, "test artifact content");
        Path sigFile = tempDir.resolve("artifact.jar.asc");

        SignResult signResult = signer.sign(artifact, sigFile);
        assertNotNull(signResult.algorithm());
        assertTrue(Files.exists(sigFile));

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());

        VerifyResult result = signer.verify(artifact, unit);
        assertEquals(Verdict.PASS, result.verdict());
    }

    @Test
    void ephemeralKeyOnlyBcInSigner(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null);
        String fingerprint = generator.generateKey("CI <ci@example.com>", "ed25519");

        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        byte[] armoredKey = armorSecretKey(ring);

        BcRunner bcSigner = new BcRunner(store, null, null,
                armoredKey, null, false, false, List.of());

        Signer signer = new Signer(List.of(bcSigner));

        Path artifact = tempDir.resolve("artifact.jar");
        Files.writeString(artifact, "signer test");

        SigningOutput output = signer.sign(artifact, tempDir);
        assertEquals(1, output.files().size());
        assertEquals("bc", output.files().get(0).toolName());
    }

    private static byte[] armorSecretKey(PGPSecretKeyRing ring) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
            ring.encode(armored);
        }
        return out.toByteArray();
    }
}
