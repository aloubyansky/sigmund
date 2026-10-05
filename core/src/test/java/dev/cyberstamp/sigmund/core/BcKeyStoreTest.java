package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

class BcKeyStoreTest {

    @Test
    void findPublicKeyFromCertD(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Test <test@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.storeCert(pubRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        PGPPublicKeyRing found = store.findPublicKey(fingerprint).ring();
        assertThat(found).isNotNull();
    }

    @Test
    void findPublicKeyNotFound(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        assertThat(store.findPublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).isNull();
    }

    @Test
    void storeAndFindSecretKey(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Test <test@example.com>");
        PGPSecretKeyRing secretRing = key.getPGPSecretKeyRing();
        store.storeSecretKey(secretRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertThat(store.findSecretKey(fingerprint)).isNotNull();
    }

    @Test
    void findPrimaryUserId(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Alice <alice@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.storeCert(pubRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        String uid = store.findPrimaryUserId(fingerprint);
        assertThat(uid).isNotNull();
        assertThat(uid.contains("alice@example.com")).isTrue();
    }

    /**
     * Verifies that a key added via {@link BcKeyStore#addFetched(PGPPublicKeyRing, String)}
     * is returned by {@link BcKeyStore#findPublicKey(String)} with the keyserver it came from.
     */
    @Test
    void fetchedKeyIsFindableWithItsKeyserver(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("Ephemeral <ephemeral@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.addFetched(pubRing, "hkps://keys.example.org");

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertThat(store.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.keyserver("hkps://keys.example.org"));
    }

    @Test
    void persistingStoreWritesFetchedKeysToCertDAndStillNamesTheKeyserver(@TempDir Path tempDir)
            throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"), true);

        OpenPGPKey key = generateEd25519Key("Persisted <persisted@example.com>");
        store.addFetched(key.toCertificate().getPGPPublicKeyRing(), "hkps://keys.example.org");

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertThat(Files.isDirectory(certD)).isTrue();
        BcKeyStore laterSession = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));
        assertThat(laterSession.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.certD(certD));
        assertThat(store.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.keyserver("hkps://keys.example.org"));
    }

    @Test
    void inspectionAnswersPerStore(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));
        OpenPGPKey stored = generateEd25519Key("Stored <stored@example.com>");
        store.storeCert(stored.toCertificate().getPGPPublicKeyRing());
        OpenPGPKey fetched = generateEd25519Key("Fetched <fetched@example.com>");
        store.addFetched(fetched.toCertificate().getPGPPublicKeyRing(), "hkps://keys.example.org");

        List<BcKeyStore.KeyLookup> byFingerprint = store.inspect(BcKeyStore.bytesToHex(fetched.getFingerprint()), null);
        assertThat(byFingerprint).extracting(BcKeyStore.KeyLookup::source)
                .containsExactly(TrustRootRef.certD(certD), TrustRootRef.keyserver("hkps://keys.example.org"));
        assertThat(byFingerprint.get(0).ring()).isNull();
        assertThat(byFingerprint.get(1).ring()).isNotNull();

        List<BcKeyStore.KeyLookup> byEmail = store.inspect(null, "Stored@Example.com");
        assertThat(byEmail).extracting(BcKeyStore.KeyLookup::source).containsExactly(TrustRootRef.certD(certD));
        assertThat(byEmail.get(0).ring()).isNotNull();

        assertThat(store.inspect(null, null)).isEmpty();
    }

    /**
     * Verifies that {@link BcKeyStore#addFetched(PGPPublicKeyRing, String)} does not write
     * any files to the cert-d directory. The key exists only in memory.
     */
    @Test
    void fetchedKeyNotPersistedByDefault(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("NoDisk <nodisk@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.addFetched(pubRing, "hkps://keys.example.org");

        assertThat(Files.exists(certD)).as("cert-d directory should not be created for ephemeral keys").isFalse();
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void secretKeyFileHasOwnerOnlyPermissions(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Perm <perm@example.com>");
        store.storeSecretKey(key.getPGPSecretKeyRing());

        String fp = BcKeyStore.bytesToHex(key.getFingerprint()).toLowerCase();
        Path keyFile = bcPrivate.resolve(fp.substring(0, 2)).resolve(fp.substring(2));
        assertThat(Files.exists(keyFile)).isTrue();

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keyFile);
        assertThat(perms).isEqualTo(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void certFileDoesNotGetRestrictedPermissions(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Cert <cert@example.com>");
        store.storeCert(key.toCertificate().getPGPPublicKeyRing());

        String fp = BcKeyStore.bytesToHex(key.getFingerprint()).toLowerCase();
        Path certFile = certD.resolve(fp.substring(0, 2)).resolve(fp.substring(2));
        assertThat(Files.exists(certFile)).isTrue();

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(certFile);
        assertThat(perms.contains(PosixFilePermission.OWNER_READ)).isTrue();
        // cert files should keep default permissions (not restricted to owner-only)
        assertThat(perms.size() > 2).as("Cert file should have broader permissions than owner-only").isTrue();
    }

    // Helper: Generate Ed25519 key using BC 1.85's high-level API
    private OpenPGPKey generateEd25519Key(String userId) throws Exception {
        BcOpenPGPApi api = new BcOpenPGPApi();
        return api.generateKey().ed25519x25519Key(userId).build();
    }
}
