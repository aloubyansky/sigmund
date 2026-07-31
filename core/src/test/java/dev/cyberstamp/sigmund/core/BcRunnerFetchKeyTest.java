package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcRunnerFetchKeyTest {

    @TempDir
    Path tempDir;

    private BcKeyStore createStore() {
        return new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
    }

    private BcRunner createRunner(BcKeyStore store, boolean resolve, List<String> keyservers) {
        return new BcRunner(store, null, null, null, null,
                resolve, false, keyservers);
    }

    @Nested
    class CanFetchKeys {

        @Test
        void trueWhenResolveEnabledAndKeyserversPresent() {
            BcRunner runner = createRunner(createStore(), true,
                    List.of("hkps://keys.openpgp.org"));
            assertTrue(runner.canFetchKeys());
        }

        @Test
        void falseWhenResolveDisabled() {
            BcRunner runner = createRunner(createStore(), false,
                    List.of("hkps://keys.openpgp.org"));
            assertFalse(runner.canFetchKeys());
        }

        @Test
        void falseWhenNoKeyservers() {
            BcRunner runner = createRunner(createStore(), true, List.of());
            assertFalse(runner.canFetchKeys());
        }
    }

    @Nested
    class EphemeralCacheWithUserIds {

        @Test
        void keyWithoutUidsReplacedByKeyWithUids() throws Exception {
            BcKeyStore store = createStore();
            BcRunner generator = new BcRunner(store, null, null);

            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = store.findPublicKey(fp);
            assertNotNull(fullKey);
            assertTrue(fullKey.getPublicKey().getUserIDs().hasNext());

            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);
            assertFalse(strippedKey.getPublicKey().getUserIDs().hasNext());

            BcKeyStore verifierStore = createStore();
            verifierStore.cacheEphemeral(strippedKey);

            PGPPublicKeyRing cached = verifierStore.findPublicKey(fp);
            assertNotNull(cached);
            assertFalse(cached.getPublicKey().getUserIDs().hasNext(),
                    "Cached key should have no UIDs initially");

            verifierStore.cacheEphemeral(fullKey);
            cached = verifierStore.findPublicKey(fp);
            assertNotNull(cached);
            assertTrue(cached.getPublicKey().getUserIDs().hasNext(),
                    "Cached key should now have UIDs after replacement");
        }

        @Test
        void findPublicKeyReturnsKeyWithoutUids() throws Exception {
            BcKeyStore store = createStore();
            BcRunner generator = new BcRunner(store, null, null);

            String fp = generator.generateKey("Test <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = store.findPublicKey(fp);
            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

            BcKeyStore verifierStore = createStore();
            verifierStore.cacheEphemeral(strippedKey);

            PGPPublicKeyRing found = verifierStore.findPublicKey(fp);
            assertNotNull(found, "Key without UIDs should still be findable");
        }
    }

    @Nested
    class FetchKeyLoop {

        @Test
        void continuesSearchingWhenFirstKeyserverReturnsNoUids() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp);
            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server1", strippedKey);
            responses.put("hkps://server2", fullKey);

            StubBcRunner runner = new StubBcRunner(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertTrue(runner.fetchKey(fp));
            assertEquals(List.of("hkps://server1", "hkps://server2"), runner.queriedServers);

            PGPPublicKeyRing cached = fetchStore.findPublicKey(fp);
            assertNotNull(cached);
            assertTrue(cached.getPublicKey().getUserIDs().hasNext(),
                    "Cached key should have UIDs from second keyserver");
        }

        @Test
        void stopsAtFirstKeyserverWithUids() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp);

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server1", fullKey);
            responses.put("hkps://server2", fullKey);

            StubBcRunner runner = new StubBcRunner(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertTrue(runner.fetchKey(fp));
            assertEquals(List.of("hkps://server1"), runner.queriedServers,
                    "Should stop after first keyserver with UIDs");
        }

        @Test
        void returnsTrueEvenWhenNoKeyserverHasUids() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing strippedKey = stripUserIds(genStore.findPublicKey(fp));

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server1", strippedKey);
            responses.put("hkps://server2", strippedKey);

            StubBcRunner runner = new StubBcRunner(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertTrue(runner.fetchKey(fp), "Should return true — key was fetched, just no UIDs");
            assertEquals(List.of("hkps://server1", "hkps://server2"), runner.queriedServers,
                    "Should try all keyservers when none has UIDs");
        }

        @Test
        void returnsFalseWhenNoKeyserverHasKey() throws Exception {
            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));

            StubBcRunner runner = new StubBcRunner(fetchStore, Map.of(),
                    List.of("hkps://server1", "hkps://server2"));

            assertFalse(runner.fetchKey("AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"));
            assertEquals(List.of("hkps://server1", "hkps://server2"), runner.queriedServers);
        }

        @Test
        void skipsKeyserversWhenKeyAlreadyCachedWithUids() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp);

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            fetchStore.cacheEphemeral(fullKey);

            StubBcRunner runner = new StubBcRunner(fetchStore, Map.of(),
                    List.of("hkps://server1"));

            assertTrue(runner.fetchKey(fp));
            assertTrue(runner.queriedServers.isEmpty(),
                    "Should not query any keyserver when key with UIDs is already cached");
        }
    }

    private static class StubBcRunner extends BcRunner {
        private final BcKeyStore store;
        private final Map<String, PGPPublicKeyRing> responses;
        final List<String> queriedServers = new ArrayList<>();

        StubBcRunner(BcKeyStore store, Map<String, PGPPublicKeyRing> responses,
                List<String> keyservers) {
            super(store, null, null, null, null, true, false, keyservers);
            this.store = store;
            this.responses = responses;
        }

        @Override
        PGPPublicKeyRing fetchFromHkpAndStore(String keyId, String keyserver) {
            queriedServers.add(keyserver);
            PGPPublicKeyRing ring = responses.get(keyserver);
            if (ring != null) {
                store.cacheEphemeral(ring);
            }
            return ring;
        }
    }

    private static PGPPublicKeyRing stripUserIds(PGPPublicKeyRing ring) {
        List<PGPPublicKey> keys = new ArrayList<>();
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        boolean first = true;
        while (it.hasNext()) {
            PGPPublicKey key = it.next();
            if (first) {
                first = false;
                Iterator<String> uids = key.getUserIDs();
                while (uids.hasNext()) {
                    key = PGPPublicKey.removeCertification(key, uids.next());
                }
            }
            keys.add(key);
        }
        return new PGPPublicKeyRing(keys);
    }
}
