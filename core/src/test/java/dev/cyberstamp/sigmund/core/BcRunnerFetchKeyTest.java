package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

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
            assertThat(runner.canFetchKeys()).isTrue();
        }

        @Test
        void falseWhenResolveDisabled() {
            BcRunner runner = createRunner(createStore(), false,
                    List.of("hkps://keys.openpgp.org"));
            assertThat(runner.canFetchKeys()).isFalse();
        }

        @Test
        void falseWhenNoKeyservers() {
            BcRunner runner = createRunner(createStore(), true, List.of());
            assertThat(runner.canFetchKeys()).isFalse();
        }
    }

    @Nested
    class EphemeralCacheWithUserIds {

        @Test
        void keyWithoutUidsReplacedByKeyWithUids() throws Exception {
            BcKeyStore store = createStore();
            BcRunner generator = new BcRunner(store, null, null);

            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = store.findPublicKey(fp).ring();
            assertThat(fullKey).isNotNull();
            assertThat(fullKey.getPublicKey().getUserIDs().hasNext()).isTrue();

            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);
            assertThat(strippedKey.getPublicKey().getUserIDs().hasNext()).isFalse();

            BcKeyStore verifierStore = createStore();
            verifierStore.cacheEphemeral(strippedKey);

            PGPPublicKeyRing cached = verifierStore.findPublicKey(fp).ring();
            assertThat(cached).isNotNull();
            assertThat(cached.getPublicKey().getUserIDs().hasNext())
                    .as("Cached key should have no UIDs initially").isFalse();

            verifierStore.cacheEphemeral(fullKey);
            cached = verifierStore.findPublicKey(fp).ring();
            assertThat(cached).isNotNull();
            assertThat(cached.getPublicKey().getUserIDs().hasNext())
                    .as("Cached key should now have UIDs after replacement").isTrue();
        }

        @Test
        void findPublicKeyReturnsKeyWithoutUids() throws Exception {
            BcKeyStore store = createStore();
            BcRunner generator = new BcRunner(store, null, null);

            String fp = generator.generateKey("Test <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = store.findPublicKey(fp).ring();
            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

            BcKeyStore verifierStore = createStore();
            verifierStore.cacheEphemeral(strippedKey);

            PGPPublicKeyRing found = verifierStore.findPublicKey(fp).ring();
            assertThat(found).as("Key without UIDs should still be findable").isNotNull();
        }
    }

    @Nested
    class FetchKeyLoop {

        @Test
        void continuesToAKeyserverWithUserIdsForDisplay() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();
            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server1", strippedKey);
            responses.put("hkps://server2", fullKey);

            StubBcRunner runner = new StubBcRunner(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(runner.fetchKey(fp)).isTrue();
            assertThat(runner.queriedServers).isEqualTo(List.of("hkps://server1", "hkps://server2"));
            assertThat(fetchStore.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver("hkps://server2"));
        }

        @Test
        void stopsAtTheFirstKeyserverWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            StubBcRunner runner = new StubBcRunner(fetchStore,
                    Map.of("hkps://server1", fullKey, "hkps://server2", fullKey),
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(runner.fetchKey(fp)).isTrue();
            assertThat(runner.queriedServers).isEqualTo(List.of("hkps://server1"));
        }

        @Test
        void aKeyWithoutUserIdsStillCountsAsFetched() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing strippedKey = stripUserIds(genStore.findPublicKey(fp).ring());

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            StubBcRunner runner = new StubBcRunner(fetchStore,
                    Map.of("hkps://server1", strippedKey),
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(runner.fetchKey(fp)).isTrue();
        }

        @Test
        void recordsWhichKeyserverSuppliedTheKey() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server2", fullKey);

            StubBcRunner runner = new StubBcRunner(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(runner.fetchKey(fp)).isTrue();
            assertThat(fetchStore.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver("hkps://server2"));
        }

        @Test
        void returnsFalseWhenNoKeyserverHasKey() throws Exception {
            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));

            StubBcRunner runner = new StubBcRunner(fetchStore, Map.of(),
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(runner.fetchKey("AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD")).isFalse();
            assertThat(runner.queriedServers).isEqualTo(List.of("hkps://server1", "hkps://server2"));
        }

        @Test
        void skipsKeyserversWhenTheKeyIsAlreadyHeldWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519");

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            fetchStore.cacheEphemeral(genStore.findPublicKey(fp).ring());

            StubBcRunner runner = new StubBcRunner(fetchStore, Map.of(),
                    List.of("hkps://server1"));

            assertThat(runner.fetchKey(fp)).isTrue();
            assertThat(runner.queriedServers).isEmpty();
        }
    }

    private static class StubBcRunner extends BcRunner {
        private final Map<String, PGPPublicKeyRing> responses;
        final List<String> queriedServers = new ArrayList<>();

        StubBcRunner(BcKeyStore store, Map<String, PGPPublicKeyRing> responses,
                List<String> keyservers) {
            super(store, null, null, null, null, true, false, keyservers);
            this.responses = responses;
        }

        @Override
        PGPPublicKeyRing fetchKeyFromHkp(String keyId, String keyserver) {
            queriedServers.add(keyserver);
            return responses.get(keyserver);
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
