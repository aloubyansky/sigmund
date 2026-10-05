package dev.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Fetches OpenPGP keys from HKP keyservers into a {@link BcKeyStore}.
 *
 * <p>
 * Keyservers supply key material only: the signature proves the key whoever served it, so
 * which server answered changes what can be verified, never what is accepted. The store
 * records the server that supplied each key it keeps.
 *
 * <p>
 * A per-build {@link KeyFetchCache} keeps a slow or unreachable server from slowing every
 * lookup: a connection-level failure trips that server's circuit breaker, and a key no healthy
 * server has is not asked for again.
 */
class KeyserverFetcher implements AutoCloseable {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final int OK = 200;

    private final BcKeyStore keyStore;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache = new KeyFetchCache();
    private final HttpClient httpClient;

    /**
     * Creates a fetcher.
     *
     * @param keyStore the store fetched keys are added to
     * @param keyservers the keyserver URLs to ask, in order; must not be empty
     */
    KeyserverFetcher(BcKeyStore keyStore, List<String> keyservers) {
        if (keyservers == null || keyservers.isEmpty()) {
            throw new IllegalArgumentException("at least one keyserver is required");
        }
        this.keyStore = keyStore;
        this.keyservers = List.copyOf(keyservers);
        this.httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    }

    /**
     * Returns the keyservers asked, in order.
     *
     * @return the keyserver URLs
     */
    List<String> keyservers() {
        return keyservers;
    }

    /**
     * Makes a key available in the store, fetching it if needed.
     *
     * <p>
     * Short-circuits if the store already holds the key with user IDs. Otherwise asks each
     * keyserver in order, skipping those whose circuit breaker has tripped, and adds what it
     * gets to the store. A copy with user IDs is preferred, so reports can show who a key
     * claims to belong to: keys.openpgp.org serves keys whose owners have not verified an
     * address without any. That preference is safe because user IDs are display text only —
     * identities come only from directories the policy names. A key no healthy server has is
     * remembered as missing for the rest of the build.
     *
     * @param keyId the key ID or fingerprint
     * @return {@code true} if the store now holds the key
     */
    boolean fetch(String keyId) {
        if (!fetchCache.shouldAttemptKey(keyId)) {
            return false;
        }
        BcKeyStore.KeyLookup existing = keyStore.findPublicKey(keyId);
        if (existing != null && hasUserIds(existing.ring())) {
            return true;
        }
        boolean fetched = existing != null;
        for (String keyserver : keyservers) {
            if (!fetchCache.shouldAttempt(keyserver, keyId)) {
                continue;
            }
            PGPPublicKeyRing ring = fetchAndStore(keyId, keyserver);
            if (ring != null) {
                fetched = true;
                if (hasUserIds(ring)) {
                    return true;
                }
            }
        }
        if (!fetched) {
            fetchCache.recordKeyNotFound(keyId);
        }
        return fetched;
    }

    private PGPPublicKeyRing fetchAndStore(String keyId, String keyserver) {
        PGPPublicKeyRing keyRing = download(keyId, keyserver);
        if (keyRing == null) {
            return null;
        }
        keyStore.addFetched(keyRing, keyserver);
        fetchCache.recordSuccess(keyserver, keyId);
        return keyRing;
    }

    /**
     * Downloads a key from one keyserver without adding it to the store.
     *
     * <p>
     * Distinguishes connection-level failures, which trip the server's circuit breaker,
     * from HTTP-level errors, which mean a healthy server does not have the key.
     *
     * @param keyId the key ID or fingerprint
     * @param keyserver the keyserver URL
     * @return the key ring, or {@code null} when the server did not supply it
     */
    PGPPublicKeyRing download(String keyId, String keyserver) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(lookupUrl(keyserver, keyId)))
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != OK) {
                return null;
            }
            try (InputStream in = PGPUtil.getDecoderStream(
                    new ByteArrayInputStream(response.body()))) {
                return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
            }
        } catch (HttpTimeoutException | ConnectException e) {
            fetchCache.recordConnectionFailure(keyserver);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Releases the HTTP client.
     *
     * <p>
     * {@link HttpClient} can be closed from Java 21 on; on Java 17 it has no close method,
     * and its resources are released once the client is no longer reachable.
     */
    @Override
    public void close() {
        if (httpClient instanceof AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (Exception ignored) {
                // nothing left to release
            }
        }
    }

    /**
     * Builds the HKP lookup URL for a keyserver, mapping {@code hkps://} to HTTPS and
     * {@code hkp://} to HTTP, and treating a bare host name as HTTPS.
     */
    static String lookupUrl(String keyserver, String keyId) {
        String base;
        if (keyserver.startsWith("hkps://")) {
            base = "https://" + keyserver.substring(7);
        } else if (keyserver.startsWith("hkp://")) {
            base = "http://" + keyserver.substring(6);
        } else if (keyserver.startsWith("https://") || keyserver.startsWith("http://")) {
            base = keyserver;
        } else {
            base = "https://" + keyserver;
        }
        if (!base.endsWith("/")) {
            base += "/";
        }
        return base + "pks/lookup?op=get&options=mr&search=0x" + keyId;
    }

    private static boolean hasUserIds(PGPPublicKeyRing ring) {
        return ring.getPublicKey().getUserIDs().hasNext();
    }
}
