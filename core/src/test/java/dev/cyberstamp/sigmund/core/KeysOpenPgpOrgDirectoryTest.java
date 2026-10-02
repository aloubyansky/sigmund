package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeysOpenPgpOrgDirectoryTest {

    @TempDir
    Path tempDir;

    private HttpServer server;
    private final Map<String, byte[]> keys = new ConcurrentHashMap<>();
    private final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    private final List<String> requests = new ArrayList<>();
    private KeysOpenPgpOrgDirectory directory;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/vks/v1/by-fingerprint/", exchange -> {
            String fingerprint = exchange.getRequestURI().getPath()
                    .substring("/vks/v1/by-fingerprint/".length());
            synchronized (requests) {
                requests.add(fingerprint);
            }
            byte[] body = keys.get(fingerprint);
            int status = statuses.getOrDefault(fingerprint, body != null ? 200 : 404);
            exchange.sendResponseHeaders(status, body != null && status == 200 ? body.length : -1);
            if (body != null && status == 200) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            exchange.close();
        });
        server.start();
        directory = new KeysOpenPgpOrgDirectory("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void servesTheVerifiedAddressOfAKey() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <Release@Example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        assertThat(directory.verifiedAddresses(fingerprint)).containsExactly("release@example.org");
    }

    @Test
    void findsTheKeyBySubkeyFingerprint() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String subkey = lastFingerprint(ring);
        keys.put(subkey, ring.getEncoded());

        assertThat(directory.verifiedAddresses(subkey.toLowerCase()))
                .containsExactly("release@example.org");
        assertThat(requests).containsExactly(subkey);
    }

    @Test
    void anUnknownKeyHasNoAddresses() throws Exception {
        assertThat(directory.verifiedAddresses("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")).isEmpty();
    }

    @Test
    void anAnswerAboutAnotherKeyVouchesForNothing() throws Exception {
        PGPPublicKeyRing ring = generate("Someone Else <else@example.org>");
        String asked = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
        keys.put(asked, ring.getEncoded());

        assertThat(directory.verifiedAddresses(asked)).isEmpty();
    }

    @Test
    void aServerErrorIsReportedAndNotRetriedWithinTheSession() {
        String fingerprint = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
        statuses.put(fingerprint, 429);

        assertThatThrownBy(() -> directory.verifiedAddresses(fingerprint))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("HTTP 429");
        assertThatThrownBy(() -> directory.verifiedAddresses(fingerprint))
                .isInstanceOf(IOException.class);
        assertThat(requests).hasSize(1);
    }

    @Test
    void answersAreCachedForTheSession() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        directory.verifiedAddresses(fingerprint);
        directory.verifiedAddresses(fingerprint);

        assertThat(requests).hasSize(1);
    }

    @Test
    void closingReleasesTheClientAndALaterLookupStartsAnother() throws Exception {
        directory.close();
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        assertThat(directory.verifiedAddresses(fingerprint)).containsExactly("release@example.org");

        directory.close();
        directory.close();
    }

    @Test
    void isNamedAsTheIssuerPolicyLists() {
        assertThat(KeysOpenPgpOrgDirectory.standard().name()).isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
    }

    private PGPPublicKeyRing generate(String userId) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d-" + keys.size() + requests.size()),
                tempDir.resolve("bc-" + keys.size()));
        String fingerprint = new BcRunner(store, null, null).generateKey(userId, "ed25519");
        return store.findPublicKey(fingerprint).ring();
    }

    private static String primaryFingerprint(PGPPublicKeyRing ring) {
        return HexFormat.of().withUpperCase().formatHex(ring.getPublicKey().getFingerprint());
    }

    private static String lastFingerprint(PGPPublicKeyRing ring) {
        PGPPublicKey last = null;
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            last = it.next();
        }
        return HexFormat.of().withUpperCase().formatHex(last.getFingerprint());
    }
}
