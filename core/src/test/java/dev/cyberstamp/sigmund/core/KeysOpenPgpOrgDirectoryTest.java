package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeysOpenPgpOrgDirectoryTest {

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

    /**
     * keys.openpgp.org serves v4 keys only, and answers a 64-hex fingerprint with HTTP 400. It
     * vouches for no address on a v6 key, which is an answer rather than a failure: a failure
     * would leave the claim key-unavailable, as if asking again could help.
     */
    @Test
    void aV6KeyHasNoAddressesAndIsNotAskedAbout() throws Exception {
        String v6 = "D62AAB339E45E5EA2FD036872B01D46A517A299115599CCADD4C50A956F8E707";
        statuses.put(v6, 400);

        assertThat(directory.verifiedAddresses(v6)).isEmpty();
        assertThat(requests).isEmpty();
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

    /** A v4 key, the only version keys.openpgp.org serves. */
    private static PGPPublicKeyRing generate(String userId) throws Exception {
        return new BcOpenPGPApi().generateKey(PublicKeyPacket.VERSION_4)
                .ed25519x25519Key(userId)
                .addSigningSubkey()
                .build()
                .toCertificate()
                .getPGPPublicKeyRing();
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
