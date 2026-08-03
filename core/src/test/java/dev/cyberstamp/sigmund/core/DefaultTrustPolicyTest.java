package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link DefaultTrustPolicy} including the {@code EMPTY} constant,
 * constructor behavior, and signer matching.
 */
class DefaultTrustPolicyTest {

    @Nested
    class EmptyConstant {

        @Test
        void emptyHasAllListedEvidencePolicy() {
            assertEquals(ListedEvidencePolicy.ALL, DefaultTrustPolicy.EMPTY.listedEvidence());
        }

        @Test
        void emptyHasIgnoreUnlistedEvidencePolicy() {
            assertEquals(UnlistedEvidencePolicy.IGNORE, DefaultTrustPolicy.EMPTY.unlistedEvidence());
        }

        @Test
        void emptyHasFailUntrustedPolicy() {
            assertEquals(UntrustedPolicy.FAIL, DefaultTrustPolicy.EMPTY.onUntrusted());
        }

        @Test
        void emptyReturnsNoExpectedSigners() {
            var artifact = testArtifact("org.example", "lib", "1.0");
            assertTrue(DefaultTrustPolicy.EMPTY.expectedSigners(artifact).isEmpty());
        }
    }

    @Nested
    class ConstructorBehavior {

        @Test
        void listedEvidencePolicy() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ALL,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);
            assertEquals(ListedEvidencePolicy.ALL, policy.listedEvidence());
        }

        @Test
        void unlistedEvidencePolicy() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ANY,
                    UnlistedEvidencePolicy.WARN, UntrustedPolicy.FAIL);
            assertEquals(UnlistedEvidencePolicy.WARN, policy.unlistedEvidence());
        }

        @Test
        void untrustedPolicy() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ANY,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.WARN);
            assertEquals(UntrustedPolicy.WARN, policy.onUntrusted());
        }

        @Test
        void storesAllValues() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ANY,
                    UnlistedEvidencePolicy.REQUIRE, UntrustedPolicy.WARN);
            assertEquals(ListedEvidencePolicy.ANY, policy.listedEvidence());
            assertEquals(UnlistedEvidencePolicy.REQUIRE, policy.unlistedEvidence());
            assertEquals(UntrustedPolicy.WARN, policy.onUntrusted());
        }
    }

    @Nested
    class SignerMatching {

        @Test
        void expectedSignersReturnsEmptyForUnmatchedPattern() {
            var signer = new SignerIdentity("alice", "Alice",
                    List.of(new FingerprintCredential("openpgp4", "AABB")));
            var policy = new DefaultTrustPolicy(
                    Map.of("org.example:*", List.of(signer)),
                    List.of(), ListedEvidencePolicy.ALL,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);

            var unmatched = testArtifact("com.other", "lib", "1.0");
            assertTrue(policy.expectedSigners(unmatched).isEmpty());
        }

        @Test
        void expectedSignersReturnsSignersForMatchedPattern() {
            var signer = new SignerIdentity("alice", "Alice",
                    List.of(new FingerprintCredential("openpgp4", "AABB")));
            var policy = new DefaultTrustPolicy(
                    Map.of("org.example:*", List.of(signer)),
                    List.of(), ListedEvidencePolicy.ALL,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);

            var matched = testArtifact("org.example", "lib", "1.0");
            var signers = policy.expectedSigners(matched);
            assertNotNull(signers);
            assertEquals(1, signers.size());
            assertEquals("alice", signers.get(0).id());
        }
    }

    private static ArtifactIdentity testArtifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return ns;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String version() {
                return version;
            }
        };
    }
}
