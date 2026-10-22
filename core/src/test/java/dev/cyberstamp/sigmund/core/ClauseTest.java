package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class ClauseTest {

    private static final Path DUMMY_EVIDENCE = Path.of("dummy.asc");

    @Test
    void acceptsClaimFromAnySigner() {
        var alice = signer("alice", "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
        var bob = signer("bob", "DEADBEEF83AFDEB23468B2E5A2D7BAF3C1E9F5A1");
        var clause = new Clause(List.of(alice, bob));

        assertThat(clause.accepts(claimFrom(alice), List.of())).isTrue();
        assertThat(clause.accepts(claimFrom(bob), List.of())).isTrue();
    }

    @Test
    void rejectsClaimFromUnlistedSigner() {
        var alice = signer("alice", "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
        var bob = signer("bob", "DEADBEEF83AFDEB23468B2E5A2D7BAF3C1E9F5A1");
        var mallory = signer("mallory", "BAADF00D83AFDEB23468B2E5A2D7BAF3C1E9F5A1");
        var clause = new Clause(List.of(alice, bob));

        assertThat(clause.accepts(claimFrom(mallory), List.of())).isFalse();
    }

    @Test
    void acceptsIdentityCredentialWithMatchingIssuer() {
        var alice = new SignerIdentity("alice",
                List.of(IdentityCredential.email("keys.openpgp.org", "alice@example.com")));
        var clause = new Clause(List.of(alice));

        var claim = claimWithIdentity("keys.openpgp.org", "alice@example.com");
        assertThat(clause.accepts(claim, List.of())).isTrue();
    }

    @Test
    void acceptsIdentityCredentialWithDefaultIssuer() {
        var alice = new SignerIdentity("alice",
                List.of(IdentityCredential.email(null, "alice@example.com")));
        var clause = new Clause(List.of(alice));

        var claim = claimWithIdentity("keys.openpgp.org", "alice@example.com");
        assertThat(clause.accepts(claim, List.of("keys.openpgp.org"))).isTrue();
    }

    @Test
    void rejectsIdentityCredentialWithoutDefaultIssuer() {
        var alice = new SignerIdentity("alice",
                List.of(IdentityCredential.email(null, "alice@example.com")));
        var clause = new Clause(List.of(alice));

        var claim = claimWithIdentity("keys.openpgp.org", "alice@example.com");
        assertThat(clause.accepts(claim, List.of())).isFalse();
    }

    @Test
    void emptyClauseRejected() {
        assertThatThrownBy(() -> new Clause(List.of()))
                .isInstanceOf(PolicyConfigException.class)
                .hasMessageContaining("clause");
    }

    // Helper methods

    private static SignerIdentity signer(String id, String fingerprint) {
        return new SignerIdentity(id, List.of(KeyCredential.openPgp(fingerprint)));
    }

    private static ClaimResult claimFrom(SignerIdentity signer) {
        return new ClaimResult(
                "openpgp",
                ClaimOutcome.VERIFIED,
                null,
                signer.credentials(),
                signer.id() + " <" + signer.id() + "@example.com>",
                TrustRootRef.unknown(),
                new EvidenceRef(DUMMY_EVIDENCE, DigestSet.sha256("dummy"), Evidence.SOURCE_SIDECAR),
                null,
                ClaimTimeSource.SIGNER,
                Instant.EPOCH,
                "RSA",
                "bc");
    }

    private static ClaimResult claimWithIdentity(String issuer, String email) {
        var identity = IdentityCredential.email(issuer, email);
        return new ClaimResult(
                "sigstore",
                ClaimOutcome.VERIFIED,
                null,
                List.of(identity),
                email,
                TrustRootRef.unknown(),
                new EvidenceRef(DUMMY_EVIDENCE, DigestSet.sha256("dummy"), Evidence.SOURCE_SIDECAR),
                null,
                ClaimTimeSource.TRANSPARENCY_LOG,
                Instant.EPOCH,
                "ECDSA",
                "sigstore");
    }
}
