package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class RequirementTest {

    private static final Path DUMMY_EVIDENCE = Path.of("dummy.asc");

    @Test
    void conjunctionRequiresAllClauses() {
        var req = requirement(clause("alice"), clause("ci-a", "ci-b"));   // alice AND (ci-a OR ci-b)
        assertThat(req.evaluate(List.of(claimFrom("alice"))).satisfied()).isFalse();
        assertThat(req.evaluate(List.of(claimFrom("alice"), claimFrom("ci-b"))).satisfied()).isTrue();
    }

    @Test
    void extraUnlistedClaimPartitioned() {
        var req = requirement(clause("alice"));
        var ev = req.evaluate(List.of(claimFrom("alice"), claimFrom("mallory")));
        assertThat(ev.satisfied()).isTrue();
        assertThat(ev.unaccepted()).hasSize(1);   // mallory → roll-up applies extra-claims
    }

    @Test
    void allClausesSatisfiedByDifferentClaims() {
        var req = requirement(clause("alice"), clause("bob"));
        var ev = req.evaluate(List.of(claimFrom("alice"), claimFrom("bob")));
        assertThat(ev.satisfied()).isTrue();
        assertThat(ev.accepted()).hasSize(2);
        assertThat(ev.unaccepted()).isEmpty();
    }

    @Test
    void singleClauseWithMultipleSigners() {
        var req = requirement(clause("alice", "bob"));   // alice OR bob
        assertThat(req.evaluate(List.of(claimFrom("alice"))).satisfied()).isTrue();
        assertThat(req.evaluate(List.of(claimFrom("bob"))).satisfied()).isTrue();
        assertThat(req.evaluate(List.of(claimFrom("mallory"))).satisfied()).isFalse();
    }

    @Test
    void claimMatchingMultipleClausesCountedOnce() {
        var req = requirement(clause("alice"), clause("alice", "bob"));
        var ev = req.evaluate(List.of(claimFrom("alice")));
        assertThat(ev.satisfied()).isTrue();
        assertThat(ev.accepted()).hasSize(1);   // alice appears in both clauses but counted once
    }

    @Test
    void emptyClaimsListUnsatisfied() {
        var req = requirement(clause("alice"));
        var ev = req.evaluate(List.of());
        assertThat(ev.satisfied()).isFalse();
        assertThat(ev.accepted()).isEmpty();
        assertThat(ev.unaccepted()).isEmpty();
    }

    @Test
    void nullClaimsListTreatedAsEmpty() {
        var req = requirement(clause("alice"));
        var ev = req.evaluate(null);
        assertThat(ev.satisfied()).isFalse();
        assertThat(ev.accepted()).isEmpty();
        assertThat(ev.unaccepted()).isEmpty();
    }

    // Helper methods to build requirements and claims

    private static Requirement requirement(Clause... clauses) {
        return new Requirement(List.of(clauses), List.of());
    }

    private static Clause clause(String... signerIds) {
        List<SignerIdentity> signers = List.of(signerIds).stream()
                .map(RequirementTest::signer)
                .toList();
        return new Clause(signers);
    }

    private static SignerIdentity signer(String id) {
        // Create a unique fingerprint based on the signer ID
        String fingerprint = String.format("%040d", id.hashCode() & 0xFFFFFFFFL)
                .replace('-', '0');
        return new SignerIdentity(id, List.of(KeyCredential.openPgp(fingerprint)));
    }

    private static ClaimResult claimFrom(String signerId) {
        SignerIdentity signer = signer(signerId);
        return new ClaimResult(
                "openpgp",
                ClaimOutcome.VERIFIED,
                null,
                signer.credentials(),
                signerId + " <" + signerId + "@example.com>",
                AttesterRole.UNKNOWN,
                TrustRootRef.unknown(),
                new EvidenceRef(DUMMY_EVIDENCE, DigestSet.sha256("dummy"), Evidence.SOURCE_SIDECAR),
                null,
                ClaimTimeSource.SIGNER,
                Instant.EPOCH,
                "RSA",
                "bc");
    }
}
