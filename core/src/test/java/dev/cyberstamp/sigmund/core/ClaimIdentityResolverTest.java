package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ClaimIdentityResolverTest {

    private static final ArtifactCoords COORDS = ArtifactCoords.parse("org.example:lib:1.0");
    private static final String PINNED = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final String NEW_KEY = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";
    private static final String ADDRESS = "release@example.org";
    private static final String DIRECTORY = IssuerKind.KEYS_OPENPGP_ORG;

    private final FakeDirectory directory = new FakeDirectory();

    @Nested
    class WhenPolicyNamesASignerByAddress {

        private final SignerIdentity release = new SignerIdentity("release", List.of(
                KeyCredential.openPgp(PINNED),
                IdentityCredential.email(null, ADDRESS)));

        @Test
        void aNewKeyIsAcceptedOnTheStrengthOfTheDirectory() {
            directory.addresses.put(NEW_KEY, List.of(ADDRESS));
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(claims.get(0).attesterCredentials())
                    .contains(IdentityCredential.email(DIRECTORY, ADDRESS));
            assertThat(satisfied(policy, claims)).isTrue();
        }

        @Test
        void aPinnedKeyNeedsNoLookup() {
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(PINNED));

            assertThat(directory.asked).isEmpty();
            assertThat(satisfied(policy, claims)).isTrue();
        }

        @Test
        void aKeyTheDirectoryVouchesForUnderAnotherAddressIsNotAccepted() {
            directory.addresses.put(NEW_KEY, List.of("someone@example.org"));
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(satisfied(policy, claims)).isFalse();
        }

        @Test
        void anUnreachableDirectoryLeavesTheClaimIndeterminate() {
            directory.failing = true;
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(claims.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE))
                    .isTrue();
            assertThat(claims.get(0).attesterCredentials())
                    .containsExactly(KeyCredential.openPgp(NEW_KEY));
        }

        @Test
        void disabledLookupsLeaveTheClaimIndeterminateWithoutAsking() {
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = new ClaimIdentityResolver(policy,
                    Map.of(DIRECTORY, directory), false).resolve(COORDS, List.of(claim(NEW_KEY)));

            assertThat(directory.asked).isEmpty();
            assertThat(claims.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE))
                    .isTrue();
        }

        @Test
        void aFailedSignatureIsNeverLookedUp() {
            TrustPolicy policy = policy(release, List.of(DIRECTORY));
            ClaimResult failed = new ClaimResult("openpgp", ClaimOutcome.FAILED, null, List.of(),
                    null, AttesterRole.UNKNOWN, TrustRootRef.unknown(), evidence(), null,
                    ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");

            resolve(policy, failed);

            assertThat(directory.asked).isEmpty();
        }
    }

    @Nested
    class WhenNoDirectoryCanVouch {

        @Test
        void aSignerNamedOnlyByKeyNeedsNoLookup() {
            SignerIdentity pinnedOnly = new SignerIdentity("release", List.of(KeyCredential.openPgp(PINNED)));

            resolve(policy(pinnedOnly, List.of(DIRECTORY)), claim(NEW_KEY));

            assertThat(directory.asked).isEmpty();
        }

        @Test
        void anAddressVouchedForOnlyByAnOidcIssuerNeedsNoLookup() {
            SignerIdentity oidcOnly = new SignerIdentity("release", List.of(
                    IdentityCredential.email("https://accounts.google.com", ADDRESS)));

            resolve(policy(oidcOnly, List.of()), claim(NEW_KEY));

            assertThat(directory.asked).isEmpty();
        }

        @Test
        void aDirectoryNamedInlineIsAskedWithoutBeingListed() {
            directory.addresses.put(NEW_KEY, List.of(ADDRESS));
            SignerIdentity inline = new SignerIdentity("release", List.of(
                    IdentityCredential.email(DIRECTORY, ADDRESS)));
            TrustPolicy policy = policy(inline, List.of());

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(satisfied(policy, claims)).isTrue();
        }
    }

    private List<ClaimResult> resolve(TrustPolicy policy, ClaimResult claim) {
        return new ClaimIdentityResolver(policy, Map.of(DIRECTORY, directory), true)
                .resolve(COORDS, List.of(claim));
    }

    private static TrustPolicy policy(SignerIdentity signer, List<String> issuers) {
        return new DefaultTrustPolicy(Map.of("org.example", List.of(signer)), List.of(),
                ListedEvidencePolicy.ALL, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL,
                issuers);
    }

    private static boolean satisfied(TrustPolicy policy, List<ClaimResult> claims) {
        List<ClaimResult> verified = claims.stream()
                .filter(c -> c.outcome() == ClaimOutcome.VERIFIED).toList();
        RequirementEvaluator.Evaluation evaluation = policy.requirements().evaluate(COORDS, verified);
        return evaluation != null && evaluation.satisfied();
    }

    private static ClaimResult claim(String fingerprint) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                List.of(KeyCredential.openPgp(fingerprint)), "Anyone <" + ADDRESS + ">",
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), evidence(), null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static EvidenceRef evidence() {
        return new EvidenceRef(Path.of("lib-1.0.jar.asc"),
                DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Evidence.SOURCE_SIDECAR);
    }

    private static final class FakeDirectory implements OpenPgpDirectory {
        final Map<String, List<String>> addresses = new HashMap<>();
        final List<String> asked = new ArrayList<>();
        boolean failing;

        @Override
        public String name() {
            return DIRECTORY;
        }

        @Override
        public List<String> verifiedAddresses(String fingerprint) throws IOException {
            asked.add(fingerprint);
            if (failing) {
                throw new IOException("unreachable");
            }
            return addresses.getOrDefault(fingerprint, List.of());
        }
    }
}
