package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;

/**
 * The cryptographic algorithms every OpenPGP backend accepts when verifying, defined once and
 * translated into each backend's own policy.
 *
 * <p>
 * Backends ship different defaults, and Sequoia's can be replaced by the host's system crypto
 * policy, so left alone the same artifact could verify under one toolchain and fail under
 * another — on one machine and not the next. Algorithm acceptance changes what is accepted,
 * so it is part of the verdict, not of how verification runs; it must not depend on which
 * backend answered or where it ran.
 *
 * <p>
 * On top of each backend's modern defaults, Sigmund accepts what artifacts in Maven
 * repositories have long been signed with:
 * <ul>
 * <li><b>SHA-1 and RIPEMD-160 document signatures</b>, which older releases carry.</li>
 * <li><b>SHA-1 and RIPEMD-160 self-signatures at any date</b> — the user ID certifications and
 * subkey bindings that bind a key to its certificate. Many active release keys are still bound
 * this way. The practical attack on SHA-1 is a chosen-prefix collision, which needs the victim to
 * sign data the attacker prepared; a self-signature is made by the key's owner over their own
 * key material, so that attack does not apply. GnuPG exempts self-signatures for the same
 * reason. Sigmund relies only on self-signatures, never on third-party certifications.</li>
 * <li><b>RSA and DSA keys from 1024 bits.</b></li>
 * </ul>
 * GnuPG's defaults already accept all of these. A signature that uses anything else is not a
 * failed signature: rejecting an algorithm is a verifier decision, reported as
 * {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}.
 */
final class VerificationAlgorithms {

    /**
     * The Sequoia crypto policy matching this definition, in {@code sequoia-policy-config}
     * format. Sequoia judges a hash by the property a signature needs: a document signature
     * needs collision resistance, a self-signature only second pre-image resistance. Anything
     * not listed keeps Sequoia's built-in default rather than the host's system policy.
     */
    static final String SEQUOIA_POLICY = """
            [hash_algorithms]
            sha1.collision_resistance = "always"
            sha1.second_preimage_resistance = "always"
            ripemd160.collision_resistance = "always"
            ripemd160.second_preimage_resistance = "always"

            [asymmetric_algorithms]
            rsa1024 = "always"
            dsa1024 = "always"
            dsa2048 = "always"
            dsa3072 = "always"
            dsa4096 = "always"
            """;

    private static volatile Path sequoiaPolicyFile;

    private VerificationAlgorithms() {
    }

    /**
     * Returns the Bouncy Castle policy matching this definition.
     *
     * @return a new policy, which callers may hold for the life of a verifier
     */
    static OpenPGPPolicy bouncyCastlePolicy() {
        return new OpenPGPDefaultPolicy()
                .acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA1)
                .acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.RIPEMD160)
                .acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA1)
                .acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.RIPEMD160)
                .acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.RSA_GENERAL, 1024)
                .acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.RSA_SIGN, 1024)
                .acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.DSA, 1024);
    }

    /**
     * Returns a file holding {@link #SEQUOIA_POLICY}, for {@code SEQUOIA_CRYPTO_POLICY}. Written
     * once per process and removed when it exits.
     *
     * @return the policy file
     * @throws UncheckedIOException if the file cannot be written
     */
    static Path sequoiaPolicyFile() {
        Path file = sequoiaPolicyFile;
        if (file == null) {
            synchronized (VerificationAlgorithms.class) {
                file = sequoiaPolicyFile;
                if (file == null) {
                    file = writeSequoiaPolicy();
                    sequoiaPolicyFile = file;
                }
            }
        }
        return file;
    }

    private static Path writeSequoiaPolicy() {
        try {
            Path file = Files.createTempFile("sigmund-sequoia-policy-", ".toml");
            file.toFile().deleteOnExit();
            return Files.writeString(file, SEQUOIA_POLICY);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write the Sequoia crypto policy", e);
        }
    }
}
