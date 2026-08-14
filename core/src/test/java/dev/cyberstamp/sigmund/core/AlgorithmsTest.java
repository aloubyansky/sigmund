package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class AlgorithmsTest {

    @Nested
    class AlgorithmName {

        @Test
        void rsa() {
            assertThat(Algorithms.algorithmName(1)).isEqualTo("RSA");
            assertThat(Algorithms.algorithmName(2)).isEqualTo("RSA");
            assertThat(Algorithms.algorithmName(3)).isEqualTo("RSA");
        }

        @Test
        void edDsa() {
            assertThat(Algorithms.algorithmName(22)).isEqualTo("EdDSA");
        }

        @Test
        void pqcComposites() {
            assertThat(Algorithms.algorithmName(30)).isEqualTo("ML-DSA-65+Ed25519");
            assertThat(Algorithms.algorithmName(31)).isEqualTo("ML-DSA-87+Ed448");
            assertThat(Algorithms.algorithmName(32)).isEqualTo("SLH-DSA-SHAKE-128s");
        }

        @Test
        void unknownIdReturnsNull() {
            assertThat(Algorithms.algorithmName(99)).isNull();
            assertThat(Algorithms.algorithmName(-1)).isNull();
        }
    }

    @Nested
    class IsPqcAlgorithm {

        @Test
        void pqcRange() {
            assertThat(Algorithms.isPqcAlgorithm(30)).isTrue();
            assertThat(Algorithms.isPqcAlgorithm(36)).isTrue();
            assertThat(Algorithms.isPqcAlgorithm(33)).isTrue();
        }

        @Test
        void classicalRange() {
            assertThat(Algorithms.isPqcAlgorithm(1)).isFalse();
            assertThat(Algorithms.isPqcAlgorithm(22)).isFalse();
            assertThat(Algorithms.isPqcAlgorithm(29)).isFalse();
        }

        @Test
        void outsideRange() {
            assertThat(Algorithms.isPqcAlgorithm(37)).isFalse();
            assertThat(Algorithms.isPqcAlgorithm(-1)).isFalse();
        }
    }

    @Nested
    class IsPqcAlgorithmName {

        @Test
        void pqcNames() {
            assertThat(Algorithms.isPqcAlgorithmName("ML-DSA-65+Ed25519")).isTrue();
            assertThat(Algorithms.isPqcAlgorithmName("ML-DSA-87+Ed448")).isTrue();
            assertThat(Algorithms.isPqcAlgorithmName("SLH-DSA-SHAKE-128s")).isTrue();
            assertThat(Algorithms.isPqcAlgorithmName("ML-KEM-768+X25519")).isTrue();
        }

        @Test
        void classicalNames() {
            assertThat(Algorithms.isPqcAlgorithmName("RSA")).isFalse();
            assertThat(Algorithms.isPqcAlgorithmName("EdDSA")).isFalse();
            assertThat(Algorithms.isPqcAlgorithmName("ECDSA")).isFalse();
        }

        @Test
        void unknownName() {
            assertThat(Algorithms.isPqcAlgorithmName("UNKNOWN")).isFalse();
        }

        @Test
        void nullName() {
            assertThat(Algorithms.isPqcAlgorithmName(null)).isFalse();
        }
    }

    @Nested
    class VersionLabel {

        @Test
        void v4() {
            assertThat(Algorithms.versionLabel(4)).isEqualTo("PGP4");
        }

        @Test
        void v6() {
            assertThat(Algorithms.versionLabel(6)).isEqualTo("PGP6");
        }

        @Test
        void otherPositive() {
            assertThat(Algorithms.versionLabel(3)).isEqualTo("PGP3");
            assertThat(Algorithms.versionLabel(5)).isEqualTo("PGP5");
        }

        @Test
        void zeroReturnsDash() {
            assertThat(Algorithms.versionLabel(0)).isEqualTo("-");
        }

        @Test
        void negativeReturnsDash() {
            assertThat(Algorithms.versionLabel(-1)).isEqualTo("-");
        }
    }
}
