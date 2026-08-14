package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignatureInspectorTest {

    @Nested
    class VersionLabelTests {

        @Test
        void v4ReturnsPGP4() {
            assertThat(SignatureInspector.versionLabel(4)).isEqualTo("PGP4");
        }

        @Test
        void v6ReturnsPGP6() {
            assertThat(SignatureInspector.versionLabel(6)).isEqualTo("PGP6");
        }

        @Test
        void v3ReturnsPGP3() {
            assertThat(SignatureInspector.versionLabel(3)).isEqualTo("PGP3");
        }

        @Test
        void v5ReturnsPGP5() {
            assertThat(SignatureInspector.versionLabel(5)).isEqualTo("PGP5");
        }

        @Test
        void zeroReturnsDash() {
            assertThat(SignatureInspector.versionLabel(0)).isEqualTo("-");
        }

        @Test
        void negativeReturnsDash() {
            assertThat(SignatureInspector.versionLabel(-1)).isEqualTo("-");
        }
    }

    @Nested
    class ParseKeyserversTests {

        @Test
        void singleServer() {
            assertThat(SignatureInspector.parseKeyservers("hkps://keys.openpgp.org"))
                    .isEqualTo(List.of("hkps://keys.openpgp.org"));
        }

        @Test
        void multipleServers() {
            assertThat(SignatureInspector.parseKeyservers(
                    "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org"))
                    .isEqualTo(List.of("hkps://keyserver.ubuntu.com", "hkps://keys.openpgp.org"));
        }

        @Test
        void withWhitespaceTrimmed() {
            assertThat(SignatureInspector.parseKeyservers("  hkps://a.com , hkps://b.com  "))
                    .isEqualTo(List.of("hkps://a.com", "hkps://b.com"));
        }

        @Test
        void emptySegmentsFiltered() {
            assertThat(SignatureInspector.parseKeyservers("hkps://a.com,,, "))
                    .isEqualTo(List.of("hkps://a.com"));
        }

        @Test
        void allEmptyReturnsEmptyList() {
            assertThat(SignatureInspector.parseKeyservers(",,,"))
                    .isEqualTo(List.of());
        }
    }
}
