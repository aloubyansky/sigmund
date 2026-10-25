package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class SigmundSchemaTest {

    private static final String PREFIX = "https://raw.githubusercontent.com/cyberstamp/sigmund/";

    @Test
    void aReleaseIsEditedAgainstTheSchemaOfItsTag() {
        assertThat(SigmundSchema.url("1.2.3"))
                .isEqualTo(PREFIX + "1.2.3/core/src/main/resources/sigmund.schema.json");
    }

    @Test
    void aSnapshotIsEditedAgainstTheSchemaOnMain() {
        assertThat(SigmundSchema.url("1.2.3-SNAPSHOT"))
                .isEqualTo(PREFIX + "main/core/src/main/resources/sigmund.schema.json");
    }

    /** The published URL names the file in the repository, which is what a tag serves. */
    @Test
    void thePublishedPathIsTheSchemaInTheRepository() {
        String path = SigmundSchema.url("main").substring((PREFIX + "main/").length());

        assertThat(Files.exists(Path.of("..").resolve(path))).as(path).isTrue();
        assertThat(SigmundSchema.class.getResource("/" + SigmundSchema.RESOURCE)).isNotNull();
    }

    @Test
    void theModelineNamesTheUrlOfThisVersion() {
        assertThat(SigmundSchema.modeline()).isEqualTo("# yaml-language-server: $schema=" + SigmundSchema.url());
        assertThat(SigmundSchema.url()).isEqualTo(SigmundSchema.url(SigmundVersion.VERSION));
    }
}
