package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;

class InspectSignerTaskTest {

    @Test
    void taskHasExpectedProperties() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        InspectSignerTask task = (InspectSignerTask) project.getTasks()
                .getByName("sigmundInspectSigner");
        assertThat(task.getGroup()).isEqualTo("sigmund");
        assertThat(task.getFingerprint().isPresent()).isFalse();
        assertThat(task.getEmail().isPresent()).isFalse();
    }
}
