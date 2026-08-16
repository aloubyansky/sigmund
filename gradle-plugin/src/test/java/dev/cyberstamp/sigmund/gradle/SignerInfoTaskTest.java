package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;

class SignerInfoTaskTest {

    @Test
    void taskHasExpectedProperties() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        SignerInfoTask task = (SignerInfoTask) project.getTasks()
                .getByName("sigmundSignerInfo");
        assertThat(task.getGroup()).isEqualTo("sigmund");
        assertThat(task.getProfile().isPresent()).isFalse();
    }
}
