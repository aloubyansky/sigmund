package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;

class SignTaskTest {

    @Test
    void taskIsRegisteredWithCorrectGroup() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        assertThat(project.getTasks().findByName("sigmundSign")).isNotNull();
        assertThat(project.getTasks().getByName("sigmundSign").getGroup())
                .isEqualTo("sigmund");
    }
}
