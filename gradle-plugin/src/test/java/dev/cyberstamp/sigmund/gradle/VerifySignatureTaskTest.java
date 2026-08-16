package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;

class VerifySignatureTaskTest {

    @Test
    void taskHasExpectedProperties() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        VerifySignatureTask task = (VerifySignatureTask) project.getTasks()
                .getByName("sigmundVerifySignature");
        assertThat(task.getGroup()).isEqualTo("sigmund");
        assertThat(task.getLenient().get()).isFalse();
    }
}
