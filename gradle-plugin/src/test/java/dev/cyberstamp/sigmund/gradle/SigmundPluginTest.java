package dev.cyberstamp.sigmund.gradle;

import static org.assertj.core.api.Assertions.assertThat;

import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;

class SigmundPluginTest {

    @Test
    void pluginRegistersExtension() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        assertThat(project.getExtensions().findByName("sigmund"))
                .isNotNull()
                .isInstanceOf(SigmundExtension.class);
    }

    @Test
    void pluginRegistersTasks() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        assertThat(project.getTasks().findByName("sigmundSign")).isNotNull();
        assertThat(project.getTasks().findByName("sigmundVerify")).isNotNull();
        assertThat(project.getTasks().findByName("sigmundDependencySigners")).isNotNull();
        assertThat(project.getTasks().findByName("sigmundVerifySignature")).isNotNull();
        assertThat(project.getTasks().findByName("sigmundInspectSigner")).isNotNull();
        assertThat(project.getTasks().findByName("sigmundSignerInfo")).isNotNull();
    }

    @Test
    void extensionHasDefaults() {
        Project project = ProjectBuilder.builder().build();
        project.getPlugins().apply("dev.cyberstamp.sigmund");
        SigmundExtension ext = project.getExtensions().getByType(SigmundExtension.class);
        assertThat(ext.getSkip().get()).isFalse();
        assertThat(ext.getConfigFile().isPresent()).isFalse();
    }
}
