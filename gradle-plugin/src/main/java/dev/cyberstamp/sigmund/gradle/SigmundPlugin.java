package dev.cyberstamp.sigmund.gradle;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

public class SigmundPlugin implements Plugin<Project> {

    @Override
    public void apply(Project project) {
        SigmundExtension extension = project.getExtensions()
                .create("sigmund", SigmundExtension.class);

        project.getTasks().register("sigmundVerifySignature", VerifySignatureTask.class, task -> {
            task.setGroup("sigmund");
            task.setDescription("Verifies all signatures in an ASC file.");
            task.getConfigFile().set(extension.getConfigFile());
            task.getSqHome().set(extension.getSqHome());
            task.getGpgHome().set(extension.getGpgHome());
            task.onlyIf(t -> !extension.getSkip().get());
        });

        project.getTasks().register("sigmundInspectSigner", InspectSignerTask.class, task -> {
            task.setGroup("sigmund");
            task.setDescription("Inspects a signer identity across all available sources.");
            task.getConfigFile().set(extension.getConfigFile());
            task.getSqHome().set(extension.getSqHome());
            task.getGpgHome().set(extension.getGpgHome());
            task.onlyIf(t -> !extension.getSkip().get());
        });

        project.getTasks().register("sigmundSignerInfo", SignerInfoTask.class, task -> {
            task.setGroup("sigmund");
            task.setDescription("Displays signing tool and identity information.");
            task.getConfigFile().set(extension.getConfigFile());
            task.getSqHome().set(extension.getSqHome());
            task.getGpgHome().set(extension.getGpgHome());
            task.onlyIf(t -> !extension.getSkip().get());
        });

        project.getTasks().register("sigmundVerify", VerifyTask.class, task -> {
            task.setGroup("sigmund");
            task.setDescription("Verifies dependency signatures against trust policy.");
            task.getConfigFile().set(extension.getConfigFile());
            task.getSqHome().set(extension.getSqHome());
            task.getGpgHome().set(extension.getGpgHome());
            task.onlyIf(t -> !extension.getSkip().get());
        });

        project.getTasks().register("sigmundSign", SignTask.class, task -> {
            task.setGroup("sigmund");
            task.setDescription("Signs artifacts using the sigmund tool chain.");
            task.getConfigFile().set(extension.getConfigFile());
            task.getSqHome().set(extension.getSqHome());
            task.getGpgHome().set(extension.getGpgHome());
            task.onlyIf(t -> !extension.getSkip().get());
        });

        project.getTasks().register("sigmundDependencySigners", DependencySignersTask.class, task -> {
            task.setGroup("sigmund");
            task.setDescription("Reports signer information for all dependencies.");
            task.getConfigFile().set(extension.getConfigFile());
            task.getSqHome().set(extension.getSqHome());
            task.getGpgHome().set(extension.getGpgHome());
            task.onlyIf(t -> !extension.getSkip().get());
        });
    }
}
