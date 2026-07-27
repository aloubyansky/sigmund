package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigningOutput;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "sign", description = "Create a hybrid signature combining GPG and PQC", mixinStandardHelpOptions = true)
public class SignCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to sign")
    private String file;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @CommandLine.Option(names = { "--output" }, description = "Output signature file path (default: <file>.asc)")
    private String output;

    @Override
    public Integer call() {
        try {
            SigmundConfig config = configMixin.loadConfig();
            Path artifactFile = Path.of(file);
            Path outputFile = resolveOutputFile(artifactFile);

            Sigmund sigmund = buildSigningSigmund(config);
            Path outputDir = outputFile.getParent();
            if (outputDir == null) {
                outputDir = Path.of(".");
            }
            SigningOutput result = sigmund.signer()
                    .sign(artifactFile, outputDir);

            if (!result.files().isEmpty()) {
                Path produced = result.files().get(0).path();
                if (!produced.equals(outputFile)) {
                    Files.move(produced, outputFile, StandardCopyOption.REPLACE_EXISTING);
                }
            }

            System.out.println("Signature created successfully!");
            System.out.println();
            System.out.println("Signature file: " + outputFile.toAbsolutePath());
            return 0;
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    private Sigmund buildSigningSigmund(SigmundConfig config) {
        return SigningSupport.buildSigningSigmund(config, sqHomeMixin);
    }

    private Path resolveOutputFile(Path artifactFile) {
        if (output != null && !output.isEmpty()) {
            return Paths.get(output);
        }
        return Paths.get(artifactFile.toString() + ".asc");
    }

    private void printErrorMessage(Exception e) {
        System.err.println("Error creating signature:");
        String message = e.getMessage();
        System.err.println("  " + (message != null && !message.isEmpty() ? message : e.getClass().getSimpleName()));
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - Signing tools are configured in sigmund.yaml or via CLI flags");
        System.err.println("  - The required keys exist and are accessible");
        System.err.println("  - The artifact file exists and is readable");
    }
}
