package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.SigningInfo;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "signer-info", description = "Display signing tool and identity information", mixinStandardHelpOptions = true)
public class SignerInfoCommand implements Callable<Integer> {

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @CommandLine.Option(names = { "--profile" }, description = "Signing profile to display (default: use the default profile)")
    private String profile;

    @Override
    public Integer call() {
        try {
            SigmundConfig config = configMixin.loadConfig();
            Sigmund sigmund = SigningSupport.buildSigningSigmund(config, sqHomeMixin);

            Signer signer = profile != null
                    ? sigmund.signer(profile)
                    : sigmund.signer();

            List<SigningInfo> infos = signer.signingInfo();
            if (infos.isEmpty()) {
                System.out.println("No signing identity information available");
                return 0;
            }

            if (profile != null) {
                System.out.println("Profile: " + profile);
            }
            for (SigningInfo info : infos) {
                System.out.println(info.display());
            }
            return 0;
        } catch (Exception e) {
            System.err.println("Error: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
            return 1;
        }
    }
}
