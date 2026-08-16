package dev.cyberstamp.sigmund.gradle;

import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;
import org.gradle.api.file.RegularFileProperty;
import javax.inject.Inject;

public abstract class SigmundExtension {

    @Inject
    public SigmundExtension(ObjectFactory objects) {
        getSkip().convention(false);
    }

    public abstract RegularFileProperty getConfigFile();

    public abstract RegularFileProperty getSqHome();

    public abstract RegularFileProperty getGpgHome();

    public abstract Property<Boolean> getSkip();
}
