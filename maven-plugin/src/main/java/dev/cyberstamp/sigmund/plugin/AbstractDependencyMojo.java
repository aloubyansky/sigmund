package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.PolicyConfigException;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.Exclusion;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.DependencyRequest;
import org.eclipse.aether.resolution.DependencyResolutionException;

/**
 * Base class for Mojos that iterate over project dependencies and inspect their signatures.
 */
abstract class AbstractDependencyMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    @Inject
    protected RepositorySystem repoSystem;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    protected RepositorySystemSession repoSession;

    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true)
    protected List<RemoteRepository> remoteRepos;

    @Parameter(property = "sigmund.trustConfig", defaultValue = "${project.basedir}/sigmund.yaml")
    protected File trustConfigFile;

    @Parameter(property = "sigmund.resolveSigners")
    protected Boolean resolveSigners;

    @Parameter(property = "sigmund.keyservers")
    protected String keyservers;

    @Parameter(property = "sigmund.sqHome")
    protected File sqHome;

    @Parameter(property = "sigmund.gpgHome")
    protected File gpgHome;

    @Parameter(property = "sigmund.includeTestDependencies", defaultValue = "false")
    protected boolean includeTestDependencies;

    @Parameter(property = "sigmund.importToKeyring")
    protected Boolean importToKeyring;

    @Parameter(property = "sigmund.skip", defaultValue = "false")
    protected boolean skip;

    List<ArtifactCoords> resolveDependencies() throws MojoExecutionException {
        CollectRequest collectRequest = new CollectRequest();
        collectRequest.setRepositories(remoteRepos);
        collectRequest.setRootArtifact(new DefaultArtifact(
                project.getGroupId(), project.getArtifactId(), null, "pom", project.getVersion()));

        for (org.apache.maven.model.Dependency dep : project.getDependencies()) {
            if (!includeTestDependencies && Artifact.SCOPE_TEST.equals(dep.getScope())) {
                continue;
            }
            collectRequest.addDependency(toAetherDependency(dep));
        }

        if (project.getDependencyManagement() != null) {
            for (org.apache.maven.model.Dependency dep : project.getDependencyManagement().getDependencies()) {
                collectRequest.addManagedDependency(toAetherDependency(dep));
            }
        }

        DependencyRequest request = new DependencyRequest(collectRequest, null);
        DependencyNode root;
        try {
            root = repoSystem.resolveDependencies(repoSession, request).getRoot();
        } catch (DependencyResolutionException e) {
            throw new MojoExecutionException("Failed to resolve dependencies", e);
        }

        List<ArtifactCoords> artifacts = new ArrayList<>();
        collectArtifacts(root, artifacts);
        return artifacts;
    }

    private void collectArtifacts(DependencyNode node, List<ArtifactCoords> artifacts) {
        if (node.getDependency() != null) {
            org.eclipse.aether.artifact.Artifact a = node.getArtifact();
            if (a != null && a.getFile() != null) {
                artifacts.add(new ArtifactCoords(
                        a.getGroupId(), a.getArtifactId(),
                        a.getClassifier() != null ? a.getClassifier() : "",
                        a.getExtension(), a.getVersion()));
            }
        }
        for (DependencyNode child : node.getChildren()) {
            collectArtifacts(child, artifacts);
        }
    }

    private Dependency toAetherDependency(org.apache.maven.model.Dependency dep) {
        DefaultArtifact artifact = new DefaultArtifact(
                dep.getGroupId(), dep.getArtifactId(),
                dep.getClassifier() != null ? dep.getClassifier() : "",
                dep.getType() != null ? dep.getType() : "jar",
                dep.getVersion());
        List<Exclusion> exclusions = new ArrayList<>();
        if (dep.getExclusions() != null) {
            for (org.apache.maven.model.Exclusion e : dep.getExclusions()) {
                exclusions.add(new Exclusion(
                        e.getGroupId() != null ? e.getGroupId() : "*",
                        e.getArtifactId() != null ? e.getArtifactId() : "*",
                        "*", "*"));
            }
        }
        return new Dependency(artifact, dep.getScope(), "true".equals(dep.getOptional()), exclusions);
    }

    /**
     * Loads and parses the configuration file. Returns {@code null} if the
     * file does not exist.
     */
    protected SigmundConfig loadSigmundConfig() throws MojoExecutionException {
        if (trustConfigFile == null || !trustConfigFile.exists()) {
            return null;
        }
        try {
            return SigmundConfig.parse(trustConfigFile.toPath());
        } catch (PolicyConfigException e) {
            throw new MojoExecutionException("Failed to parse config: " + trustConfigFile, e);
        }
    }

    /**
     * Merges the Mojo parameters with the tools configuration from the config file.
     */
    protected ToolsConfig resolveToolsConfig(ToolsConfig fileConfig) {
        boolean effectiveResolve = resolveSigners != null
                ? resolveSigners
                : fileConfig.resolveSigners();
        List<String> effectiveKeyservers = keyservers != null
                ? SignatureInspector.parseKeyservers(keyservers)
                : fileConfig.keyservers();
        if (effectiveResolve && effectiveKeyservers.isEmpty()) {
            effectiveKeyservers = List.of(ToolsConfig.DEFAULT_KEYSERVER);
        }
        boolean effectiveImport = importToKeyring != null
                ? importToKeyring
                : fileConfig.importToKeyring();
        Map<String, Map<String, String>> mergedTools = new HashMap<>(fileConfig.tools());
        for (var override : toolOverrides().entrySet()) {
            mergedTools.merge(override.getKey(), override.getValue(), (existing, incoming) -> {
                var merged = new HashMap<>(existing);
                merged.putAll(incoming);
                return Map.copyOf(merged);
            });
        }
        return new ToolsConfig(
                effectiveResolve, effectiveImport,
                effectiveKeyservers, mergedTools, fileConfig.toolPriority());
    }

    protected Sigmund buildSigmund(ToolsConfig toolsConfig) throws MojoExecutionException {
        return Sigmund.builder()
                .toolsConfig(toolsConfig)
                .build();
    }

    protected Map<String, Map<String, String>> toolOverrides() {
        var overrides = new HashMap<>(SequoiaHomeResolver.toolOverrides(sqHome));
        if (gpgHome != null) {
            String gpgHomePath = gpgHome.toPath().toString();
            overrides.put("gpg", Map.of("home", gpgHomePath));
            overrides.put("bc", Map.of(
                    "gnupg-home", gpgHomePath,
                    "cert-d-home", gpgHomePath + "/cert-d",
                    "bc-private-home", gpgHomePath + "/bc-private"));
        }
        return overrides;
    }

    protected SignatureInspector buildInspector(ToolsConfig toolsConfig)
            throws MojoExecutionException {
        Sigmund sigmund = buildSigmund(toolsConfig);
        return SignatureInspector.builder()
                .log(getLog())
                .sigmund(sigmund)
                .repoSystem(repoSystem).repoSession(repoSession).remoteRepos(remoteRepos)
                .sqHome(sqHome)
                .build();
    }
}
