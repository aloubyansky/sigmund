package dev.cyberstamp.sigmund.core;

import java.util.Objects;
import java.util.StringJoiner;

/**
 * A Sigstore certificate-based credential with named, nullable fields
 * corresponding to Sigstore certificate extensions.
 * <p>
 * A {@code null} field means "don't match on this." Matching checks that
 * every non-null field in the <em>configured</em> credential equals the
 * corresponding field in the <em>extracted</em> credential. Fields not
 * configured (null) are ignored. This enables flexible trust policies:
 * matching on {@code issuer} + {@code sourceRepositoryUri} trusts all
 * releases from a repository, while adding {@code subject} pins to a
 * specific workflow run.
 *
 * @see Credential
 */
public final class SigstoreCredential implements Credential {

    private final String issuer;
    private final String subject;
    private final String sourceRepositoryUri;
    private final String sourceRepositoryOwnerUri;
    private final String buildTrigger;
    private final String buildConfigUri;
    private final String runnerEnvironment;

    private SigstoreCredential(Builder builder) {
        this.issuer = builder.issuer;
        this.subject = builder.subject;
        this.sourceRepositoryUri = builder.sourceRepositoryUri;
        this.sourceRepositoryOwnerUri = builder.sourceRepositoryOwnerUri;
        this.buildTrigger = builder.buildTrigger;
        this.buildConfigUri = builder.buildConfigUri;
        this.runnerEnvironment = builder.runnerEnvironment;
    }

    /**
     * Returns the fixed credential type {@code "sigstore"}.
     *
     * @return {@code "sigstore"}
     */
    @Override
    public String type() {
        return TYPE_SIGSTORE;
    }

    /**
     * Returns the OIDC issuer URL that signed the certificate.
     * <p>
     * For GitHub Actions, this is typically {@code "https://token.actions.githubusercontent.com"}.
     *
     * @return the issuer URL, or {@code null} if not set
     */
    public String issuer() {
        return issuer;
    }

    /**
     * Returns the OIDC subject claim from the certificate.
     * <p>
     * For GitHub Actions, this typically contains the workflow path and ref
     * (e.g., {@code "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0"}).
     *
     * @return the subject claim, or {@code null} if not set
     */
    public String subject() {
        return subject;
    }

    /**
     * Returns the source repository URI where the build occurred.
     * <p>
     * Extracted from the Sigstore certificate's source repository URI extension.
     *
     * @return the repository URI, or {@code null} if not set
     */
    public String sourceRepositoryUri() {
        return sourceRepositoryUri;
    }

    /**
     * Returns the source repository owner URI.
     * <p>
     * Identifies the organization or user who owns the repository where the build occurred.
     *
     * @return the repository owner URI, or {@code null} if not set
     */
    public String sourceRepositoryOwnerUri() {
        return sourceRepositoryOwnerUri;
    }

    /**
     * Returns the build trigger that initiated the workflow.
     * <p>
     * For GitHub Actions, this might be {@code "push"}, {@code "release"}, {@code "workflow_dispatch"}, etc.
     *
     * @return the build trigger, or {@code null} if not set
     */
    public String buildTrigger() {
        return buildTrigger;
    }

    /**
     * Returns the build configuration URI that produced the signature.
     * <p>
     * For GitHub Actions, this is the workflow file URI including the ref
     * (e.g., {@code "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"}).
     *
     * @return the build config URI, or {@code null} if not set
     */
    public String buildConfigUri() {
        return buildConfigUri;
    }

    /**
     * Returns the runner environment where the build executed.
     * <p>
     * For GitHub Actions, this is typically {@code "github-hosted"} or {@code "self-hosted"}.
     *
     * @return the runner environment, or {@code null} if not set
     */
    public String runnerEnvironment() {
        return runnerEnvironment;
    }

    /**
     * Returns a human-readable representation showing all non-null fields.
     * <p>
     * Format: {@code sigstore{field1=value1, field2=value2, ...}}
     *
     * @return a display string containing all configured fields
     */
    @Override
    public String displayName() {
        var sj = new StringJoiner(", ", "sigstore{", "}");
        if (issuer != null)
            sj.add("issuer=" + issuer);
        if (subject != null)
            sj.add("subject=" + subject);
        if (sourceRepositoryUri != null)
            sj.add("source-repository-uri=" + sourceRepositoryUri);
        if (sourceRepositoryOwnerUri != null)
            sj.add("source-repository-owner-uri=" + sourceRepositoryOwnerUri);
        if (buildTrigger != null)
            sj.add("build-trigger=" + buildTrigger);
        if (buildConfigUri != null)
            sj.add("build-config-uri=" + buildConfigUri);
        if (runnerEnvironment != null)
            sj.add("runner-environment=" + runnerEnvironment);
        return sj.toString();
    }

    /**
     * Checks whether this credential matches another credential.
     * <p>
     * Returns {@code true} only if the other credential is a {@link SigstoreCredential}
     * and every non-null field in {@code this} equals the corresponding field in
     * the other credential. Null fields in {@code this} are skipped (not matched).
     * A non-null field in {@code this} that is null in {@code other} does not match.
     *
     * @param other the credential to match against
     * @return {@code true} if all non-null fields match
     */
    @Override
    public boolean matches(Credential other) {
        if (!(other instanceof SigstoreCredential sc)) {
            return false;
        }
        if (issuer != null && !issuer.equals(sc.issuer))
            return false;
        if (subject != null && !subject.equals(sc.subject))
            return false;
        if (sourceRepositoryUri != null && !sourceRepositoryUri.equals(sc.sourceRepositoryUri))
            return false;
        if (sourceRepositoryOwnerUri != null && !sourceRepositoryOwnerUri.equals(sc.sourceRepositoryOwnerUri))
            return false;
        if (buildTrigger != null && !buildTrigger.equals(sc.buildTrigger))
            return false;
        if (buildConfigUri != null && !buildConfigUri.equals(sc.buildConfigUri))
            return false;
        if (runnerEnvironment != null && !runnerEnvironment.equals(sc.runnerEnvironment))
            return false;
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof SigstoreCredential sc))
            return false;
        return Objects.equals(issuer, sc.issuer)
                && Objects.equals(subject, sc.subject)
                && Objects.equals(sourceRepositoryUri, sc.sourceRepositoryUri)
                && Objects.equals(sourceRepositoryOwnerUri, sc.sourceRepositoryOwnerUri)
                && Objects.equals(buildTrigger, sc.buildTrigger)
                && Objects.equals(buildConfigUri, sc.buildConfigUri)
                && Objects.equals(runnerEnvironment, sc.runnerEnvironment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, subject, sourceRepositoryUri,
                sourceRepositoryOwnerUri, buildTrigger, buildConfigUri, runnerEnvironment);
    }

    /**
     * A builder for creating {@link SigstoreCredential} instances.
     * <p>
     * All fields are optional but at least one must be set. Use this to construct
     * trust policies by specifying only the fields you want to verify.
     */
    public static final class Builder {
        private String issuer;
        private String subject;
        private String sourceRepositoryUri;
        private String sourceRepositoryOwnerUri;
        private String buildTrigger;
        private String buildConfigUri;
        private String runnerEnvironment;

        /**
         * Sets the OIDC issuer URL.
         *
         * @param issuer the issuer URL
         * @return this builder
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Sets the OIDC subject claim.
         *
         * @param subject the subject claim
         * @return this builder
         */
        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        /**
         * Sets the source repository URI.
         *
         * @param sourceRepositoryUri the repository URI
         * @return this builder
         */
        public Builder sourceRepositoryUri(String sourceRepositoryUri) {
            this.sourceRepositoryUri = sourceRepositoryUri;
            return this;
        }

        /**
         * Sets the source repository owner URI.
         *
         * @param sourceRepositoryOwnerUri the repository owner URI
         * @return this builder
         */
        public Builder sourceRepositoryOwnerUri(String sourceRepositoryOwnerUri) {
            this.sourceRepositoryOwnerUri = sourceRepositoryOwnerUri;
            return this;
        }

        /**
         * Sets the build trigger.
         *
         * @param buildTrigger the build trigger type
         * @return this builder
         */
        public Builder buildTrigger(String buildTrigger) {
            this.buildTrigger = buildTrigger;
            return this;
        }

        /**
         * Sets the build configuration URI.
         *
         * @param buildConfigUri the build config URI
         * @return this builder
         */
        public Builder buildConfigUri(String buildConfigUri) {
            this.buildConfigUri = buildConfigUri;
            return this;
        }

        /**
         * Sets the runner environment.
         *
         * @param runnerEnvironment the runner environment type
         * @return this builder
         */
        public Builder runnerEnvironment(String runnerEnvironment) {
            this.runnerEnvironment = runnerEnvironment;
            return this;
        }

        /**
         * Builds the credential, validating that at least one field is set.
         * Blank strings are normalized to {@code null}.
         *
         * @return the credential
         * @throws IllegalArgumentException if all fields are null or blank
         */
        public SigstoreCredential build() {
            issuer = blankToNull(issuer);
            subject = blankToNull(subject);
            sourceRepositoryUri = blankToNull(sourceRepositoryUri);
            sourceRepositoryOwnerUri = blankToNull(sourceRepositoryOwnerUri);
            buildTrigger = blankToNull(buildTrigger);
            buildConfigUri = blankToNull(buildConfigUri);
            runnerEnvironment = blankToNull(runnerEnvironment);
            if (issuer == null && subject == null && sourceRepositoryUri == null
                    && sourceRepositoryOwnerUri == null && buildTrigger == null
                    && buildConfigUri == null && runnerEnvironment == null) {
                throw new IllegalArgumentException(
                        "At least one Sigstore credential field must be set");
            }
            return new SigstoreCredential(this);
        }

        private static String blankToNull(String s) {
            return s != null && s.isBlank() ? null : s;
        }
    }
}
