package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringReader;
import org.junit.jupiter.api.Test;

class RulePolicyTest {

    private static SigmundConfig parse(String yaml) {
        return SigmundConfigParser.parse("<test>", new StringReader(yaml));
    }

    private static ArtifactCoords coords(String namespace, String name, String version) {
        return new ArtifactCoords(namespace, name, "", "jar", version);
    }

    @Test
    void compilesAndMatchesMostSpecific() {
        var doc = parse("""
                signers: { a: "a@x.io", b: "b@x.io" }
                issuers: [keys.openpgp.org]
                rules:
                  - match: ["com.acme.*"]
                    requires: [a]
                  - match: ["com.acme.secret.*"]
                    requires: [b]
                """);
        var policy = RulePolicy.compile(doc.trustPolicySpec(), doc.signers());
        assertThat(policy.matchRule(coords("com.acme.secret", "x", "1")).requirement().clauses())
                .hasSize(1);
        assertThat(policy.matchRule(coords("com.acme.other", "y", "1"))).isNotNull();
        assertThat(policy.matchRule(coords("org.other", "z", "1"))).isNull();
    }

    @Test
    void undefinedSignerRefIsErrorAtCompile() {
        var doc = parse("rules: [{ match: [\"*\"], requires: [ghost] }]");
        assertThatThrownBy(() -> RulePolicy.compile(doc.trustPolicySpec(), doc.signers()))
                .isInstanceOf(PolicyConfigException.class).hasMessageContaining("ghost");
    }

    @Test
    void specificityTieIsErrorAtCompile() {
        var doc = parse("""
                signers: { a: "a@x.io" }
                issuers: [keys.openpgp.org]
                rules:
                  - match: ["com.acme.*"]
                    requires: [a]
                  - match: ["com.acme.*"]
                    requires: [a]
                """);
        assertThatThrownBy(() -> RulePolicy.compile(doc.trustPolicySpec(), doc.signers()))
                .isInstanceOf(PolicyConfigException.class).hasMessageContaining("specificity");
    }

    @Test
    void catchAllMatchesEverythingElse() {
        var doc = parse("""
                signers: { a: "a@x.io" }
                issuers: [keys.openpgp.org]
                rules:
                  - match: ["com.acme.*"]
                    requires: [a]
                  - match: ["*"]
                    on-no-claim: ignore
                """);
        var policy = RulePolicy.compile(doc.trustPolicySpec(), doc.signers());
        assertThat(policy.matchRule(coords("org.other", "x", "1")).patterns().get(0).specificity())
                .isEqualTo(0);
    }

    @Test
    void signingIgnoresRuleErrors() {
        // a spec with a bad rule parses fine and is never compiled on the signing path
        var config = parse("""
                signing: { signer: alice }
                signers: { alice: { pgp4: "4AEE18F83AFDEB23000000000000000000000000" } }
                rules: [{ match: ["*"], requires: [ghost] }]
                """);
        assertThat(config.signingConfig().signer()).isEqualTo("alice");
    }
}
