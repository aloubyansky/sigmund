# Policy Schema (rules / match / requires) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `trust`/`signature-optional`/`policy` schema with the ADR-007 `rules`/`match`/`requires` model — conjunctive requirement clauses, `artifact-sets`, `extra-claims`, per-outcome enforcement, load-time issuer validation — consumed end-to-end by the `verify` goal, without coupling the signing use-case to any of it.

**Architecture:** Two representations of policy. (1) A **spec** form (`TrustPolicySpec` of `RuleSpec`s) is what the parser produces: pure data with signer-id strings, structurally validated, held on `SigmundConfig`. Signing reads only `signing`/`signers`/`tools` and never touches it. (2) A **compiled** form (`RulePolicy` of `Rule`s, each holding a `Requirement` of `Clause`s over *resolved* signers) is built by `RulePolicy.compile(spec, signers)` only when the verifier is constructed — that is where the semantic verification validation (signer-ref resolution, issuer ambiguity, specificity ties) and the `Requirement` compilation happen, so "fail-fast at load" means "when the verifier loads," and signing is immune. The verification core is otherwise untouched: `TrustVerifier` matches the rule once (recording the matched rule on `ArtifactResult`), evaluates via `rule.requirement().evaluate(claims)`, and `OutcomeRollup` applies the existing §3.2.1 roll-up. Enforcement (`fail`/`warn`/`ignore`) is resolved at the reporting/blocking seam from the recorded matched rule, replacing the removed `UntrustedPolicy` dial; the enforce/observe behaviour is the single switch "a policy file is present."

**Tech Stack:** Java 17, Jackson 2.22.3 (YAML `JsonNode` tree), JUnit Jupiter 6.1.3, AssertJ 3.27.7, Maven (Surefire 3.6.0).

**Spec:** `adr/007-policy-schema-and-enforcement.md` (revised 2026-10-11). Supporting: `adr/005-verification-result-model.md` (roll-up, outcomes, matched-rule reference), `adr/006-identity-and-credential-model.md` (credentials, issuers).

## Global Constraints

- Package `dev.cyberstamp.sigmund.core`, flat, under `core/src/main/java/dev/cyberstamp/sigmund/core/`; tests under `core/src/test/java/dev/cyberstamp/sigmund/core/`.
- **No backward compatibility.** The old `trust`/`signature-optional`/`policy` sections and the YAML key `artifacts` are removed outright; no aliases. A file using them is a config error (the v1 tripwire, Task 12).
- **Signing must not require the verification setup.** The parser produces structure usable for signing without resolving rules, compiling `Requirement`s, or validating issuers; those run only in `RulePolicy.compile(...)` on the verifier path. A signing run must not fail on a verification-only semantic error.
- **Package imports only; no inline FQNs. Defensive copies** (`List.copyOf`/`Map.copyOf`/`LinkedHashMap`) in records/constructors. Detailed javadoc on public types/methods; no comments on implementation.
- All config errors are `PolicyConfigException` with a human-readable message naming the file/location/fix.
- Build green at every commit. Core tests: `mvn -pl core test` (single class: `-Dtest=ClassName`). Iterate without formatting via `-Dno-format -Dformat.skip=true`.
- `mvn verify` runs strict javadoc (`failOnWarnings=true`): new/renamed public members need valid javadoc and `@link`/`@param` references.
- **Out of scope (later plans):** bootstrap emission (P2.8); observe as an explicit run-mode flag + scope parameter (P3.2/P3.3); reactor-root policy (P3.5); the detailed per-claim report (P3.7); the published JSON Schema (P2.16).

## Review Focus

Inputs the spec implies but no happy-path test exercises; each line's test is added to the owning task:

- **Zero-config build (no policy file).** Only `NOT_CONFIGURED`→`ignore` and `FAILED`→`fail` occur; passes unless a signature fails. → Task 9 `zeroConfigPassesExceptFailed`.
- **Policy present, artifact matches no rule.** `NOT_CONFIGURED`→`fail`. → Task 9 `notConfiguredFailsWhenPolicyPresent`.
- **Catch-all `"*"` with `on-no-claim: ignore`.** A partial policy tolerates the remainder; unmatched become the catch-all's outcome, not `NOT_CONFIGURED`. → Task 8 `catchAllMatchesEverythingElse` + Task 9 `catchAllIgnoreToleratesUnsigned`.
- **Extra verified claim from an unlisted signer, requirement already met.** `extra-claims: reject` → `UNSATISFIED`; `ignore` → `SATISFIED`. → Task 4 `extraUnlistedClaimPartitioned` + Task 9 rollup wiring.
- **Signing run with a verification-config semantic error.** A `sign` invocation whose config has an undefined signer-ref *in rules* must still sign (compile never runs). → Task 7 `signingIgnoresRuleErrors`.
- **Validation-error family:** specificity tie, 4-segment pattern, empty/scalar `requires`, undefined signer ref, issuer-less entry assertable by 0 or >1 listed issuers — all config-load errors at **compile** time (verification), structural ones at parse. → Tasks 6, 7, 11.

---

## File Structure

**New (core main):**
- `EnforcementAction.java` — enum `FAIL`, `WARN`, `IGNORE`; `parse(String)`, `blocks()`.
- `RuleSpec.java` — raw rule from the parser: patterns, raw CNF clause ids, enforcement overrides, location.
- `TrustPolicySpec.java` — raw policy: `List<RuleSpec>`, `ClaimSetMode extraClaims`, `Map<ArtifactOutcome,EnforcementAction> defaults`, `List<String> issuers`, `boolean present`.
- `Clause.java` — compiled OR-group: non-empty `List<SignerIdentity>`; `accepts(ClaimResult, List<String> defaultIssuers)`.
- `Requirement.java` — compiled conjunction: `List<Clause>`; `evaluate(List<ClaimResult> verifiedClaims)` → `RequirementEvaluator.Evaluation`.
- `Rule.java` — compiled rule: patterns, `Requirement`, enforcement overrides, location; `matches`/`specificity`; `toMatchedRule()`.
- `MatchedRule.java` — slim reference carried on results: pattern text, location, enforcement overrides.
- `RulePolicy.java` — `TrustPolicy` impl over `List<Rule>`; `static RulePolicy compile(TrustPolicySpec, SignersConfig)`; `EMPTY`.

**Modified (core main):**
- `TrustPolicy.java` — slim interface: `matchRule(ArtifactCoords)`→`Rule`, `requirements()`, `claimSetMode()`, `issuers()`, `enforcementFor(ArtifactOutcome, MatchedRule, boolean present)`; remove `expectedSigners`/`isUnsignedAllowed`/`listedEvidence`/`unlistedEvidence`/`onUntrusted`.
- `SigmundConfig.java` — component `trustPolicy` (`TrustPolicy`) → `trustPolicySpec` (`TrustPolicySpec`); `artifacts` → `artifactSets` (`ArtifactSetsConfig`).
- `ArtifactsConfig.java` → rename `ArtifactSetsConfig.java`; YAML key `artifact-sets`.
- `SigmundConfigParser.java` — parse `artifact-sets`, `rules`, `requires`/`any-of` (structural only → `RuleSpec`/`TrustPolicySpec`), `extra-claims`, `defaults`, `on-*`; v1 tripwire; delete the six old parse methods; **no** signer resolution / issuer semantic validation here.
- `ArtifactPattern.java` — permit catch-all `"*"` explicitly (confirm).
- `ArtifactResult.java` — add `MatchedRule matchedRule` component (nullable when none matched).
- `TrustVerifier.java` — match once, record `MatchedRule` on the result, evaluate via the compiled rule.
- `VerificationReport.java` — block via `enforcementFor(outcome, result.matchedRule(), present)`; drop role rendering.
- `ClaimResult.java` — remove `role`/`AttesterRole`.
- `IdentityEntryValidator.java` — add the 0/>1-asserting-issuer check; invoked from `compile`, not parse.

**Removed (core main):** `DefaultTrustPolicy.java`, `ListedEvidencePolicy.java`, `UnlistedEvidencePolicy.java`, `UntrustedPolicy.java`, `AttesterRole.java`.

**Modified (maven-plugin):** `VerifyMojo.java` — remove `onUntrusted`/`listedEvidence` params/overrides; compile the policy on the verify path (`RulePolicy.compile(config.trustPolicySpec(), config.signers())`); its inline `TrustPolicy` record updated or dropped. `SignMojo`/signing path confirmed to use only `config.signingConfig()`.

**Tests:** rename `ArtifactsConfigTest`→`ArtifactSetsConfigTest`; rewrite `SigmundConfigParserTest` trust/policy nests; new `RequirementTest`, `ClauseTest`, `RulePolicyTest` (compile), `EnforcementTest`; delete `DefaultTrustPolicyTest`; update `ClaimResultTest`, `ArtifactResultTest`, `TrustVerifierTest`, `VerificationReportTest`.

---

### Task 1: Rename `ArtifactsConfig` → `ArtifactSetsConfig`, YAML key `artifacts` → `artifact-sets`

Mechanical rename first, old trust parsing still intact, build green.

**Files:** rename `ArtifactsConfig.java`→`ArtifactSetsConfig.java`; `SigmundConfig.java` (component `artifactSets`, default `ArtifactSetsConfig.EMPTY`); `SigmundConfigParser.java` (`parseArtifactGroups` reads `"artifact-sets"`); rename `ArtifactsConfigTest.java`→`ArtifactSetsConfigTest.java`.

**Interfaces:** Produces `ArtifactSetsConfig` with the identical API (`EMPTY`, `get`, `isEmpty`, `expandTrustMappings`, `expandPatterns`) and `SigmundConfig.artifactSets()`.

- [ ] **Step 1: Failing test** in `SigmundConfigParserTest`:
```java
@Test
void artifactSetsKeyParsed() {
    var config = parse("""
            artifact-sets:
              apache-stack: [org.apache.maven.*]
            """);
    assertThat(config.artifactSets().get("apache-stack")).containsExactly("org.apache.maven.*");
}
```
- [ ] **Step 2: Run, expect FAIL** — `mvn -pl core test -Dtest=SigmundConfigParserTest#artifactSetsKeyParsed`
- [ ] **Step 3:** `git mv` the file, rename the type, rename the `SigmundConfig` component, read key `"artifact-sets"`. Verify no stragglers: `grep -rn ArtifactsConfig core/src`.
- [ ] **Step 4: Run, expect PASS** — `mvn -pl core test`
- [ ] **Step 5: Commit** — `git commit -am "refactor: rename artifacts config to artifact-sets"`

---

### Task 2: Add `EnforcementAction` enum

**Files:** `EnforcementAction.java`; `EnforcementActionTest.java`
**Interfaces:** `enum EnforcementAction { FAIL, WARN, IGNORE }`; `static EnforcementAction parse(String)`; `boolean blocks()` → `this == FAIL`.

- [ ] **Step 1: Failing test**
```java
@Test
void parsesAndReportsBlocking() {
    assertThat(EnforcementAction.parse("fail")).isEqualTo(EnforcementAction.FAIL);
    assertThat(EnforcementAction.parse("ignore")).isEqualTo(EnforcementAction.IGNORE);
    assertThat(EnforcementAction.FAIL.blocks()).isTrue();
    assertThat(EnforcementAction.WARN.blocks()).isFalse();
    assertThatThrownBy(() -> EnforcementAction.parse("block"))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("block");
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** (`parse` = switch on lower-cased trimmed value; `blocks`). Javadoc.
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** — `git commit -am "feat: add EnforcementAction enum"`

---

### Task 3: Data types — `RuleSpec`, `TrustPolicySpec`, `Clause`, `Requirement`, `Rule`, `MatchedRule`

Add the types (no evaluation logic yet; that is Task 4). All unused for now; build green.

**Files:** create the six files; tests `RuleTest.java`, `TrustPolicySpecTest.java`.
**Interfaces (exact shapes later tasks rely on):**
```java
public record RuleSpec(List<ArtifactPattern> patterns, List<Set<String>> clauseIds,
                       Map<ArtifactOutcome, EnforcementAction> enforcement, String location) {}

public record TrustPolicySpec(List<RuleSpec> rules, ClaimSetMode extraClaims,
                                  Map<ArtifactOutcome, EnforcementAction> defaults,
                                  List<String> issuers, boolean present) {
    public static final TrustPolicySpec EMPTY =
        new TrustPolicySpec(List.of(), ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), false);
}

public record Clause(List<SignerIdentity> signers) { /* non-empty invariant */ }

public record Requirement(List<Clause> clauses) {
    public RequirementEvaluator.Evaluation evaluate(List<ClaimResult> verifiedClaims) { /* Task 4 */ }
}

public record Rule(List<ArtifactPattern> patterns, Requirement requirement,
                   Map<ArtifactOutcome, EnforcementAction> enforcement, String location) {
    public boolean matches(ArtifactCoords c) { ... }
    public int specificity(ArtifactCoords c) { ... }   // best matching pattern's specificity
    public MatchedRule toMatchedRule() { return new MatchedRule(patterns.get(0).toString(), location, enforcement); }
}

public record MatchedRule(String pattern, String location,
                          Map<ArtifactOutcome, EnforcementAction> enforcement) {}
```

- [ ] **Step 1: Failing tests** — `Rule.matches`/`specificity` pick the best matching pattern; defensive copies hold; `Clause` rejects an empty signer list.
```java
@Test
void ruleScoresByBestMatchingPattern() {
    var rule = new Rule(
            List.of(ArtifactPattern.parse("com.acme.*"), ArtifactPattern.parse("com.acme:lib")),
            new Requirement(List.of()), Map.of(), "rules[0]");
    var c = new ArtifactCoords("com.acme", "lib", "", "jar", "1.0");
    assertThat(rule.matches(c)).isTrue();
    assertThat(rule.specificity(c)).isEqualTo(ArtifactPattern.parse("com.acme:lib").specificity());
}

@Test
void clauseRejectsEmpty() {
    assertThatThrownBy(() -> new Clause(List.of()))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("clause");
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** the six records with defensive copies, invariants, `matches`/`specificity`/`toMatchedRule`. `Requirement.evaluate` throws `UnsupportedOperationException("Task 4")` as a temporary body (replaced next task) — note: this is a deliberate stepwise stub removed in Task 4, not a plan placeholder.
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** — `git commit -am "feat: policy spec and compiled rule types"`

---

### Task 4: `Requirement.evaluate` — CNF satisfaction + accepted/unaccepted partition

The core requirement logic, unit-tested against resolved signers (no `SignersConfig`/issuer plumbing — the `Requirement` is already compiled).

**Files:** `Requirement.java` (+ `Clause.accepts`); `RequirementTest.java`, `ClauseTest.java`
**Interfaces:**
- `Clause.accepts(ClaimResult claim, List<String> defaultIssuers)` → true if any of its `SignerIdentity`s' credentials match the claim's proven credentials (reuse the matching logic currently in `TrustPolicy.matches/matchesAny`: `IdentityCredential.matches(proven, defaultIssuers)` for identity creds, else `Credential.matches(proven)`).
- `Requirement.evaluate(verifiedClaims)` → `Evaluation(satisfied, accepted, unaccepted)`: `satisfied` = every clause has ≥1 claim it `accepts`; `accepted` = claims accepted by *any* clause; `unaccepted` = verified claims accepted by none. (The compiled `Requirement` carries the default-issuer list it was built with, so `evaluate` takes only claims.)

- [ ] **Step 1: Failing tests** (helpers build `SignerIdentity`s and `ClaimResult`s with matching credentials, mirroring `TrustVerifierTest`):
```java
@Test
void conjunctionRequiresAllClauses() {
    var req = requirement(clause("alice"), clause("ci-a", "ci-b"));   // alice AND (ci-a OR ci-b)
    assertThat(req.evaluate(List.of(claimFrom("alice"))).satisfied()).isFalse();
    assertThat(req.evaluate(List.of(claimFrom("alice"), claimFrom("ci-b"))).satisfied()).isTrue();
}

@Test
void extraUnlistedClaimPartitioned() {
    var req = requirement(clause("alice"));
    var ev = req.evaluate(List.of(claimFrom("alice"), claimFrom("mallory")));
    assertThat(ev.satisfied()).isTrue();
    assertThat(ev.unaccepted()).hasSize(1);   // mallory → roll-up applies extra-claims
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** `Clause.accepts` and `Requirement.evaluate`; move the credential-matching statics out of `TrustPolicy` into package-private helpers used here.
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** — `git commit -am "feat: CNF requirement evaluation"`

---

### Task 5: Pin catch-all `"*"` and 4-segment pattern behaviour

**Files:** `ArtifactPattern.java` (change only if needed); `ArtifactPatternTest.java`

- [ ] **Step 1: Pinning tests**
```java
@Test
void catchAllMatchesAnythingAtLowestSpecificity() {
    var star = ArtifactPattern.parse("*");
    assertThat(star.matches(new ArtifactCoords("any.ns","x","","jar","9"))).isTrue();
    assertThat(star.specificity()).isEqualTo(0);
}
@Test
void fourSegmentPatternRejected() {
    assertThatThrownBy(() -> ArtifactPattern.parse("a:b:c:d")).isInstanceOf(PolicyConfigException.class);
}
```
- [ ] **Step 2: Run** — likely PASS already (existing behaviour); if not, fix minimally.
- [ ] **Step 3: (if needed) Implement**
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** — `git commit -am "test: pin catch-all and 4-segment pattern behaviour"`

---

### Task 6: Parser produces `TrustPolicySpec` (structural only)

Rewrite the parser to emit the raw spec. No signer resolution, no issuer semantic validation, no `Requirement` compilation here — those are Task 7. Structural errors (unknown keys, empty/scalar `requires`, 4-segment patterns, malformed `on-*`/`extra-claims`) still raise at parse.

**Files:** `SigmundConfigParser.java` (add `parseRules`→`RuleSpec`, `parseRequires`→`List<Set<String>>`, `parseExtraClaims`, `parseDefaults`, `parseEnforcementOverrides`; resolve `match` entries against `artifact-sets` names or `ArtifactPattern.parse`; build `TrustPolicySpec(present=true)`; delete `parseTrustSection`/`parseSignerRefs`/`resolveTrustMappings`/`parseListed*`/`parseUnlisted*`/`parseUntrusted*`; remove the `IdentityEntryValidator.validate` call from `parseRoot`); `SigmundConfig.java` (hold `TrustPolicySpec trustPolicySpec`, default `TrustPolicySpec.EMPTY`).

**Interfaces:** Produces `SigmundConfig.trustPolicySpec()`; `RuleSpec`/`TrustPolicySpec` populated. Signer-id strings are **not** resolved yet.

- [ ] **Step 1: Failing tests** (structural):
```java
@Test
void rulesParsedToSpec() {
    var doc = parse("""
            rules:
              - match: ["com.acme.*"]
                requires: [acme-release, {any-of: [ci-a, ci-b]}]
                on-no-claim: ignore
            """).trustPolicySpec();
    assertThat(doc.rules()).hasSize(1);
    assertThat(doc.rules().get(0).clauseIds())
            .containsExactly(Set.of("acme-release"), Set.of("ci-a", "ci-b"));
    assertThat(doc.rules().get(0).enforcement()).containsEntry(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE);
    assertThat(doc.present()).isTrue();
}
@Test
void emptyRequiresIsError() {
    assertThatThrownBy(() -> parse("rules: [{ match: [\"*\"], requires: [] }]"))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("requires");
}
@Test
void scalarRequiresIsError() {
    assertThatThrownBy(() -> parse("rules: [{ match: [\"*\"], requires: a }]"))
            .isInstanceOf(PolicyConfigException.class);
}
@Test
void extraClaimsDefaultsToReject() {
    assertThat(parse("rules: [{ match: [\"*\"], requires: [a] }]").trustPolicySpec().extraClaims())
            .isEqualTo(ClaimSetMode.ALL_CLAIMS);
}
@Test
void failedEnforcementSettingIsError() {
    assertThatThrownBy(() -> parse("defaults: { on-failed: warn }\nrules: []"))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("FAILED");
}
```
- [ ] **Step 2: Run, expect FAIL** — `mvn -pl core test -Dtest=SigmundConfigParserTest`
- [ ] **Step 3: Implement** the parser rewrite; delete the six old methods and their `parseRoot` calls; rewrite `SigmundConfigParserTest` trust/policy nests to the new schema. (At this point `SigmundConfig` no longer exposes `trustPolicy()`; the compiled policy comes from Task 7 — some downstream code is temporarily red; keep core compiling by keeping a `TrustPolicy`-returning path only where needed. If `VerificationReport`/`TrustVerifier` reference `config.trustPolicy()`, switch them in Task 7/8/9. To keep *this* task's build green, Task 7 lands immediately after; sequence them together before running the whole module.)
- [ ] **Step 4: Run parser tests, expect PASS** — `mvn -pl core test -Dtest=SigmundConfigParserTest,ArtifactSetsConfigTest`
- [ ] **Step 5: Commit** — `git commit -am "feat: parse policy into TrustPolicySpec (structural)"`

---

### Task 7: `RulePolicy.compile(...)` — resolve, validate, compile `Requirement`s (verifier path)

The semantic step, run only when the verifier is built. Resolves signer ids → `SignerIdentity`, builds `Requirement`/`Clause`, and validates: refs resolve, issuer-ambiguity (via `IdentityEntryValidator`), specificity ties, bakes default issuers into clauses.

**Files:** `RulePolicy.java` (implements `TrustPolicy`; holds `List<Rule>`, `ClaimSetMode extraClaims`, `Map<ArtifactOutcome,EnforcementAction> defaults`, `boolean present`, `List<String> issuers`; `static RulePolicy compile(TrustPolicySpec, SignersConfig)`; `EMPTY = compile(TrustPolicySpec.EMPTY, SignersConfig.EMPTY)`); `RulePolicyTest.java`.

**Interfaces:**
- `static RulePolicy compile(TrustPolicySpec doc, SignersConfig signers)` — for each `RuleSpec`: map each clause's ids via `signers.resolve(id)` (throws naming the id if undefined) into `Clause`s, assemble `Requirement`, carry `doc.issuers()` into the clauses; detect specificity ties (two rules whose patterns yield equal top specificity for an overlapping target — implement the identical-pattern-string tie, per ADR-007) → error; run `IdentityEntryValidator.validate(signers, doc.issuers())` including the 0/>1 check (Task 11).
- `requirements()` → `RequirementEvaluator` lambda: `matchRule(coords)`; null → null (NOT_CONFIGURED); else `rule.requirement().evaluate(claims)`.
- `claimSetMode()` → `extraClaims`.
- `matchRule(ArtifactCoords)` → most-specific `Rule` or null.

- [ ] **Step 1: Failing tests**
```java
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
    assertThat(policy.matchRule(coords("com.acme.secret","x","1")).requirement().clauses()).hasSize(1);
    assertThat(policy.matchRule(coords("com.acme.other","y","1"))).isNotNull();
    assertThat(policy.matchRule(coords("org.other","z","1"))).isNull();
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
void signingIgnoresRuleErrors() {   // the signing-independence guarantee
    // a spec with a bad rule parses fine and is never compiled on the signing path
    var config = parse("""
            signing: { signer: alice }
            signers: { alice: { pgp4: "4AEE18F83AFDEB23000000000000000000000000" } }
            rules: [{ match: ["*"], requires: [ghost] }]
            """);
    assertThat(config.signingConfig().signer()).isEqualTo("alice");   // usable without compile
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** `RulePolicy` + `compile`.
- [ ] **Step 4: Run, expect PASS** — `mvn -pl core test -Dtest=RulePolicyTest`
- [ ] **Step 5: Commit** — `git commit -am "feat: compile TrustPolicySpec into RulePolicy at verifier build"`

---

### Task 8: Slim `TrustPolicy`; `matchRule` + `enforcementFor`; wire `TrustVerifier` to record the matched rule

**Files:** `TrustPolicy.java` (new shape: `matchRule`, `requirements`, `claimSetMode`, `issuers`, `enforcementFor(ArtifactOutcome, MatchedRule, boolean present)`; remove old methods + private `matches/matchesAny`); `ArtifactResult.java` (add `MatchedRule matchedRule`); `TrustVerifier.java` (match once, pass the rule into the rollup and record `MatchedRule` on the result); `EnforcementTest.java`.

**Interfaces:** `TrustPolicy.enforcementFor(outcome, matchedRule, present)` resolves: matchedRule override → `defaults` → code default; `FAILED` always `FAIL` (override ignored); `NOT_CONFIGURED` = `FAIL` if `present` else `IGNORE`; others `FAIL`. `TrustVerifier.assess` returns an `ArtifactResult` whose `matchedRule()` is the matched rule's `toMatchedRule()` (or null).

- [ ] **Step 1: Failing tests**
```java
@Test
void enforcementDefaultsWhenPolicyPresent() {
    var p = RulePolicy.compile(docWithDefaults(Map.of()), SignersConfig.EMPTY);
    for (var o : List.of(ArtifactOutcome.FAILED, ArtifactOutcome.UNSATISFIED,
            ArtifactOutcome.NO_CLAIM, ArtifactOutcome.INDETERMINATE, ArtifactOutcome.NOT_CONFIGURED)) {
        assertThat(p.enforcementFor(o, null, true)).isEqualTo(EnforcementAction.FAIL);
    }
}
@Test
void notConfiguredIgnoredInZeroConfig() {
    assertThat(RulePolicy.EMPTY.enforcementFor(ArtifactOutcome.NOT_CONFIGURED, null, false))
            .isEqualTo(EnforcementAction.IGNORE);
    assertThat(RulePolicy.EMPTY.enforcementFor(ArtifactOutcome.FAILED, null, false))
            .isEqualTo(EnforcementAction.FAIL);
}
@Test
void ruleOverrideBeatsDefaultExceptFailed() {
    var mr = new MatchedRule("*", "rules[0]", Map.of(
            ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE,
            ArtifactOutcome.FAILED, EnforcementAction.IGNORE));
    var p = RulePolicy.EMPTY;
    assertThat(p.enforcementFor(ArtifactOutcome.NO_CLAIM, mr, true)).isEqualTo(EnforcementAction.IGNORE);
    assertThat(p.enforcementFor(ArtifactOutcome.FAILED, mr, true)).isEqualTo(EnforcementAction.FAIL);
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
    var p = RulePolicy.compile(doc.trustPolicySpec(), doc.signers());
    assertThat(p.matchRule(coords("org.other","x","1")).patterns().get(0).specificity()).isEqualTo(0);
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** the interface change, `ArtifactResult.matchedRule`, `enforcementFor`, and `TrustVerifier` recording. Update `ArtifactResultTest`/`TrustVerifierTest` for the new component.
- [ ] **Step 4: Run, expect PASS** — `mvn -pl core test`
- [ ] **Step 5: Commit** — `git commit -am "feat: matchRule, enforcementFor, matched-rule on ArtifactResult"`

---

### Task 9: Block via enforcement in `VerificationReport`

**Files:** `VerificationReport.java` (block iff any `policy.enforcementFor(r.outcome(), r.matchedRule(), present).blocks()`; thread `present` from the caller/`TrustPolicySpec.present()`; keep grouped counts/summary); `VerificationReportTest.java`.

- [ ] **Step 1: Failing tests** (Review-Focus rows):
```java
@Test
void zeroConfigPassesExceptFailed() {
    assertThat(reportFor(RulePolicy.EMPTY, false,
            List.of(result(ArtifactOutcome.NOT_CONFIGURED, null))).blocks()).isFalse();
    assertThat(reportFor(RulePolicy.EMPTY, false,
            List.of(result(ArtifactOutcome.FAILED, null))).blocks()).isTrue();
}
@Test
void notConfiguredFailsWhenPolicyPresent() {
    var p = compiledPolicyRequiring("com.acme.*", "a");
    assertThat(reportFor(p, true, List.of(result(ArtifactOutcome.NOT_CONFIGURED, null))).blocks()).isTrue();
}
@Test
void catchAllIgnoreToleratesUnsigned() {
    var p = compiledPolicyWithCatchAllIgnore();
    var mr = p.matchRule(coords("org.other","x","1")).toMatchedRule();
    assertThat(reportFor(p, true, List.of(result(ArtifactOutcome.NO_CLAIM, mr))).blocks()).isFalse();
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** — replace the `onUntrusted()` check with per-outcome enforcement using the recorded `matchedRule`.
- [ ] **Step 4: Run, expect PASS** — `mvn -pl core test`
- [ ] **Step 5: Commit** — `git commit -am "feat: block build via per-outcome enforcement"`

---

### Task 10: Remove legacy policy types and old interface methods

**Files:** delete `DefaultTrustPolicy.java`, `ListedEvidencePolicy.java`, `UnlistedEvidencePolicy.java`, `UntrustedPolicy.java`, `DefaultTrustPolicyTest.java`; finalize `TrustPolicy.java` removals; `SigmundConfig` default already `TrustPolicySpec.EMPTY`.

- [ ] **Step 1:** `grep -rn "DefaultTrustPolicy\|ListedEvidencePolicy\|UnlistedEvidencePolicy\|UntrustedPolicy\|expectedSigners\|isUnsignedAllowed" core/src maven-plugin/src cli/src` and clear every core hit (maven-plugin in Task 13).
- [ ] **Step 2: Run core tests, expect PASS** — `mvn -pl core test`
- [ ] **Step 3: Commit** — `git commit -am "refactor: remove legacy trust-policy types"`

---

### Task 11: Issuer ambiguity check (0 / >1 asserting issuers) in `compile`

**Files:** `IdentityEntryValidator.java` (add the >1 branch to its existing 0 branch); invoked from `RulePolicy.compile` (Task 7 already calls `validate`); tests in `RulePolicyTest`/`IdentityEntryValidatorTest`.

- [ ] **Step 1: Failing tests**
```java
@Test
void issuerlessEntryAmbiguousIsError() {
    // two issuers of the same kind that can both assert the entry's attributes
    var doc = parse("""
            issuers: [https://a.example, https://b.example]   # two OIDC issuers
            signers: { ci: { identities: [{ source-repository-uri: https://github.com/x/y }] } }
            """);
    assertThatThrownBy(() -> RulePolicy.compile(doc.trustPolicySpec(), doc.signers()))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("ambiguous");
}
@Test
void issuerlessEntryWithOneAssertingIssuerIsFine() {
    var doc = parse("""
            issuers: [keys.openpgp.org, https://token.actions.githubusercontent.com]
            signers: { alice: "alice@x.io" }
            """);
    RulePolicy.compile(doc.trustPolicySpec(), doc.signers());   // no throw: only the directory asserts email
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** the >1 branch; message names the entry and says "name the issuer inline."
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** — `git commit -am "feat: error on ambiguous issuer-less identity entries at compile"`

---

### Task 12: v1-schema tripwire

**Files:** `SigmundConfigParser.parseRoot` (before the strict unknown-key pass, detect `trust`/`signature-optional`/`policy`/`artifacts` → `PolicyConfigException` naming the replacement); `SigmundConfigParserTest`.

- [ ] **Step 1: Failing tests**
```java
@Test
void oldTrustSchemaRejectedWithGuidance() {
    assertThatThrownBy(() -> parse("trust: { \"org.acme:*\": alice }"))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("rules");
}
@Test
void oldArtifactsKeyRejectedWithGuidance() {
    assertThatThrownBy(() -> parse("artifacts: { g: [\"com.acme.*\"] }"))
            .isInstanceOf(PolicyConfigException.class).hasMessageContaining("artifact-sets");
}
```
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** — `git commit -am "feat: v1 policy schema tripwire with migration guidance"`

---

### Task 13: Remove `AttesterRole`/`ClaimResult.role`; update `VerifyMojo` (compile on verify path)

**Files:** `ClaimResult.java` (drop `role` component/default/factory/javadoc); `VerificationReport.java:250-251` (drop role suffix); delete `AttesterRole.java`; `ClaimResultTest.java`; `maven-plugin/.../VerifyMojo.java` (remove `onUntrusted`/`listedEvidence` params + `applyPolicyOverrides`; on the verify path call `RulePolicy.compile(config.trustPolicySpec(), config.signers())` and pass to `sigmund.verifier(...)`; update/drop its inline `TrustPolicy` record); confirm `SignMojo` uses only `config.signingConfig()` and never compiles.

- [ ] **Step 1: Adjust/author failing tests** — `ClaimResultTest` without `role`; a maven-plugin test that `verify` compiles the policy and blocks per enforcement, and that `sign` works with a rules-section error present (signing independence).
- [ ] **Step 2: Run, expect FAIL** — `mvn -pl core,maven-plugin test`
- [ ] **Step 3: Implement**; `grep -rn "AttesterRole\|\.role()\|onUntrusted\|listedEvidence" core/src maven-plugin/src cli/src` must be empty.
- [ ] **Step 4: Run, expect PASS** — `mvn -pl core,maven-plugin test`; then `mvn -q -pl core,maven-plugin,cli -am install -DskipTests` to confirm the reactor compiles.
- [ ] **Step 5: Commit** — `git commit -am "refactor: remove AttesterRole; compile policy on verify path"`

---

### Task 14: Full verify + docs touch

**Files:** roadmap `docs/sigmund-verification-roadmap.md` (status for P2.6/P2.7 + a decision-log row for the 2026-10-11 review).

- [ ] **Step 1: Run the whole build** — `mvn verify` (strict javadoc + integration). Expected PASS.
- [ ] **Step 2: Fix any doclint failures** on new public types (`EnforcementAction`, `RuleSpec`, `TrustPolicySpec`, `Clause`, `Requirement`, `Rule`, `MatchedRule`, `RulePolicy`, new `TrustPolicy` methods, `ArtifactResult.matchedRule`).
- [ ] **Step 3: Update the roadmap** status + decision log.
- [ ] **Step 4: Commit** — `git commit -am "docs: roadmap status and decision log for the rules schema"`

---

## Self-Review

**Spec coverage (ADR-007):** document shape — Tasks 1,6; Rules (match resolution, catch-all, most-specific/no-merge/ties) — Tasks 5,6,7,8; Requirements (R1, any-of, no roles, extra-claims) — Tasks 3,4,6,13; Enforcement (vocab, resolution, enforce/observe, roll-up precedence) — Tasks 2,8,9; Validation (structural at parse; semantic refs/ties/issuer-0/>1 at compile) — Tasks 6,7,11,12; Consequences (removed types, `TrustPolicy`→matchRule+evaluator, role removal) — Tasks 10,13. **Signing independence** — Tasks 6 (parser structural), 7/13 (compile only on verify path), Review-Focus test in 7/13. **Deferred by design** (bootstrap, run modes/scope, reactor-root, detailed report, JSON Schema) — not gaps.

**Placeholder scan:** none. The only stub is `Requirement.evaluate` in Task 3, explicitly replaced in Task 4 (a stepwise TDD stub, labelled as such).

**Type consistency:** `RequirementEvaluator.Evaluation(boolean, List<ClaimResult>, List<ClaimResult>)` (existing) returned by `Requirement.evaluate` (Task 4) and the `requirements()` lambda (Task 7); `Rule(List<ArtifactPattern>, Requirement, Map<ArtifactOutcome,EnforcementAction>, String)` consistent across Tasks 3/7/8; `MatchedRule(String, String, Map<ArtifactOutcome,EnforcementAction>)` consistent across Tasks 3/8/9; `enforcementFor(ArtifactOutcome, MatchedRule, boolean)` identical in Tasks 8/9; `RulePolicy.compile(TrustPolicySpec, SignersConfig)` identical in Tasks 7/8/11/13; `TrustPolicySpec.present()` drives `present` in Tasks 7/8/9.

**Review Focus:** all six rows have owning tasks with tests (zero-config → 9; not-configured-present → 9; catch-all ignore → 8/9; extra-claims → 4/9; signing-independence → 7/13; validation-error family → 6/7/11).

**Ordering risk:** Tasks 6→7→8 change `SigmundConfig`'s policy field and the `TrustPolicy` interface together; core may be transiently red between 6 and 8, so run the full `mvn -pl core test` only at the end of Task 8. `maven-plugin` stays red until Task 13 (`mvn install` green from Task 13 on). Both are called out in the owning tasks.
