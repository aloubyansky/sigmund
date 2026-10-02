# ADR-007: Policy Schema and Enforcement

## Status

Proposed

## Context

Policy today maps artifact patterns to expected signers:

```yaml
trust:
  "org.apache.maven.*": apache
signature-optional:
  - "com.internal.*"
policy:
  on-untrusted: fail
  listed-evidence: all
  unlisted-evidence: ignore
```

`DefaultTrustPolicy` answers three questions from this: which signers are
expected for an artifact, whether an unsigned artifact is allowed, and what to
do when the result is untrusted. Three limitations block the design direction:

- **"Expected signer" cannot express a new requirement type.** Adding "and a
  builder claim from our CI" has nowhere to go, because the value of a mapping
  is a signer, not a requirement (§3.2).
- **Only one signer set per target.** A rule cannot say "the publisher's key
  AND our CI's Sigstore identity"; any listed signer satisfies it.
- **Enforcement is one dial.** `on-untrusted` conflates outcomes that need
  different treatment: a missing signature is a coverage decision, a failed
  signature is an attack signal (§3.5, §3.6).

ADR-005 supplies the outcome vocabulary and roll-up; ADR-006 supplies
credentials. What remains is the document that states what
must be true for an artifact, and what happens when it is not.

## Decision

### Document shape

```yaml
version: 2

issuers:                      # ADR-006: default issuers for identity entries
  - keys.openpgp.org
  - https://token.actions.githubusercontent.com

signers:                      # ADR-006
  apache:
    pgp4: 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12   # keys already seen
    email: release@apache.org                          # keys to come
  acme-release:
    pgp4: 9B1C0E7F2D4A6B83C5E1F09A7D3B2C4E6F8A0B1D
  acme-ci:
    identities:
      - source-repository-uri: https://github.com/acme/widget
        build-config-uri: https://github.com/acme/widget/.github/workflows/release.yml

artifacts:                    # unchanged: named pattern groups
  apache-stack:
    - "org.apache.maven.*"
    - "org.apache.commons.*"

rules:
  - targets: [apache-stack]
    requires: [apache]

  - targets: ["com.acme.*"]
    requires: [acme-release, acme-ci]     # both

  - targets: ["org.jboss.*"]
    requires:
      - any-of: [jboss, redhat]           # either

  - targets: ["com.internal.*"]
    requires: [release-team]
    on-no-claim: allow        # what `signature-optional` used to say

defaults:
  claim-set: all              # or: any
  on-unsatisfied: fail
  on-no-claim: warn
  on-indeterminate: warn
  on-not-configured: warn
  by-scope:
    build-tooling:            # populated by the core extension (§2)
      on-no-claim: fail
      on-indeterminate: fail
```

`trust`, `signature-optional` and `policy` are replaced. `artifacts` groups keep
working and expand in `targets`.

### Rules

A rule is `targets` plus `requires`, with optional per-rule enforcement and
claim-set overrides.

- **`targets`** are GAV patterns or `artifacts` group names, matched as today by
  `ArtifactPatternMatcher`. Rules match at GAV level only; classifier and
  extension are not policy dimensions (§3.2). A pattern with more than three
  coordinate segments is a config error rather than silently matching nothing,
  which is what the current matcher does.
- **Most specific rule wins**, by the existing specificity score. One rule
  applies — no merging across rules, so the matched rule fully explains the
  outcome. Two rules with identical specificity for the same target are a config
  error, not a silent pick.
- **The matched-rule reference** on the artifact result (ADR-005) carries the
  rule's pattern and its location in the file, so a surprising verdict traces to the line that caused it.

### Requirements

Each entry in `requires` is a clause: a signer id, or `any-of` with a list of
signer ids.

```yaml
requires:
  - acme-release                    # this signer
  - any-of: [acme-ci, acme-ci-eu]   # and one of these
```

- **Clauses are conjunctive; signers within `any-of` are disjunctive.**
  `requires: [a, b]` means both. Reading it as "either" fails closed — the
  artifact is `UNSATISFIED` — which is the safe direction for the mistake.
- A clause is satisfied by a **verified claim** whose proven credentials match
  one of the named signers' credentials (ADR-006).
- **No roles.** A clause names signers, and a signer's credentials already say
  what it is: an OpenPGP key or a CI workflow identity. "A publisher claim AND a
  builder claim" is written as the two signers. A role label would add a
  second, unchecked statement of the same thing; it is deferred until an
  attestation consumer needs the capacity spelled out (§3.3).
- **`claim-set`** governs claims beyond those that satisfied the clauses:
  `all` (default) requires every remaining claim to be verified and accepted;
  `any` records and ignores them. This replaces `listed-evidence`.
  `unlisted-evidence` disappears: evidence from an unlisted signer is a verified
  claim that no clause accepts, which `claim-set: all` turns into `UNSATISFIED`
  and `claim-set: any` ignores.

### Enforcement

Each non-`SATISFIED` outcome has its own setting — `fail`, `warn`, `allow` —
resolved in this order: rule-level, scope-level, `defaults`, code defaults.

| Outcome | Code default | Notes |
|---|---|---|
| `FAILED` | fail | Not overridable at any level; a setting for it is a config error |
| `UNSATISFIED` | fail | A claim exists and policy does not accept it |
| `NO_CLAIM` | warn | Coverage decision; `fail` for build tooling |
| `INDETERMINATE` | warn | `fail` for build tooling; downgraded from cache first (§3.7) |
| `NOT_CONFIGURED` | warn | Nothing applies; zero-config runs are all of these |

`on-no-claim: allow` on a rule is what `signature-optional` used to express,
with an important difference: the artifact is still verified and still counted
as `NO_CLAIM` in coverage (§2.1), and a signature that *is* present is still
checked — so a `FAILED` signature on a tolerated artifact still fails the build.
Today those artifacts are filtered out before assessment and never looked at.

Enforcement decides build failure only. It never changes an outcome, so
observe mode (§5.4) and VSA emission (§6) report the same results a strict run
would.

### Validation

The parser is strict: unknown keys are errors. Beyond that it checks that
signer references in `requires` exist, that every identity entry can be
asserted by one of its issuers (ADR-006), that no setting exists for `FAILED`,
that target patterns are GAV-shaped, and that no two rules tie on specificity.
Errors name the file, the location and the fix.

`requires` has exactly two clause shapes, and the parser normalizes both to one
model — a conjunction of disjunctions, `List<Set<String>>` by signer id, a
scalar clause being a one-member set. Two edge cases are errors rather than
readings:

- **An empty `requires`**, which would read as "a rule applies and nothing is
  required" and make every matched artifact vacuously `SATISFIED`. A rule that
  tolerates artifacts says so through enforcement, such as `on-no-claim: allow`.
- **A bare scalar**, `requires: acme-release`. It would be a third shape to save
  two characters; `requires` is always a sequence.

### Schema

A JSON Schema for the policy document ships as a resource and is published for
editors: with it, YAML language servers in IntelliJ and VS Code offer
completion, hover documentation and unknown-key errors while the file is being
written. It states the structure — keys, value types, the two clause shapes as
a `oneOf`, `additionalProperties: false` throughout.

**The parser stays authoritative.** The schema cannot express cross-references,
specificity ties or issuer assertability, and a schema validator's errors point
at a JSON path where the parser names the rule and the fix. So the schema is not
consulted at runtime and adds no dependency to verification.

Drift between the two is caught by a test that runs on every build: every
valid fixture and every example in the documentation passes both the schema and
the parser, and every invalid fixture the parser rejects for a structural
reason is rejected by the schema too.

## Consequences

**Removed:** `TrustPolicy.expectedSigners` and `isUnsignedAllowed`,
`DefaultTrustPolicy`, `ListedEvidencePolicy`, `UnlistedEvidencePolicy`,
`UntrustedPolicy`, and the `trust`, `signature-optional` and `policy` sections.

**Added:** `rules`, `requires` with `any-of`, `defaults`, per-rule
enforcement, `claim-set`; a published JSON Schema for the document.

**`TrustPolicy` becomes** a rule lookup plus a `RequirementEvaluator`
(ADR-005) — `matchRule(subject)` and `evaluate(subject, verifiedClaims)` — so
the roll-up stays independent of schema details.

**Bootstrap** (`generateTrustConfig`) emits `rules` with one clause per group —
the observed signer, or `any-of` where a group was observed signed by several —
and `on-no-claim: allow` for artifacts observed without evidence, replacing the
`signature-optional` list.

**`AttesterRole` and `ClaimResult.role` are removed.** Nothing sets a role other
than `UNKNOWN`, and without role-scoped clauses nothing reads one. They return
with attestations if a consumer needs them.

**Behaviour users would notice:** a policy that used to pass with a tolerated
unsigned artifact now also verifies any signature that artifact carries; a
4-segment pattern that silently matched nothing is now an error; evidence from
an unlisted signer under `claim-set: all` is `UNSATISFIED` rather than
`UNTRUSTED` with no explanation of which claim caused it.

**Ordering:** implemented in roadmap phase P2 (schema, evaluator, bootstrap) and
P3 (enforcement, scopes, run modes).
