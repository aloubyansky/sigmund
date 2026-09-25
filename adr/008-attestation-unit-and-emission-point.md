# ADR-008: Attestation Unit and Emission Point

## Status

Proposed

## Context

[§6](../docs/sigmund-verification-design-direction.md) separates two
attestations — inbound ("I verified my dependencies") and outbound ("this
release was built from verified inputs") — but says neither what each is
attached to nor when it is produced. With the Maven core extension (§2) as the
most comprehensive insertion point, both questions become concrete, because the
extension verifies lazily: each artifact is checked as the resolver touches it,
spread across the whole session. There is no moment before the session ends at
which "everything this build depended on" exists.

Four facts about Maven constrain the answer.

**There is no release unit in the repository format.** A module's artifacts are
independently consumable: a consumer resolves `com.corp:lib-a:1.0` without
knowing `lib-b` exists, and discovery is by coordinate. Three things come close
and none of them is a release: the aggregator POM is published and lists
`<modules>`, but only within its own groupId/version tree and consumers never
resolve it; staging repositories and Central's publishing deployments bundle
GAVs as a unit, but that is publishing infrastructure and the bundling
disappears once published; `deployAtEnd` is a build-time convenience, not a
published fact.

**Files change after their inputs are verified.** Shade, proguard, a
repackaging mojo, and the GPG plugin attaching `.asc` all run later in the
lifecycle than the resolution that fed them. An attestation written at `package`
names bytes that may never be published.

**An upload cannot be described by something inside it.** Central's publishing
portal and the staging plugins assemble a bundle and validate it as a unit;
a file cannot be appended afterwards. Anything that ships with the artifacts is
assembled before the upload happens.

**Verification is enforced from the resolver, but observation is available
separately.** Maven's `EventSpy` receives execution events (which mojo ran, for
which project, from which plugin GAV) and repository events. It is
observational — a spy cannot reliably fail a build — so it complements the
resolver-side hook that blocks, rather than replacing it.

## Decision

### The outbound attestation is per module

Its subject is every file that module publishes — jar, pom, sources, javadoc,
each with its digest. An in-toto Statement takes multiple subjects, so one
statement per module covers them.

It is **attached as a module artifact, the way `.asc` already is**, and
uploads in the same batch as everything else. It is written late in the
lifecycle, after the module's mutating plugins have run, so that its subject
digests are the bytes that are actually published.

It therefore **says nothing about its own upload**, and nothing about the
deployment succeeding: it is assembled before the upload it would be describing.
It may name the deploy tooling configured for the module; it may not claim where
that tooling put the files.

Per-module granularity also removes the ordering problem that session-level
granularity creates. A module's input set is complete when its own lifecycle
finishes, which is before its `deploy` runs, so module 1's attestation is ready
in time without staging the whole reactor. A later module resolving more
artifacts does not change module 1's inputs.

**Reactor-internal dependencies are stated separately from repository inputs.**
When `lib-b` depends on `lib-a` from the same build, `lib-a` arrives from the
reactor: unsigned, unverified, and correctly so. Counting it as covered would
be false; the statement distinguishes inputs verified from repositories from
inputs supplied by this build, and points at those modules' own attestations.
Build tooling splits the same way: session-level extensions are inputs to every
module, per-project plugins only to theirs.

### The session-level artifact is a run record, not an attestation

It is written at session end — the only point at which the session's coverage
is complete — and is the result serialization of P4.1: JSON, unsigned, always
emitted. Because it is written after the deploys have happened, it is the right
place for what the module attestation structurally cannot carry: which mojo
performed each upload, with its resolved plugin GAV and whether verification
covered it, and the target repository.

It is **not signed until a consumer that crosses a trust boundary is named.**
An attestation earns its signature when someone who did not run the build has
to believe it and detect tampering. The outbound attestation crosses such a
boundary by definition. The session record usually does not: the CI step that
reads it ran in the same pipeline that produced it, where a file on disk is
exactly as trustworthy as a signed one, and signing costs the verifier-identity
trust root that §6 calls the plan-sinker.

The one consumer that does hold up today is the **observe-mode gate** (§5.4,
P3.3). In enforcing mode a blocking outcome fails the build, so a gate asking
"did verification pass?" is redundant. In observe mode the build deliberately
exits zero and something downstream decides whether to promote; that decider
needs one object stating policy digest, enforcement mode and coverage counts,
and it cannot reconstruct them from per-module attestations without already
knowing the module set. When that gate runs in a separate pipeline, the record
is signed on the same content — promotion is additive.

### The chain terminates at the signature

The outbound attestation is DSSE-signed, so tampering with it after upload is
detectable without a further attestation above it. Two residual threats remain,
and a session-level attestation answers neither:

- **Deletion** — a consumer sees no attestation at all. Answered by
  consumer-side policy: "require an attestation for `com.corp:*`".
- **Rollback** — an older, validly signed attestation is served. Answered by
  digest binding: an old statement names old digests, which do not match the
  artifact being consumed. Rolling back both requires mutating a released GAV,
  which the repository does not permit. SNAPSHOTs are the exception, as usual.

### Deploy facts stay out of the attestation predicate

"Published by X to Y" is a provenance claim, not a verification summary. There
is an existing predicate for provenance and P7 already ingests it. Deploy facts
belong in the session record as coverage metadata; growing the VSA predicate
into a half-provenance statement would make it harder to consume, not easier.

## Consequences

**The attestation unit follows the consumer, not the build.** Outbound is per
module because discovery is by coordinate; inbound is per session because
coverage is a property of the run. The two are not the same statement at
different scopes.

**No release concept is introduced.** Publishing a release manifest — GAVs and
digests at some coordinate, itself attested — is left until a consumer asks for
one signature over a set. It can be layered on later at the aggregator
coordinate without changing the per-module attestations. Introducing it now
would mean defining what it means to resolve one module of it, which is §2.1's
partial-coverage problem in a new place.

**Two questions become pass/fail for the P5.1 spike**, because the decisions
above depend on them:

- **Per-project attribution.** Can a resolution be attributed to the project
  that requested it? `RepositoryEvent.getTrace()` walks back to the originating
  request and is the lead worth checking first. If attribution is impossible,
  a per-module attestation would have to claim the union of everything the
  session resolved — a bad overclaim for a leaf module — and the unit falls back
  to the session with staged deployment.
- **Late attachment.** Can an extension attach an artifact late enough to be in
  the upload batch — for instance on the deploy mojo's `MojoStarted` event,
  before the mojo reads the project's attached artifacts — and does the same
  path work for `install`, for `deployAtEnd`, and for the publishing plugins
  that assemble their own bundle?

Also to confirm rather than assume: which repository events Maven actually
forwards to `EventSpy`, and whether deployment events among them carry the
target repository.

**P8.1 splits.** Serializing the run result and signing it as a VSA become
separate steps, since the run record is emitted unsigned on every build and the
module attestation is the signed one. P8.1's dependency on P3.6 (coverage from
the goal) is not sufficient for the extension case; extension-side emission
depends on P5.8.

**Two coverage fields are missing from §2.1** and are needed before either
artifact is honest:

- **What the session ran** — invoked goals and module set. `mvn test` and
  `mvn verify` resolve different sets, and `-pl` narrower still, so
  `artifacts-verified: 412` is unanchored without it, and P8.4's
  minimum-coverage check cannot tell a full release build from a partial one.
- **Freshness** — once P4.3's cache lands a build can satisfy every artifact
  from cache and verify nothing fresh. P4.4 records age per result; the summary
  needs the aggregate, or it attests a freshness it never had.

**Ordering:** the module attestation lands with P8.1–P8.2 and cannot be built
before P5.1 answers attribution; the session record lands with P4.1 and is
usable from the goal before the extension exists.
