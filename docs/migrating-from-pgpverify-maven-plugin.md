# Migrating from pgpverify-maven-plugin

> **Draft — not published, not linked.** Notes toward a comparison and migration guide, kept on
> the `pgpverify-comparison` branch. What is marked *verified* was read from pgpverify's source;
> everything else is still to check. Finish after the 0.0.3 release.

## Sources

pgpverify-maven-plugin `master` at
[`b2314a0`](https://github.com/s4u/pgpverify-maven-plugin/tree/b2314a04bb1b3b4045eb26f37be13edcac7b7c48)
(2026-11-12), read on 2026-11-12. The files relied on are identical in the latest release,
**v1.19.1** (2025-03-08):

- [`AbstractPGPMojo.java`](https://github.com/s4u/pgpverify-maven-plugin/blob/v1.19.1/src/main/java/org/simplify4u/plugins/AbstractPGPMojo.java) — keyserver defaults
- [`CheckMojo.java`](https://github.com/s4u/pgpverify-maven-plugin/blob/v1.19.1/src/main/java/org/simplify4u/plugins/CheckMojo.java) — how a result becomes pass or fail
- [`pgp/SignatureUtils.java`](https://github.com/s4u/pgpverify-maven-plugin/blob/v1.19.1/src/main/java/org/simplify4u/plugins/pgp/SignatureUtils.java) — signature check
- [`pgp/PublicKeyUtils.java`](https://github.com/s4u/pgpverify-maven-plugin/blob/v1.19.1/src/main/java/org/simplify4u/plugins/pgp/PublicKeyUtils.java) — key ring loading and subkey binding
- [`keyserver/PGPKeysCache.java`](https://github.com/s4u/pgpverify-maven-plugin/blob/v1.19.1/src/main/java/org/simplify4u/plugins/keyserver/PGPKeysCache.java) — key cache

Sigmund side: as of 0.0.3.

## Tone

Same goal, different trust models, each with a cost. State what each checks and what it gives
up; no "everything it does, plus". Credit what pgpverify does that Sigmund does not.

## The two trust models

**pgpverify** trusts the keys map. For each artifact you list the primary keys allowed to sign
it; the plugin confirms the artifact's bytes were signed by such a key. It checks the signature
against the key and nothing about the key's lifecycle. That makes it robust where Sigmund is
not — keys served without user IDs, user IDs that are not UTF-8 — and lenient where Sigmund is
not — expired and revoked keys.

**Sigmund** checks the signature *and* that the key was valid when it signed, as GnuPG and
Sequoia do: bound by its self-signatures, not expired, not revoked. That is what lets `FAILED`
mean "do not use this artifact". The cost is needing a usable, complete copy of the key.

## How pgpverify checks a signature (verified)

1. Key ID or issuer fingerprint taken from the signature packet (`SignatureUtils.retrieveKeyId`).
2. Key ring from its cache or a keyserver. Default keyservers, in order with fallback:
   `hkps://keyserver.ubuntu.com, hkps://keys.openpgp.org, hkps://pgp.mit.edu` (`AbstractPGPMojo`,
   `pgpverify.keyserver`).
3. Cached in the local repository (`pgpkeys-cache`) and **never refreshed**; only "not found"
   markers expire (`PGPKeysCache.getKeyRing`, `notFoundRefreshHours`).
4. Ring loaded with **every subkey's binding signature checked** — a subkey without a valid
   binding by the primary rejects the ring (`PublicKeyUtils.verifySigForSubKey`). Not checked:
   user IDs and their self-signatures (read for display only, decoded from raw bytes), the
   primary key's validity, expiry, key flags, a signing subkey's back-signature.
5. Signature checked with Bouncy Castle's low-level `PGPSignature.init(key)` + `verify()`.
6. Verdict (`CheckMojo`): `SIGNATURE_VALID` passes when the keys map allows the **primary** key's
   fingerprint for the artifact; an empty keys map accepts any valid signature, with a warning.
   **A revoked key whose public key is present is still `SIGNATURE_VALID`** — the revocation is
   recorded for the report; only a revocation served without the public key
   (`KEY_REVOCATION`) blocks.

## Differences (verified unless marked)

| Case | pgpverify | Sigmund 0.0.3 |
|---|---|---|
| Bytes do not match the signature | Fails | `FAILED` |
| Key the map / policy does not allow | Fails | `UNSATISFIED` or `NOT_CONFIGURED` |
| Key expired before it signed | Passes — expiry not checked | `FAILED` |
| Key revoked as compromised, or with no reason given | Passes when the public key is present | `FAILED`, whenever it signed |
| Key retired or superseded, signature made before | Passes | `VERIFIED` under Bouncy Castle and Sequoia; `FAILED` when GnuPG answers (Sigmund `limitations.md`, roadmap P4.7) |
| Key retired or superseded, signature made after | Passes | `FAILED` |
| Key with no verified address, served stripped by keys.openpgp.org | Passes — usually fetched in full from keyserver.ubuntu.com first, and a stripped copy keeps the subkey bindings it checks | `INDETERMINATE (KEY_UNAVAILABLE)` unless a keyserver serving the full key is listed |
| Old key after a rotation on keys.openpgp.org (served stripped) | Passes, and keeps whatever copy it cached first | `INDETERMINATE` from keys.openpgp.org alone, even pinned (roadmap P4.6, P4.10) |
| User ID that is not UTF-8 (gson's release key) | Passes — decodes raw bytes itself | `INDETERMINATE` under Bouncy Castle; `VERIFIED` when `sq` or `gpg` holds the key (roadmap P10.6) |
| Later revocation of a cached key | Not seen — cache never refreshed | Seen — keys fetched each build, held in memory |
| Post-quantum (ML-DSA) signatures | — *(to check)* | Verified with `sq` |
| Sigstore bundles | — *(to check)* | Verified with `sigmund-sigstore` |

## What pgpverify has that Sigmund does not (to check each)

- Verifying build plugins (`verifyPlugins`, `verifyPluginDependencies`).
- Keys-map special values: `badSig` (accept an invalid signature), `noKey` (accept a key no
  keyserver has), `any` (any valid signature).
- A persistent key cache on disk — Sigmund's is roadmap P4.6.
- A machine-readable report file — *to check what it contains*.
- Load-balancing across keyservers (`RoundRobinRouterPlaner`).

## Mapping the keys map to `sigmund.yaml` (current schema; to re-check before publishing)

| keys map | `sigmund.yaml` |
|---|---|
| `com.example.* = 0x<fingerprint>` | a signer with `pgp4: "<fingerprint>"`, and a rule `match: ["com.example.*"]`, `requires: [<signer>]` |
| several fingerprints for one pattern | one signer holding them as a `pgp4` list (any of them satisfies it), or several signers with `requires: [{any-of: [...]}]` |
| `noSig` | `on-no-claim: ignore` on the rule |
| `noKey` | `on-indeterminate: ignore` on the rule — broader: it tolerates every reason a claim could not be checked |
| `any` | a rule without `requires`, with `on-unsatisfied: ignore` — a signature by anyone is tolerated, an invalid one still fails |
| `badSig` | no equivalent: `FAILED` is never tolerated |

`mvn sigmund:dependency-signers -Dsigmund.generateTrustConfig` writes a starting policy from the
signatures the dependencies carry today, instead of translating the map by hand.

Configuration:

| pgpverify | Sigmund |
|---|---|
| `pgpverify.keyserver` | `verification.keyservers` (default `keys.openpgp.org` only; listing more is key material only, never what is accepted) |
| `pgpverify.scope` (default `test`) | — *(roadmap P3.2; check what Sigmund resolves today)* |
| `pgpverify.verifyPomFiles` (default `true`) | `sigmund.verifyPomFiles` (default `false`) |
| `pgpverify.verifyPlugins` | — |
| `pgpverify.skip` | `sigmund.skip` |

## Open points

- `PGPKeysCache`: what happens with a downloaded key that has no user IDs (`PublicKeyUtils.loadPublicKeyRing` returns it; check the cache keeps it).
- The empty-keys-map behaviour in practice (warning plus accept-any).
- pgpverify's weak-hash check (`verifyWeakSignature`) against Sigmund's
  [accepted algorithms](verification.md#accepted-algorithms).
- PQC and Sigstore support on pgpverify's side, and its report file.
- Measure both on one real project — same dependencies, default settings — for the article.

## Stale in the earlier draft (commit `eb68fd6`)

The first draft used Sigmund's old schema (`trust:`, `unsigned:`, `discovery.keyservers`,
`openpgp4:`, `name:`), said Sigmund had no verification report, and opened with "Sigmund offers
everything pgpverify-maven-plugin does … plus". Its keyserver section and plugin-replacement
steps are reusable once updated.
