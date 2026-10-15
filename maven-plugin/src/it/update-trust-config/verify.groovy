File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text

// commons-lang3 key is on keys.openpgp.org and should be fully identified
assert log.contains("Signer: Gary David Gregory (Code signing key) <ggregory@apache.org>") : "Should identify commons-lang3 signer"
assert log.contains("org.apache.commons:commons-lang3:3.14.0") : "Should list commons-lang3"

// jspecify key is on keys.openpgp.org but without a UID, so the signer
// cannot be fully identified. BC fetches the key and verifies the signature
// but reports "NOT VERIFIED" (no signer name). GPG would report "UNKNOWN
// (key not in keyring)" since it cannot import keys without UIDs.
assert log.contains("org.jspecify:jspecify:1.0.0") : "Should list jspecify"
assert !log.contains("UNSIGNED") || log.contains("Signer: UNKNOWN") || log.contains("Signer: NOT VERIFIED") : "jspecify should not be fully identified"

// jspecify's signer proves only a key ID, no full fingerprint or verified identity, so the
// update must leave it out rather than write a rule naming a signer the file never defines —
// such a config would not load. With nothing usable to add, the file is left as it was.
assert log.contains("proved no full fingerprint or verified identity and is left out of the config") : "Should leave out the unidentifiable signer"
assert log.contains("Trust configuration is already up to date") : "Should report nothing to add"

// The config should have the original signer plus an entry for jspecify
File trustConfig = new File(basedir, "sigmund.yaml")
assert trustConfig.exists()
String yaml = trustConfig.text
assert yaml.contains("gary-gregory") : "Should still have original signer"
assert !yaml.contains("signer-2") : "Must not reference a signer it does not define"

// Should not have duplicate section headers
int signersCount = yaml.split("signers:").length - 1
assert signersCount == 1 : "Should have exactly one signers: section, found ${signersCount}"
int rulesCount = yaml.split("rules:").length - 1
assert rulesCount == 1 : "Should have exactly one rules: section, found ${rulesCount}"

// Round-trip guard: the updated config must stay on the new rules schema and must never emit
// any of the removed v1 keys, each of which the parser's tripwire hard-errors on. These
// line-level checks stand in for a reparse (the parser is not on the verify.groovy classpath):
// a config carrying any of these keys at the top level would fail SigmundConfig.parse.
def topLevelKeys = yaml.readLines().findAll { !it.startsWith(" ") && it.contains(":") }
    .collect { it.substring(0, it.indexOf(":")).trim() }
assert topLevelKeys.contains("rules") : "Updated config must use the rules schema"
assert !topLevelKeys.contains("trust") : "Updated config must not emit the removed 'trust:' key"
assert !topLevelKeys.contains("signature-optional") : "Updated config must not emit the removed 'signature-optional:' key"
assert !topLevelKeys.contains("policy") : "Updated config must not emit the removed 'policy:' key"
assert !topLevelKeys.contains("artifacts") : "Updated config must not emit the removed 'artifacts:' key"

// Comments should be preserved
assert yaml.contains("# Trust configuration for update test") : "Header comment should be preserved"
assert yaml.contains("# Gary Gregory signs commons-lang3") : "Inline comment should be preserved"

println "SUCCESS: sigmund.yaml stays loadable on the rules schema (no v1 keys), keeps its comments, and leaves out the unidentifiable jspecify signer"
