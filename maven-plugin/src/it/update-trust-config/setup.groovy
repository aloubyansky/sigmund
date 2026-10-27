// Create a clean GPG home so the test doesn't depend on the user's keyring state.
// The jspecify key is not served with UID by keys.openpgp.org, so GPG will skip it.
def gpghome = new File(basedir, "gpghome")
gpghome.mkdirs()
gpghome.setReadable(false, false)
gpghome.setReadable(true, true)
gpghome.setWritable(false, false)
gpghome.setWritable(true, true)
gpghome.setExecutable(false, false)
gpghome.setExecutable(true, true)

// Create a partial sigmund.yaml that only covers commons-lang3.
// Includes a comment that should be preserved after update.
// jspecify is signed by a key no full fingerprint is known for, so the update leaves it out.
def config = new File(basedir, "sigmund.yaml")
config.text = """\
# Trust configuration for update test
signers:
  # Gary Gregory signs commons-lang3
  gary-gregory:  # user ID on the key, unverified: Gary David Gregory (Code signing key) <ggregory@apache.org>
    pgp4: "2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB"

rules:
  - match: [org.apache.commons:commons-lang3]
    requires: [gary-gregory]

# gpgHome places gpg's keyring and, through it, the one bc reads; bc's own stores are not
# GnuPG's, so they are placed here to keep the test off the user's cert-d and private keys.
tools:
  bc:
    cert-d-home: ${new File(gpghome, "cert-d").path}
    bc-private-home: ${new File(gpghome, "bc-private").path}
"""
println "Created partial sigmund.yaml (commons-lang3 only, with comments)"
println "Created clean GNUPGHOME at ${gpghome}"
return true
